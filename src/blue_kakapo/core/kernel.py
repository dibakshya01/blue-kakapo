"""The deterministic orchestration kernel.

A typed, checkpointed state machine. Nodes are pure-ish steps (deterministic, or a single bounded
LLM/tool call) returning a ``NodeResult``; the engine checkpoints after every node, emits a ledger
entry on entry/exit, and supports human-in-the-loop **suspend/resume that re-enters the exact node**.
Agents compose as sub-graphs. State is a Pydantic model serialized to JSON for checkpoints.

Reproducibility note: the *decision path* is replayable from the ledger; we do not claim bit-identical
LLM output (hosted/batched inference is not deterministic even at temperature 0).

Budget guardrail (build-plan §4.4): this kernel core is meant to stay small (≤ ~1,500 LOC). If it
outgrows that, fall back to LangGraph wrapped with our Guardian + ledger + tenancy.
"""

from __future__ import annotations

import asyncio
import datetime as _dt
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Generic, TypeVar

from pydantic import BaseModel

from ..logging import get_logger
from ..schema.common import new_id, new_token
from ..schema.ledger import ModelRef
from .bus import Event, EventBus
from .ledger import Ledger
from .store import Store

S = TypeVar("S", bound=BaseModel)

log = get_logger("blue_kakapo.kernel")


class RunStatus(StrEnum):
    RUNNING = "running"
    DONE = "done"
    SUSPENDED = "suspended"
    FAILED = "failed"


# --- Node results (the union a node may return) ---


@dataclass
class Goto:
    node: str
    state: BaseModel | None = None


@dataclass
class Suspend:
    reason: str
    resume_token: str = field(default_factory=lambda: new_token(12))
    state: BaseModel | None = None


@dataclass
class Done:
    state: BaseModel | None = None


@dataclass
class Fail:
    error: str


NodeResult = Goto | Suspend | Done | Fail


class RunContext(Generic[S]):
    """Everything a node needs: typed state, the ledger, the store/bus, shared services, resume data."""

    def __init__(
        self,
        *,
        run_id: str,
        tenant_id: str,
        state: S,
        ledger: Ledger,
        store: Store,
        bus: EventBus,
        case_id: str | None = None,
        services: dict[str, Any] | None = None,
    ) -> None:
        self.run_id = run_id
        self.tenant_id = tenant_id
        self.state = state
        self.ledger = ledger
        self.store = store
        self.bus = bus
        self.case_id = case_id
        self.services = services or {}
        self.resume_payload: dict[str, Any] | None = None

    async def emit(
        self,
        action: str,
        *,
        actor: str = "system",
        actor_id: str | None = None,
        model: ModelRef | None = None,
        disposition: str | None = None,
        inputs_ref: str | None = None,
        outputs_ref: str | None = None,
    ) -> None:
        """Append a ledger entry and publish a bus event (the universal 'everything is recorded' hook)."""
        entry = await asyncio.to_thread(
            self.ledger.append,
            tenant_id=self.tenant_id,
            action=action,
            actor=actor,
            actor_id=actor_id,
            case_id=self.case_id,
            run_id=self.run_id,
            model=model,
            disposition=disposition,
            inputs_ref=inputs_ref,
            outputs_ref=outputs_ref,
        )
        await self.bus.publish(
            Event(
                topic=f"run.{self.run_id}",
                tenant_id=self.tenant_id,
                payload={"action": action, "seq": entry.seq, "case_id": self.case_id},
            )
        )


Node = Callable[[RunContext[Any]], Awaitable[NodeResult]]


@dataclass
class NodeSpec:
    name: str
    fn: Node
    timeout: float | None = None
    retries: int = 0
    retry_backoff: float = 0.5


class Graph:
    """A named set of nodes with an entry point. Agents are graphs; the orchestrator composes them."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.nodes: dict[str, NodeSpec] = {}
        self._entry: str | None = None

    def add(
        self,
        name: str,
        fn: Node,
        *,
        timeout: float | None = None,
        retries: int = 0,
        retry_backoff: float = 0.5,
        entry: bool = False,
    ) -> Graph:
        self.nodes[name] = NodeSpec(name, fn, timeout, retries, retry_backoff)
        if entry or self._entry is None:
            self._entry = name
        return self

    @property
    def entry(self) -> str:
        if self._entry is None:
            raise ValueError(f"graph {self.name!r} has no entry node")
        return self._entry


@dataclass
class RunOutcome(Generic[S]):
    status: RunStatus
    state: S
    node_id: str
    resume_token: str | None = None
    error: str | None = None


async def run_parallel(
    ctx: RunContext[Any], funcs: list[Callable[[RunContext[Any]], Awaitable[Any]]]
) -> list[Any]:
    """Run child callables concurrently. Each is a scoped step; results are returned in order.

    (The children share ``ctx`` read-only by convention and return values rather than mutating state,
    keeping the join auditable.)
    """
    return await asyncio.gather(*(fn(ctx) for fn in funcs))


class Engine:
    """Runs and resumes graphs, checkpointing after every node and recording to the ledger."""

    def __init__(
        self, store: Store, ledger: Ledger, bus: EventBus, *, max_steps: int = 256
    ) -> None:
        self.store = store
        self.ledger = ledger
        self.bus = bus
        self.max_steps = max_steps

    def _checkpoint(
        self, ctx: RunContext[Any], graph: Graph, node_id: str, status: RunStatus, token: str | None
    ) -> None:
        self.store.upsert_checkpoint(
            {
                "run_id": ctx.run_id,
                "tenant_id": ctx.tenant_id,
                "graph": graph.name,
                "node_id": node_id,
                "seq": 0,
                "status": status.value,
                "resume_token": token,
                "case_id": ctx.case_id,
                "state_json": ctx.state.model_dump(mode="json"),
                "updated_at": _dt.datetime.now(_dt.UTC),
            }
        )

    async def _call_node(self, spec: NodeSpec, ctx: RunContext[Any]) -> NodeResult:
        attempt = 0
        while True:
            try:
                if spec.timeout is not None:
                    return await asyncio.wait_for(spec.fn(ctx), timeout=spec.timeout)
                return await spec.fn(ctx)
            except TimeoutError:
                if attempt >= spec.retries:
                    return Fail(error=f"node {spec.name!r} timed out after {spec.timeout}s")
            except Exception as exc:  # noqa: BLE001 — convert any node crash into a Fail result
                if attempt >= spec.retries:
                    return Fail(error=f"node {spec.name!r} raised: {exc!r}")
            attempt += 1
            await asyncio.sleep(spec.retry_backoff * attempt)

    async def run(
        self, graph: Graph, ctx: RunContext[S], *, start_node: str | None = None
    ) -> RunOutcome[S]:
        node_id = start_node or graph.entry
        steps = 0
        while True:
            steps += 1
            if steps > self.max_steps:
                await ctx.emit(f"run.aborted:{node_id}")
                self._checkpoint(ctx, graph, node_id, RunStatus.FAILED, None)
                return RunOutcome(RunStatus.FAILED, ctx.state, node_id, error="max_steps exceeded")

            spec = graph.nodes.get(node_id)
            if spec is None:
                return RunOutcome(
                    RunStatus.FAILED, ctx.state, node_id, error=f"unknown node {node_id!r}"
                )

            await ctx.emit(f"node.enter:{node_id}")
            result = await self._call_node(spec, ctx)

            if isinstance(result, Goto):
                if result.state is not None:
                    ctx.state = result.state  # type: ignore[assignment]
                await ctx.emit(f"node.exit:{node_id}->{result.node}")
                self._checkpoint(ctx, graph, result.node, RunStatus.RUNNING, None)
                node_id = result.node
                continue

            if isinstance(result, Suspend):
                if result.state is not None:
                    ctx.state = result.state  # type: ignore[assignment]
                await ctx.emit(f"node.suspend:{node_id}:{result.reason}")
                self._checkpoint(ctx, graph, node_id, RunStatus.SUSPENDED, result.resume_token)
                return RunOutcome(
                    RunStatus.SUSPENDED, ctx.state, node_id, resume_token=result.resume_token
                )

            if isinstance(result, Done):
                if result.state is not None:
                    ctx.state = result.state  # type: ignore[assignment]
                await ctx.emit(f"node.done:{node_id}")
                self._checkpoint(ctx, graph, node_id, RunStatus.DONE, None)
                return RunOutcome(RunStatus.DONE, ctx.state, node_id)

            # Fail
            await ctx.emit(f"node.fail:{node_id}:{result.error}")
            self._checkpoint(ctx, graph, node_id, RunStatus.FAILED, None)
            return RunOutcome(RunStatus.FAILED, ctx.state, node_id, error=result.error)

    async def resume(
        self,
        graph: Graph,
        run_id: str,
        state_type: type[S],
        *,
        ledger: Ledger,
        bus: EventBus,
        payload: dict[str, Any] | None = None,
        resume_token: str | None = None,
        services: dict[str, Any] | None = None,
    ) -> RunOutcome[S]:
        """Resume a suspended run, re-entering the exact node with restored typed state."""
        cp = self.store.get_checkpoint(run_id)
        if cp is None:
            raise ValueError(f"no checkpoint for run {run_id!r}")
        if cp["status"] != RunStatus.SUSPENDED.value:
            raise ValueError(f"run {run_id!r} is not suspended (status={cp['status']})")
        if resume_token is not None and cp["resume_token"] != resume_token:
            raise ValueError("resume token mismatch")

        state = state_type.model_validate(cp["state_json"])
        ctx: RunContext[S] = RunContext(
            run_id=run_id,
            tenant_id=cp["tenant_id"],
            state=state,
            ledger=ledger,
            store=self.store,
            bus=bus,
            case_id=cp["case_id"],
            services=services,
        )
        ctx.resume_payload = payload
        await ctx.emit(f"run.resume:{cp['node_id']}")
        return await self.run(graph, ctx, start_node=cp["node_id"])


def new_run_id() -> str:
    return new_id("run")
