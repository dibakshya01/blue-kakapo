"""S1: the deterministic kernel — run, checkpoint, suspend/resume, fail, parallel."""

from __future__ import annotations

import pytest
from pydantic import BaseModel

from blue_kakapo.core import (
    Done,
    Engine,
    EventBus,
    Fail,
    Goto,
    Graph,
    Ledger,
    RunContext,
    RunStatus,
    Store,
    Suspend,
    new_run_id,
    run_parallel,
)
from blue_kakapo.core.kernel import NodeResult


class CaseState(BaseModel):
    steps: list[str] = []
    score: int = 0
    approved: bool | None = None


def _engine() -> tuple[Engine, Store, Ledger, EventBus]:
    store = Store.in_memory()
    ledger = Ledger(store)
    bus = EventBus()
    return Engine(store, ledger, bus), store, ledger, bus


def _ctx(store: Store, ledger: Ledger, bus: EventBus, state: CaseState) -> RunContext[CaseState]:
    return RunContext(
        run_id=new_run_id(),
        tenant_id="t1",
        state=state,
        ledger=ledger,
        store=store,
        bus=bus,
        case_id="c1",
    )


async def test_two_node_graph_runs_to_done() -> None:
    engine, store, ledger, bus = _engine()

    async def enrich(ctx: RunContext[CaseState]) -> NodeResult:
        ctx.state.steps.append("enrich")
        ctx.state.score = 7
        return Goto("verdict")

    async def verdict(ctx: RunContext[CaseState]) -> NodeResult:
        ctx.state.steps.append("verdict")
        return Done()

    graph = Graph("triage").add("enrich", enrich, entry=True).add("verdict", verdict)
    ctx = _ctx(store, ledger, bus, CaseState())
    outcome = await engine.run(graph, ctx)

    assert outcome.status == RunStatus.DONE
    assert outcome.state.steps == ["enrich", "verdict"]
    assert ledger.verify("t1") is True
    # The ledger recorded the path (entry/exit/done per node).
    actions = [e.action for e in ledger.replay("t1", run_id=ctx.run_id)]
    assert any(a.startswith("node.enter:enrich") for a in actions)
    assert any(a.startswith("node.done:verdict") for a in actions)


async def test_suspend_then_resume_reenters_exact_node() -> None:
    engine, store, ledger, bus = _engine()

    async def investigate(ctx: RunContext[CaseState]) -> NodeResult:
        ctx.state.steps.append("investigate")
        return Goto("await_approval")

    async def await_approval(ctx: RunContext[CaseState]) -> NodeResult:
        # First entry: no resume payload yet -> suspend for a human decision.
        if ctx.resume_payload is None:
            return Suspend(reason="needs_human_approval", resume_token="tok-1")
        ctx.state.approved = bool(ctx.resume_payload.get("approved"))
        ctx.state.steps.append("approved" if ctx.state.approved else "denied")
        return Done()

    graph = (
        Graph("resp")
        .add("investigate", investigate, entry=True)
        .add("await_approval", await_approval)
    )
    ctx = _ctx(store, ledger, bus, CaseState())
    out1 = await engine.run(graph, ctx)
    assert out1.status == RunStatus.SUSPENDED
    assert out1.node_id == "await_approval"
    assert out1.resume_token == "tok-1"

    out2 = await engine.resume(
        graph,
        ctx.run_id,
        CaseState,
        ledger=ledger,
        bus=bus,
        payload={"approved": True},
        resume_token="tok-1",
    )
    assert out2.status == RunStatus.DONE
    assert out2.state.approved is True
    assert out2.state.steps == ["investigate", "approved"]  # state restored across suspend
    assert ledger.verify("t1") is True


async def test_resume_rejects_bad_token() -> None:
    engine, store, ledger, bus = _engine()

    async def hold(ctx: RunContext[CaseState]) -> NodeResult:
        return Suspend(reason="hold", resume_token="right")

    graph = Graph("g").add("hold", hold, entry=True)
    ctx = _ctx(store, ledger, bus, CaseState())
    await engine.run(graph, ctx)
    with pytest.raises(ValueError, match="resume token mismatch"):
        await engine.resume(
            graph, ctx.run_id, CaseState, ledger=ledger, bus=bus, resume_token="wrong"
        )


async def test_node_failure_is_captured() -> None:
    engine, store, ledger, bus = _engine()

    async def boom(ctx: RunContext[CaseState]) -> NodeResult:
        raise RuntimeError("kaboom")

    graph = Graph("g").add("boom", boom, entry=True)
    ctx = _ctx(store, ledger, bus, CaseState())
    out = await engine.run(graph, ctx)
    assert out.status == RunStatus.FAILED
    assert "kaboom" in (out.error or "")
    assert ledger.verify("t1") is True  # failure is recorded, chain intact


async def test_explicit_fail_result() -> None:
    engine, store, ledger, bus = _engine()

    async def refuse(ctx: RunContext[CaseState]) -> NodeResult:
        return Fail(error="policy_violation")

    graph = Graph("g").add("refuse", refuse, entry=True)
    ctx = _ctx(store, ledger, bus, CaseState())
    out = await engine.run(graph, ctx)
    assert out.status == RunStatus.FAILED and out.error == "policy_violation"


async def test_retry_then_succeed() -> None:
    engine, store, ledger, bus = _engine()
    calls = {"n": 0}

    async def flaky(ctx: RunContext[CaseState]) -> NodeResult:
        calls["n"] += 1
        if calls["n"] < 2:
            raise RuntimeError("transient")
        return Done()

    graph = Graph("g").add("flaky", flaky, entry=True, retries=2, retry_backoff=0.0)
    ctx = _ctx(store, ledger, bus, CaseState())
    out = await engine.run(graph, ctx)
    assert out.status == RunStatus.DONE and calls["n"] == 2


async def test_max_steps_guard_prevents_infinite_loop() -> None:
    engine, store, ledger, bus = _engine()
    engine.max_steps = 5

    async def loop(ctx: RunContext[CaseState]) -> NodeResult:
        return Goto("loop")

    graph = Graph("g").add("loop", loop, entry=True)
    ctx = _ctx(store, ledger, bus, CaseState())
    out = await engine.run(graph, ctx)
    assert out.status == RunStatus.FAILED and "max_steps" in (out.error or "")


async def test_run_parallel_children() -> None:
    engine, store, ledger, bus = _engine()
    ctx = _ctx(store, ledger, bus, CaseState())

    async def a(c: RunContext[CaseState]) -> int:
        return 1

    async def b(c: RunContext[CaseState]) -> int:
        return 2

    results = await run_parallel(ctx, [a, b])
    assert results == [1, 2]
