"""The triage orchestrator (walking-skeleton superagent).

Builds the deterministic triage graph — intake → L1 → route — and drives a raw alert through it on
the kernel, persisting the Case and recording every step in the ledger. The full 14-agent
orchestration (investigation, correlation, intel, response, approvals) grows onto this loop in later
stages; the shape here is the one that stays.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from ..core import (
    CaseRepo,
    Done,
    Engine,
    EventBus,
    Goto,
    Graph,
    Ledger,
    RunContext,
    Store,
    new_run_id,
)
from ..core.kernel import NodeResult
from ..normalize import normalize_alert
from ..providers import ProviderGateway
from ..schema.common import CaseState, utcnow
from ..schema.ledger import ModelRef
from ..schema.models import Case
from . import l1


class TriageState(BaseModel):
    case: Case


async def _intake(ctx: RunContext[TriageState]) -> NodeResult:
    case = ctx.state.case
    case.state = CaseState.TRIAGING
    case.updated_at = utcnow()
    # Opt-in memory recall: surface similar prior cases as cited context (never as instructions).
    memory = ctx.services.get("memory")
    if memory is not None and case.memory_enabled:
        from ..schema.models import Evidence

        recalled = await memory.recall_for_case(case, k=3)
        for sr in recalled:
            case.add_evidence(
                Evidence(
                    tenant_id=case.tenant_id,
                    source="memory",
                    summary=f"Similar prior case ({sr.score:.2f}): {sr.record.case_summary[:160]}",
                    supports="prior_case",
                )
            )
        if recalled:
            await ctx.emit("memory.recalled", actor="agent", actor_id="orchestrator")
    return Goto("l1")


async def _l1(ctx: RunContext[TriageState]) -> NodeResult:
    gateway: ProviderGateway = ctx.services["gateway"]
    case = ctx.state.case
    verdict, evidence, model_ref = await l1.triage(case, gateway)
    for ev in evidence:
        case.add_evidence(ev)
    case.verdict = verdict
    case.attack_techniques = verdict.attack_techniques
    if model_ref is not None:
        case.cost.add(model_ref.tokens_in, model_ref.tokens_out, model_ref.usd)
    await ctx.emit(
        f"l1.verdict:{verdict.verdict_class}:{verdict.routing}",
        actor="agent",
        actor_id="L1",
        model=model_ref or ModelRef(id=verdict.model_id or "offline-deterministic"),
    )
    return Goto("route")


async def _route(ctx: RunContext[TriageState]) -> NodeResult:
    case = ctx.state.case
    routing = case.verdict.routing if case.verdict else "escalate"
    if routing == "auto_close":
        case.state = CaseState.RESOLVED
    elif routing == "await_approval":
        case.state = CaseState.AWAITING_APPROVAL
    else:
        case.state = CaseState.ESCALATED
    case.updated_at = utcnow()
    await ctx.emit(f"route:{case.state}", actor="agent", actor_id="orchestrator")
    return Done()


def build_triage_graph() -> Graph:
    return (
        Graph("triage")
        .add("intake", _intake, entry=True)
        .add("l1", _l1, timeout=180.0, retries=1)
        .add("route", _route)
    )


class TriageOrchestrator:
    """Wires store/ledger/bus/engine/gateway and runs the triage graph for a new alert."""

    def __init__(
        self,
        store: Store,
        gateway: ProviderGateway,
        *,
        bus: EventBus | None = None,
        ledger: Ledger | None = None,
        memory: object | None = None,
    ) -> None:
        self.store = store
        self.gateway = gateway
        self.bus = bus or EventBus()
        self.ledger = ledger or Ledger(store)
        self.engine = Engine(store, self.ledger, self.bus)
        self.repo = CaseRepo(store)
        self.memory = memory  # optional MemoryService
        self.graph = build_triage_graph()

    async def triage_alert(
        self,
        raw: dict[str, Any],
        *,
        tenant_id: str,
        source: str = "webhook",
        memory_enabled: bool = False,
    ) -> Case:
        alert = normalize_alert(raw, tenant_id=tenant_id, source=source)
        case = Case(
            tenant_id=tenant_id,
            title=alert.title,
            severity=alert.severity,
            alerts=[alert],
            memory_enabled=memory_enabled,
        )
        self.repo.save(case)

        ctx: RunContext[TriageState] = RunContext(
            run_id=new_run_id(),
            tenant_id=tenant_id,
            state=TriageState(case=case),
            ledger=self.ledger,
            store=self.store,
            bus=self.bus,
            case_id=case.id,
            services={"gateway": self.gateway, "memory": self.memory},
        )
        outcome = await self.engine.run(self.graph, ctx)
        final_case = outcome.state.case
        self.repo.save(final_case)

        # Learn from the resolved case (opt-in). Stored quarantined until a human promotes it.
        if self.memory is not None and final_case.memory_enabled:
            await self.memory.remember(final_case)  # type: ignore[attr-defined]

        return final_case
