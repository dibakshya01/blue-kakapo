"""The triage orchestrator / superagent.

Drives a case through the deterministic graph on the kernel — intake → L1 → (investigate: INTEL + L2 +
FUSION) → route — running each stage as an SDK agent whose output is merged into the case and recorded
in the ledger. Triage is read-only; RESP containment is a separate, explicitly-invoked, Guardian-gated
path (``respond``), never auto-run. More agents (S9) attach to this same shape.
"""

from __future__ import annotations

import asyncio
from typing import Any

from pydantic import BaseModel

from ..assets import AssetInventory, resolve_entities
from ..connectors import ConnectorRegistry
from ..core import (
    CaseRepo,
    CryptoShredder,
    Done,
    Engine,
    EventBus,
    Goto,
    Graph,
    Ledger,
    RunContext,
    Store,
    collect_case_pii_values,
    erase_case_pii,
    new_run_id,
    protect_case_pii,
    redact_pii_text,
)
from ..core.kernel import NodeResult
from ..guardian import GuardedExecutor
from ..memory import MemoryService
from ..normalize import normalize_alert
from ..providers import ProviderGateway
from ..schema.common import CaseState, RoutingDisposition, utcnow
from ..schema.ledger import ModelRef
from ..schema.models import Case, Evidence
from .fusion import FusionAgent
from .intel import IntelAgent
from .l1 import L1Agent
from .l2 import L2Agent
from .proactive import DetAgent, HuntAgent, InsiderAgent, VulnAgent, WatchAgent
from .resp import RespAgent
from .sdk import Agent, AgentOutput, AgentServices
from .serviceops import CommsAgent, MaintAgent, MgrAgent, RptAgent


class TriageState(BaseModel):
    case: Case


def _merge(case: Case, out: AgentOutput) -> None:
    """Merge an agent's output into the case (evidence, verdict, techniques, entities, cost)."""
    for ev in out.evidence:
        case.add_evidence(ev)
    if out.verdict is not None:
        case.verdict = out.verdict
    for t in out.techniques:
        if t not in case.attack_techniques:
            case.attack_techniques.append(t)
    for ent in out.entities:
        if not any(e.type == ent.type and e.value == ent.value for e in case.entities):
            case.entities.append(ent)
    if out.cost is not None:
        case.cost.add(out.cost.tokens_in, out.cost.tokens_out, out.cost.usd)
    case.updated_at = utcnow()


class TriageOrchestrator:
    """Wires store/ledger/bus/engine/gateway/connectors/guardian/memory and runs the triage graph."""

    def __init__(
        self,
        store: Store,
        gateway: ProviderGateway,
        *,
        bus: EventBus | None = None,
        ledger: Ledger | None = None,
        memory: MemoryService | None = None,
        registry: ConnectorRegistry | None = None,
        inventory: AssetInventory | None = None,
        guardian: GuardedExecutor | None = None,
        max_concurrent_cases: int = 16,
    ) -> None:
        self.store = store
        self.gateway = gateway
        self.bus = bus or EventBus()
        self.ledger = ledger or Ledger(store)
        # PII at rest: raw payloads are crypto-shred-tokenized before a case is ever persisted.
        self.shredder = CryptoShredder(store)
        self.engine = Engine(store, self.ledger, self.bus)
        self.repo = CaseRepo(store)
        self.memory = memory
        self.registry = registry
        self.inventory = inventory
        self.guardian = guardian
        # Backpressure: bound concurrent case processing so a flood queues rather than overwhelming
        # the box (FR-34). Excess ingests await here instead of exploding memory/CPU.
        self._sem = asyncio.Semaphore(max_concurrent_cases)
        self.max_concurrent_cases = max_concurrent_cases
        self.l1 = L1Agent()
        self.intel = IntelAgent()
        self.l2 = L2Agent()
        self.fusion = FusionAgent()
        self.resp = RespAgent()
        # The remaining roster (proactive + service ops), available on-demand / scheduled.
        self.watch = WatchAgent()
        self.hunt = HuntAgent()
        self.det = DetAgent()
        self.vuln = VulnAgent()
        self.insider = InsiderAgent()
        self.comms = CommsAgent()
        self.rpt = RptAgent()
        self.maint = MaintAgent()
        self.mgr = MgrAgent()
        self.roster: list[Agent] = [
            self.l1,
            self.watch,
            self.l2,
            self.fusion,
            self.intel,
            self.hunt,
            self.det,
            self.vuln,
            self.insider,
            self.resp,
            self.comms,
            self.rpt,
            self.maint,
            self.mgr,
        ]
        self.graph = self._build_graph()

    def agent(self, name: str) -> Agent | None:
        return next((a for a in self.roster if a.name == name.upper()), None)

    async def run_agent_on_case(self, name: str, case: Case, **options: Any) -> AgentOutput:
        """Run any roster agent on a case (for scheduled/on-demand ops). Persists the mutated case."""
        agent = self.agent(name)
        if agent is None:
            raise ValueError(f"unknown agent {name!r}")
        services = AgentServices(
            tenant_id=case.tenant_id,
            gateway=self.gateway,
            emit=self._noop_emit,
            registry=self.registry,
            inventory=self.inventory,
            guardian=self.guardian,
            memory=self.memory,
            repo=self.repo,
            options=options,
        )
        out = await agent.run(case, services)
        _merge(case, out)
        self.repo.save(case)
        return out

    def _services(self, ctx: RunContext[TriageState], **options: Any) -> AgentServices:
        async def emit(action: str, **kw: Any) -> None:
            await ctx.emit(action, **kw)

        return AgentServices(
            tenant_id=ctx.tenant_id,
            gateway=self.gateway,
            emit=emit,
            registry=self.registry,
            inventory=self.inventory,
            guardian=self.guardian,
            memory=self.memory,
            repo=self.repo,
            options=options,
        )

    async def _run_agent(
        self, agent: Agent, ctx: RunContext[TriageState], **options: Any
    ) -> AgentOutput:
        out = await agent.run(ctx.state.case, self._services(ctx, **options))
        _merge(ctx.state.case, out)
        await ctx.emit(f"agent:{agent.name}", actor="agent", actor_id=agent.name)
        return out

    # --- graph nodes ---

    async def _intake(self, ctx: RunContext[TriageState]) -> NodeResult:
        case = ctx.state.case
        case.state = CaseState.TRIAGING
        if self.inventory is not None:
            for ent in resolve_entities(case, self.inventory):
                case.entities.append(ent)
        if self.memory is not None and case.memory_enabled:
            recalled = await self.memory.recall_for_case(case, k=3)
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

    async def _l1(self, ctx: RunContext[TriageState]) -> NodeResult:
        out = await self._run_agent(self.l1, ctx)
        model = out.cost or ModelRef(
            id=(out.verdict.model_id if out.verdict else "offline-deterministic")
        )
        v = ctx.state.case.verdict
        await ctx.emit(
            f"l1.verdict:{v.verdict_class if v else '?'}:{v.routing if v else '?'}",
            actor="agent",
            actor_id="L1",
            model=model,
        )
        if v and v.routing == RoutingDisposition.AUTO_CLOSE:
            return Goto("route")
        return Goto("investigate")

    async def _investigate(self, ctx: RunContext[TriageState]) -> NodeResult:
        ctx.state.case.state = CaseState.INVESTIGATING
        await self._run_agent(self.intel, ctx)
        await self._run_agent(self.l2, ctx)
        await self._run_agent(self.fusion, ctx)
        return Goto("route")

    async def _route(self, ctx: RunContext[TriageState]) -> NodeResult:
        case = ctx.state.case
        routing = case.verdict.routing if case.verdict else RoutingDisposition.ESCALATE
        if routing == RoutingDisposition.AUTO_CLOSE:
            case.state = CaseState.RESOLVED
        elif routing == RoutingDisposition.AWAIT_APPROVAL:
            case.state = CaseState.AWAITING_APPROVAL
        else:
            case.state = CaseState.ESCALATED
        case.updated_at = utcnow()
        await ctx.emit(f"route:{case.state}", actor="agent", actor_id="orchestrator")
        return Done()

    def _build_graph(self) -> Graph:
        return (
            Graph("triage")
            .add("intake", self._intake, entry=True)
            .add("l1", self._l1, timeout=180.0, retries=1)
            .add("investigate", self._investigate, timeout=240.0, retries=1)
            .add("route", self._route)
        )

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
        # Tokenize raw payloads BEFORE the first persist, so no raw PII is ever written to cases.data.
        protect_case_pii(case, self.shredder)
        self.repo.save(case)
        ctx: RunContext[TriageState] = RunContext(
            run_id=new_run_id(),
            tenant_id=tenant_id,
            state=TriageState(case=case),
            ledger=self.ledger,
            store=self.store,
            bus=self.bus,
            case_id=case.id,
        )
        async with self._sem:  # backpressure: bound in-flight cases under a flood
            outcome = await self.engine.run(self.graph, ctx)
        final_case = outcome.state.case
        self.repo.save(final_case)
        if self.memory is not None and final_case.memory_enabled:
            await self.memory.remember(final_case)
        return final_case

    async def respond(
        self, case_id: str, *, dry_run: bool = True, actor_roles: list[str] | None = None
    ) -> Case:
        """Run RESP on an existing case — Guardian-gated, explicit, never part of auto-triage."""
        case = self.repo.get(case_id)
        if case is None:
            raise ValueError(f"unknown case {case_id!r}")
        case.state = CaseState.RESPONDING
        services = AgentServices(
            tenant_id=case.tenant_id,
            gateway=self.gateway,
            emit=self._noop_emit,
            registry=self.registry,
            inventory=self.inventory,
            guardian=self.guardian,
            memory=self.memory,
            repo=self.repo,
            options={"dry_run": dry_run, "actor_roles": actor_roles or []},
        )
        out = await self.resp.run(case, services)
        _merge(case, out)
        results: list[dict[str, Any]] = out.metadata.get("results", [])
        pending = any(r.get("status") == "pending_approval" for r in results)
        case.state = CaseState.AWAITING_APPROVAL if pending else CaseState.RESOLVED
        self.ledger.append(
            tenant_id=case.tenant_id,
            action=f"respond:{case.state}",
            actor="agent",
            actor_id="RESP",
            case_id=case.id,
        )
        self.repo.save(case)
        return case

    async def erase_case(self, case_id: str) -> dict[str, Any]:
        """GDPR subject-erasure across every PII-bearing surface of a case.

        Crypto-shreds raw blobs, scrubs known-pattern PII (emails/SSNs/phones) + the case's own
        identified PII values from the case's free-text/observables/entities, redacts the case's
        approval rows, deletes the kernel checkpoints (each holds a full case snapshot), and deletes
        derived memory records. Pattern/value-based (not NER): see ``docs/gdpr-erasure.md`` for the
        honest scope. The append-only ledger is untouched (holds no PII) and still verifies. A
        ``case.erased`` entry is appended once; re-erasing is idempotent (no duplicate entry).
        """
        case = self.repo.get(case_id)
        if case is None:
            raise ValueError(f"unknown case {case_id!r}")
        already_erased = case.erased_at is not None
        pii_values = collect_case_pii_values(case)
        report = erase_case_pii(case, self.shredder)
        case.erased_at = utcnow()
        self.repo.save(case)
        approvals_redacted = self._redact_case_approvals(case.tenant_id, case.id, pii_values)
        # Kernel checkpoints each hold a full Case snapshot — drop them (an erased case is not resumable).
        checkpoints_deleted = self.store.delete_checkpoints_by_case(case.tenant_id, case.id)
        memory_deleted = 0
        if self.memory is not None:
            memory_deleted = await self.memory.forget_case(case.tenant_id, case.id)
        if not already_erased:
            self.ledger.append(
                tenant_id=case.tenant_id,
                action="case.erased",
                actor="system",
                actor_id="dpo",
                case_id=case.id,
            )
        return {
            "case_id": case.id,
            "erased_at": case.erased_at.isoformat(),
            "memory_records_deleted": memory_deleted,
            "approvals_redacted": approvals_redacted,
            "checkpoints_deleted": checkpoints_deleted,
            **report,
        }

    def _redact_case_approvals(self, tenant_id: str, case_id: str, pii_values: set[str]) -> int:
        """Redact PII from a case's approval rows (target/args/reason) — they outlive the case."""
        redacted = 0
        for row in self.store.list_approvals(tenant_id, status=None):
            data = row.get("data") or {}
            if data.get("case_id") != case_id:
                continue
            action = data.get("action") or {}
            action["target"], _ = redact_pii_text(action.get("target"), pii_values)
            args = action.get("args") or {}
            for key, val in list(args.items()):
                if isinstance(val, str):
                    args[key], _ = redact_pii_text(val, pii_values)
            data["action"] = action
            data["reason"], _ = redact_pii_text(data.get("reason"), pii_values)
            self.store.update_approval(row["id"], {"data": data})
            redacted += 1
        return redacted

    @staticmethod
    async def _noop_emit(action: str, **kw: Any) -> None:
        return None
