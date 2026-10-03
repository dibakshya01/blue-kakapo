"""Service-ops agents: COMMS, RPT, MAINT, MGR.

Keep humans informed, produce reports, keep the pipeline healthy, and run the shift (incl. regulatory
clocks). Deterministic-first; external sends are drafted for human approval, never auto-sent.
"""

from __future__ import annotations

from ..compliance import clocks_for_case, soonest_deadline
from ..schema.common import AutonomyLevel
from ..schema.models import AgBOM, Case, Evidence
from .sdk import Agent, AgentOutput, AgentServices


class CommsAgent(Agent):
    """Keeps analysts informed: case summaries + drafted external messages (human-sent)."""

    name = "COMMS"
    autonomy_level = AutonomyLevel.PROPOSE
    handles_untrusted_input = False
    holds_sensitive_access = False
    changes_external_state = False  # external send is human-approved; drafts only

    def agbom(self) -> AgBOM:
        return AgBOM(
            agent=self.name,
            autonomy_level=self.autonomy_level,
            tools=["summarizer"],
            data_scopes=["case:read"],
        )

    async def run(self, case: Case, svc: AgentServices) -> AgentOutput:
        v = case.verdict
        summary = (
            f"Case {case.id}: {case.title} — verdict {v.verdict_class if v else '?'} "
            f"({v.routing if v else '?'}, {int((v.confidence if v else 0) * 100)}%). "
            f"{len(case.evidence)} evidence item(s); state {case.state}."
        )
        draft = f"[DRAFT — requires human approval to send]\nSubject: SOC case {case.id} ({case.severity})\n{summary}"
        ev = [
            Evidence(
                tenant_id=case.tenant_id,
                source="COMMS",
                summary="Posted case summary to the analyst feed.",
                supports="comms",
            )
        ]
        return AgentOutput(
            evidence=ev,
            metadata={"summary": summary, "external_draft": draft},
            notes="COMMS summarized; external message drafted (not sent).",
        )


class RptAgent(Agent):
    """Reporting & insight: an incident report from the case (incl. compliance clocks + cost)."""

    name = "RPT"
    autonomy_level = AutonomyLevel.PROPOSE
    handles_untrusted_input = False
    holds_sensitive_access = True
    changes_external_state = False

    def agbom(self) -> AgBOM:
        return AgBOM(
            agent=self.name,
            autonomy_level=self.autonomy_level,
            tools=["report-builder"],
            data_scopes=["case:read", "ledger:read"],
        )

    async def run(self, case: Case, svc: AgentServices) -> AgentOutput:
        v = case.verdict
        clocks = case.regulatory_clocks or clocks_for_case(case)
        lines = [
            f"# Incident report — {case.id}",
            f"Title: {case.title}",
            f"Severity: {case.severity} | State: {case.state}",
            f"Verdict: {v.verdict_class if v else '—'} ({v.routing if v else '—'}, conf {int((v.confidence if v else 0) * 100)}%)",
            f"ATT&CK: {', '.join(case.attack_techniques) or '—'}",
            f"Evidence items: {len(case.evidence)}",
            f"LLM cost: ${case.cost.usd:.4f} ({case.cost.model_calls} call(s))",
            f"Regulatory clocks: {', '.join(f'{c.framework}/{c.label}@{c.deadline_at.isoformat()}' for c in clocks) or 'none'}",
        ]
        report = "\n".join(lines)
        return AgentOutput(
            metadata={"report": report, "clock_count": len(clocks)},
            notes="RPT generated an incident report.",
        )


class MaintAgent(Agent):
    """Keeps the SOC seeing: connector/pipeline health + detection-decay flags."""

    name = "MAINT"
    autonomy_level = AutonomyLevel.PROPOSE
    handles_untrusted_input = False
    holds_sensitive_access = True
    changes_external_state = False

    def agbom(self) -> AgBOM:
        return AgBOM(
            agent=self.name,
            autonomy_level=self.autonomy_level,
            tools=["health-probe"],
            data_scopes=["connector:read"],
        )

    async def run(self, case: Case, svc: AgentServices) -> AgentOutput:
        ev: list[Evidence] = []
        unhealthy = 0
        if svc.registry is not None:
            for conn in svc.registry.all():
                health = await conn.health()
                if not health.healthy:
                    unhealthy += 1
                    ev.append(
                        Evidence(
                            tenant_id=case.tenant_id,
                            source="MAINT",
                            summary=f"Connector {conn.info().name!r} unhealthy: {health.detail}",
                            supports="pipeline_health",
                        )
                    )
        return AgentOutput(
            evidence=ev,
            metadata={"unhealthy_connectors": unhealthy},
            notes=f"MAINT checked connector health ({unhealthy} unhealthy).",
        )


class MgrAgent(Agent):
    """Runs the shift: regulatory-clock tracking + prioritization signal."""

    name = "MGR"
    autonomy_level = AutonomyLevel.PROPOSE
    handles_untrusted_input = False
    holds_sensitive_access = False
    changes_external_state = False

    def agbom(self) -> AgBOM:
        return AgBOM(
            agent=self.name,
            autonomy_level=self.autonomy_level,
            tools=["sla-clocks", "prioritizer"],
            data_scopes=["case:read"],
        )

    async def run(self, case: Case, svc: AgentServices) -> AgentOutput:
        clocks = clocks_for_case(case)
        case.regulatory_clocks = clocks  # MGR owns the compliance clocks on the case
        ev: list[Evidence] = []
        soonest = soonest_deadline(clocks)
        if soonest is not None:
            ev.append(
                Evidence(
                    tenant_id=case.tenant_id,
                    source="MGR",
                    summary=f"Regulatory clock: {soonest.framework} {soonest.label} due {soonest.deadline_at.isoformat()}.",
                    supports="compliance",
                )
            )
        return AgentOutput(
            evidence=ev,
            metadata={"clocks": [c.model_dump(mode="json") for c in clocks]},
            notes=f"MGR set {len(clocks)} regulatory clock(s).",
        )
