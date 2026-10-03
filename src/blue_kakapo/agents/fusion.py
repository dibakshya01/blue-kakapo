"""FUSION — Links signals & campaigns. Correlates a case with other open cases by shared entities.

Deterministic entity-overlap clustering: if another case shares an observable value, they are likely
one incident/campaign. Produces 'correlated case' evidence and a correlation id. Read-only.
"""

from __future__ import annotations

from ..schema.common import AutonomyLevel, CaseState
from ..schema.models import AgBOM, Case, Evidence
from .l2 import _observables
from .sdk import Agent, AgentOutput, AgentServices

_OPEN_STATES = {
    CaseState.NEW,
    CaseState.TRIAGING,
    CaseState.INVESTIGATING,
    CaseState.AWAITING_APPROVAL,
    CaseState.ESCALATED,
}


class FusionAgent(Agent):
    name = "FUSION"
    autonomy_level = AutonomyLevel.PROPOSE
    handles_untrusted_input = True
    holds_sensitive_access = False
    changes_external_state = False

    def agbom(self) -> AgBOM:
        return AgBOM(
            agent=self.name,
            autonomy_level=self.autonomy_level,
            tools=["entity-overlap"],
            data_scopes=["case:read"],
        )

    async def run(self, case: Case, svc: AgentServices) -> AgentOutput:
        if svc.repo is None:
            return AgentOutput(notes="no case repository available for correlation")

        mine = {o.value for o in _observables(case)}
        if not mine:
            return AgentOutput(notes="no observables to correlate on")

        evidence: list[Evidence] = []
        correlated: list[str] = []
        others = svc.repo.list(case.tenant_id, limit=200)
        for other in others:
            if other.id == case.id or other.state not in _OPEN_STATES:
                continue
            theirs = {o.value for o in _observables(other)}
            shared = mine & theirs
            if shared:
                correlated.append(other.id)
                evidence.append(
                    Evidence(
                        tenant_id=case.tenant_id,
                        source="fusion",
                        summary=(
                            f"Correlated with case {other.id} — shared: {', '.join(sorted(shared))}."
                        ),
                        supports="correlation",
                    )
                )

        return AgentOutput(
            evidence=evidence,
            metadata={"correlated_case_ids": correlated},
            notes=f"FUSION correlated {len(correlated)} related case(s).",
        )
