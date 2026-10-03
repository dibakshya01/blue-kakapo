"""L2 — Investigation. Deepens an escalated case with connector enrichment + SIEM queries.

Deterministic-first: enrich each observable through connectors that declare the ENRICH capability, and
pull related events from a SIEM via the native-query escape hatch. Produces cited evidence and a short
narrative. Reads sensitive data but takes no external action (Rule of Two: breaks the state-change leg).
"""

from __future__ import annotations

from ..connectors.base import Capability, ConnectorError
from ..schema.common import AutonomyLevel
from ..schema.models import AgBOM, Case, Evidence
from ..schema.ocsf import Observable, ObservableType
from .sdk import Agent, AgentOutput, AgentServices

_INVESTIGABLE = {
    ObservableType.IP,
    ObservableType.HOSTNAME,
    ObservableType.FQDN,
    ObservableType.USER,
}


def _observables(case: Case) -> list[Observable]:
    seen: dict[tuple[str, str], Observable] = {}
    for alert in case.alerts:
        for event in alert.events:
            for obs in event.observables:
                seen.setdefault((obs.type, obs.value), obs)
    return list(seen.values())


class L2Agent(Agent):
    name = "L2"
    autonomy_level = AutonomyLevel.PROPOSE
    handles_untrusted_input = True
    holds_sensitive_access = True  # queries the SIEM
    changes_external_state = False

    def agbom(self) -> AgBOM:
        return AgBOM(
            agent=self.name,
            autonomy_level=self.autonomy_level,
            tools=["connector.enrich", "connector.query"],
            data_scopes=["siem:read", "alert:read"],
        )

    async def run(self, case: Case, svc: AgentServices) -> AgentOutput:
        evidence: list[Evidence] = []
        registry = svc.registry
        if registry is None:
            return AgentOutput(notes="no connectors available for investigation")

        enrichers = registry.with_capability(Capability.ENRICH)
        investigable = [o for o in _observables(case) if o.type in _INVESTIGABLE]
        for obs in investigable[:8]:
            for conn in enrichers:
                try:
                    evidence.extend(await conn.enrich(tenant_id=case.tenant_id, observable=obs))
                except ConnectorError:
                    continue

        # One SIEM query for related activity on the most salient observable.
        queriers = registry.with_capability(Capability.QUERY)
        if queriers and investigable:
            top = investigable[0]
            try:
                res = await queriers[0].query(
                    tenant_id=case.tenant_id,
                    native_query=f"search {top.type}={top.value} earliest=-24h",
                )
                evidence.append(
                    Evidence(
                        tenant_id=case.tenant_id,
                        source=queriers[0].info().name,
                        connector=queriers[0].info().name,
                        query=f"{top.type}={top.value} last 24h",
                        summary=f"SIEM returned {res.count} related record(s) for {top.value}.",
                        supports="investigation",
                    )
                )
            except ConnectorError:
                pass

        return AgentOutput(
            evidence=evidence,
            notes=f"L2 gathered {len(evidence)} investigative fact(s).",
        )
