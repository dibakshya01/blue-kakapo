"""Proactive agents: WATCH, HUNT, DET, VULN, INSIDER.

Each is deterministic-first, declares an AgBOM, breaks at least one Rule-of-Two leg, and emits
evidence-cited output. They act on the case where it fits and expose standalone helpers for
batch/scheduled operation.
"""

from __future__ import annotations

from ..connectors.base import Capability, ConnectorError
from ..detections import coverage_gaps, detection_inventory, sigma_skeleton
from ..schema.common import SEVERITY_RANK, AutonomyLevel, Severity
from ..schema.models import AgBOM, Case, Evidence
from ..schema.ocsf import ObservableType
from ..vuln_feed import sample_vulnerabilities
from .l2 import _observables
from .sdk import Agent, AgentOutput, AgentServices


class WatchAgent(Agent):
    """Early warning: flags bursts/correlated activity across recent cases."""

    name = "WATCH"
    autonomy_level = AutonomyLevel.PROPOSE
    handles_untrusted_input = True
    holds_sensitive_access = False
    changes_external_state = False

    def agbom(self) -> AgBOM:
        return AgBOM(
            agent=self.name,
            autonomy_level=self.autonomy_level,
            tools=["case-stream"],
            data_scopes=["case:read"],
        )

    async def run(self, case: Case, svc: AgentServices) -> AgentOutput:
        if svc.repo is None:
            return AgentOutput(notes="no case stream available")
        recent = svc.repo.list(case.tenant_id, limit=200)
        same_source = [
            c
            for c in recent
            if c.alerts and case.alerts and c.alerts[0].source == case.alerts[0].source
        ]
        ev: list[Evidence] = []
        if len(same_source) >= 5:
            ev.append(
                Evidence(
                    tenant_id=case.tenant_id,
                    source="WATCH",
                    summary=f"Burst: {len(same_source)} recent cases from source {case.alerts[0].source!r}.",
                    supports="early_warning",
                )
            )
        return AgentOutput(evidence=ev, notes=f"WATCH scanned {len(recent)} recent case(s).")


class HuntAgent(Agent):
    """Proactive hunting: generates + runs a hunt query from the case's techniques."""

    name = "HUNT"
    autonomy_level = AutonomyLevel.PROPOSE
    handles_untrusted_input = True
    holds_sensitive_access = True
    changes_external_state = False

    def agbom(self) -> AgBOM:
        return AgBOM(
            agent=self.name,
            autonomy_level=self.autonomy_level,
            tools=["connector.query"],
            data_scopes=["siem:read"],
        )

    async def run(self, case: Case, svc: AgentServices) -> AgentOutput:
        if svc.registry is None:
            return AgentOutput(notes="no query connector for hunting")
        queriers = svc.registry.with_capability(Capability.QUERY)
        if not queriers:
            return AgentOutput(notes="no query-capable connector")
        techniques = case.attack_techniques or [t for a in case.alerts for t in a.attack_techniques]
        hypothesis = f"activity for techniques {techniques or ['generic']}"
        query = f"search attack_technique IN ({','.join(techniques) or '*'}) earliest=-7d"
        ev: list[Evidence] = []
        try:
            res = await queriers[0].query(tenant_id=case.tenant_id, native_query=query)
            ev.append(
                Evidence(
                    tenant_id=case.tenant_id,
                    source="HUNT",
                    connector=queriers[0].info().name,
                    query=query,
                    summary=f"Hunt ({hypothesis}) returned {res.count} hit(s).",
                    supports="hunt",
                )
            )
        except ConnectorError:
            pass
        return AgentOutput(
            evidence=ev,
            metadata={"hypothesis": hypothesis, "query": query},
            notes="HUNT executed a hypothesis-driven query.",
        )


class DetAgent(Agent):
    """Detection engineering: coverage gaps + a proposed Sigma skeleton (human-merged, never auto-deployed)."""

    name = "DET"
    autonomy_level = AutonomyLevel.PROPOSE
    handles_untrusted_input = False
    holds_sensitive_access = False
    changes_external_state = False

    def agbom(self) -> AgBOM:
        return AgBOM(
            agent=self.name,
            autonomy_level=self.autonomy_level,
            tools=["detection-inventory", "sigma-gen"],
            data_scopes=["detections:read"],
        )

    async def run(self, case: Case, svc: AgentServices) -> AgentOutput:
        techniques = case.attack_techniques or [t for a in case.alerts for t in a.attack_techniques]
        gaps = coverage_gaps(techniques, detection_inventory())
        ev: list[Evidence] = []
        proposed: dict[str, str] = {}
        if gaps:
            ev.append(
                Evidence(
                    tenant_id=case.tenant_id,
                    source="DET",
                    summary=f"Detection coverage gap for: {', '.join(gaps)}.",
                    supports="detection_gap",
                )
            )
            for t in gaps[:3]:
                proposed[t] = sigma_skeleton(t)
        return AgentOutput(
            evidence=ev,
            metadata={"coverage_gaps": gaps, "proposed_sigma": proposed},
            notes=f"DET found {len(gaps)} coverage gap(s).",
        )


class VulnAgent(Agent):
    """Exposure management: correlates vulns/KEV with assets + active threats and prioritizes."""

    name = "VULN"
    autonomy_level = AutonomyLevel.PROPOSE
    handles_untrusted_input = False
    holds_sensitive_access = False
    changes_external_state = False

    def agbom(self) -> AgBOM:
        return AgBOM(
            agent=self.name,
            autonomy_level=self.autonomy_level,
            tools=["vuln-feed", "asset-inventory"],
            data_scopes=["vuln:read", "asset:read"],
        )

    async def run(self, case: Case, svc: AgentServices) -> AgentOutput:
        identifiers = {o.value for o in _observables(case)}
        techniques = set(case.attack_techniques) | {
            t for a in case.alerts for t in a.attack_techniques
        }
        ev: list[Evidence] = []
        prioritized: list[dict] = []
        for v in sample_vulnerabilities():
            if not (set(v.affected_identifiers) & identifiers):
                continue
            score = v.cvss + (3.0 if v.kev else 0.0) + (2.0 if v.technique in techniques else 0.0)
            prioritized.append({"cve": v.cve, "score": round(score, 1), "kev": v.kev})
            ev.append(
                Evidence(
                    tenant_id=case.tenant_id,
                    source="VULN",
                    summary=f"{v.cve} (CVSS {v.cvss}{', KEV' if v.kev else ''}) affects an involved asset — priority {score:.1f}.",
                    supports="exposure",
                )
            )
        prioritized.sort(key=lambda x: x["score"], reverse=True)
        return AgentOutput(
            evidence=ev,
            metadata={"prioritized": prioritized},
            notes=f"VULN correlated {len(prioritized)} exposure(s).",
        )


class InsiderAgent(Agent):
    """Insider risk: privacy-gated behavioral signals over user activity (data minimization)."""

    name = "INSIDER"
    autonomy_level = AutonomyLevel.PROPOSE
    handles_untrusted_input = True
    holds_sensitive_access = True
    changes_external_state = False

    def agbom(self) -> AgBOM:
        return AgBOM(
            agent=self.name,
            autonomy_level=self.autonomy_level,
            tools=["ueba-heuristics"],
            data_scopes=["user-activity:read (minimized)"],
            permissions=["privacy:purpose-limited"],
        )

    async def run(self, case: Case, svc: AgentServices) -> AgentOutput:
        users = {o.value for o in _observables(case) if o.type == ObservableType.USER}
        if not users:
            return AgentOutput(notes="no user entities; INSIDER not applicable")
        events = [e for a in case.alerts for e in a.events]
        off_hours = sum(1 for e in events if e.time.hour < 7 or e.time.hour >= 20)
        high_sev = any(
            SEVERITY_RANK.get(a.severity, 0) >= SEVERITY_RANK[Severity.HIGH] for a in case.alerts
        )
        ev: list[Evidence] = []
        # Privacy: we report only an aggregate risk signal, not the user's raw activity.
        if off_hours or high_sev:
            ev.append(
                Evidence(
                    tenant_id=case.tenant_id,
                    source="INSIDER",
                    summary=f"Behavioral signal for {len(users)} user(s): {off_hours} off-hours event(s){' + high severity' if high_sev else ''}. (privacy: aggregate only)",
                    supports="insider_risk",
                )
            )
        return AgentOutput(
            evidence=ev,
            metadata={"users_observed": len(users), "privacy": "minimized"},
            notes="INSIDER produced a privacy-gated signal.",
        )
