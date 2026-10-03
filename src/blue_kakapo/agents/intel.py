"""INTEL — Adversary context. Enriches IOCs and maps the case to ATT&CK tactics.

Uses built-in indicators plus any intel connectors (MISP/OpenCTI via the ENRICH capability), treating
all intel content as untrusted data. Read-only external intel; takes no action.
"""

from __future__ import annotations

from ..attack import tactics_for
from ..connectors.base import Capability, ConnectorError
from ..intel_builtin import check_indicator
from ..schema.common import AutonomyLevel
from ..schema.models import AgBOM, Case, Evidence
from ..schema.ocsf import ObservableType
from .l2 import _observables
from .sdk import Agent, AgentOutput, AgentServices

_IOC_TYPES = {
    ObservableType.IP,
    ObservableType.DOMAIN,
    ObservableType.FQDN,
    ObservableType.FILE_HASH,
}


class IntelAgent(Agent):
    name = "INTEL"
    autonomy_level = AutonomyLevel.PROPOSE
    handles_untrusted_input = True
    holds_sensitive_access = False
    changes_external_state = False

    def agbom(self) -> AgBOM:
        return AgBOM(
            agent=self.name,
            autonomy_level=self.autonomy_level,
            tools=["builtin-intel", "connector.enrich", "attack-map"],
            data_scopes=["intel:read"],
        )

    async def run(self, case: Case, svc: AgentServices) -> AgentOutput:
        evidence: list[Evidence] = []
        iocs = [o for o in _observables(case) if o.type in _IOC_TYPES]

        for obs in iocs[:10]:
            label = check_indicator(obs)
            if label == "malicious":
                evidence.append(
                    Evidence(
                        tenant_id=case.tenant_id,
                        source="threat-intel",
                        summary=f"IOC {obs.value} ({obs.type}) is associated with known-malicious activity.",
                        supports="malicious",
                    )
                )

        # External intel connectors (MISP/OpenCTI), if registered.
        if svc.registry is not None:
            for conn in svc.registry.with_capability(Capability.ENRICH):
                if conn.info().kind in ("mock-siem",):  # SIEM enrich handled by L2, skip here
                    continue
                for obs in iocs[:5]:
                    try:
                        evidence.extend(await conn.enrich(tenant_id=case.tenant_id, observable=obs))
                    except ConnectorError:
                        continue

        techniques = list(
            dict.fromkeys(
                [*case.attack_techniques, *(t for a in case.alerts for t in a.attack_techniques)]
            )
        )
        tactics = tactics_for(techniques)
        if tactics:
            evidence.append(
                Evidence(
                    tenant_id=case.tenant_id,
                    source="attack-map",
                    summary=f"Maps to ATT&CK tactics: {', '.join(tactics)}.",
                    supports="context",
                )
            )

        return AgentOutput(
            evidence=evidence,
            techniques=techniques,
            metadata={"tactics": tactics},
            notes=f"INTEL added {len(evidence)} context item(s).",
        )
