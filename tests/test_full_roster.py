"""S9: the remaining 9 agents + compliance clocks + full 14-agent roster."""

from __future__ import annotations

from blue_kakapo.agents import (
    CommsAgent,
    DetAgent,
    HuntAgent,
    InsiderAgent,
    MaintAgent,
    MgrAgent,
    RptAgent,
    TriageOrchestrator,
    VulnAgent,
    WatchAgent,
)
from blue_kakapo.agents.sdk import AgentServices
from blue_kakapo.compliance import clocks_for_case
from blue_kakapo.config import ProviderKind, Settings
from blue_kakapo.connectors import ConnectorRegistry, MockSIEM
from blue_kakapo.connectors.base import BaseConnector, Capability, ConnectorInfo, HealthStatus
from blue_kakapo.core import CaseRepo, Store
from blue_kakapo.normalize import normalize_alert
from blue_kakapo.providers import ProviderGateway
from blue_kakapo.schema.models import Case, Verdict


def _gw() -> ProviderGateway:
    return ProviderGateway(Settings(provider=ProviderKind.OFFLINE))


def _case(raw: dict, techniques: list[str] | None = None, verdict_class: str | None = None) -> Case:
    a = normalize_alert(raw, tenant_id="t1")
    c = Case(
        tenant_id="t1",
        title=a.title,
        severity=a.severity,
        alerts=[a],
        attack_techniques=techniques or [],
    )
    if verdict_class:
        c.verdict = Verdict(
            verdict_class=verdict_class, routing="escalate", confidence=0.9, rationale="x"
        )
    return c


async def _noop(action: str, **kw: object) -> None:
    return None


def _svc(**kw: object) -> AgentServices:
    return AgentServices(tenant_id="t1", gateway=_gw(), emit=_noop, **kw)  # type: ignore[arg-type]


def test_full_roster_has_14_agents_all_valid() -> None:
    orch = TriageOrchestrator(Store.in_memory(), _gw())
    assert len(orch.roster) == 14
    names = {a.name for a in orch.roster}
    assert names == {
        "L1",
        "L2",
        "INTEL",
        "FUSION",
        "RESP",
        "WATCH",
        "HUNT",
        "DET",
        "VULN",
        "INSIDER",
        "COMMS",
        "RPT",
        "MAINT",
        "MGR",
    }
    for a in orch.roster:
        assert a.agbom().agent == a.name  # constructed (Rule-of-Two satisfied)


async def test_watch_detects_burst() -> None:
    store = Store.in_memory()
    repo = CaseRepo(store)
    for i in range(6):
        repo.save(_case({"title": f"a{i}", "severity": "medium"}))  # source defaults to 'webhook'
    out = await WatchAgent().run(_case({"title": "new", "severity": "medium"}), _svc(repo=repo))
    assert any("Burst" in e.summary for e in out.evidence)


async def test_hunt_runs_query() -> None:
    reg = ConnectorRegistry()
    reg.register(MockSIEM())
    out = await HuntAgent().run(
        _case({"title": "x", "severity": "high"}, techniques=["T1071"]), _svc(registry=reg)
    )
    assert any(e.supports == "hunt" for e in out.evidence)
    assert "query" in out.metadata


async def test_det_finds_gap_and_proposes_sigma() -> None:
    out = await DetAgent().run(
        _case({"title": "ransomware", "severity": "high"}, techniques=["T1486"]), _svc()
    )
    assert "T1486" in out.metadata["coverage_gaps"]
    assert "T1486" in out.metadata["proposed_sigma"]
    assert "title:" in out.metadata["proposed_sigma"]["T1486"]


async def test_vuln_prioritizes_kev_on_involved_asset() -> None:
    out = await VulnAgent().run(
        _case({"title": "x", "severity": "high", "host": "WS-14"}, techniques=["T1190"]), _svc()
    )
    prioritized = out.metadata["prioritized"]
    assert (
        prioritized and prioritized[0]["cve"] == "CVE-2026-1001" and prioritized[0]["kev"] is True
    )


async def test_insider_privacy_gated_signal() -> None:
    out = await InsiderAgent().run(
        _case({"title": "x", "severity": "high", "user": "jdoe"}), _svc()
    )
    assert out.metadata["privacy"] == "minimized"
    assert any("privacy" in e.summary for e in out.evidence)


async def test_comms_drafts_external_not_sent() -> None:
    out = await CommsAgent().run(
        _case({"title": "x", "severity": "high"}, verdict_class="malicious"), _svc()
    )
    assert "external_draft" in out.metadata
    assert "requires human approval" in out.metadata["external_draft"]


async def test_rpt_builds_report_with_clocks() -> None:
    out = await RptAgent().run(
        _case({"title": "x", "severity": "high"}, verdict_class="malicious"), _svc()
    )
    assert "Incident report" in out.metadata["report"]
    assert out.metadata["clock_count"] >= 1  # malicious -> reportable


async def test_maint_flags_unhealthy_connector() -> None:
    class SickConnector(BaseConnector):
        kind = "sick"

        def info(self) -> ConnectorInfo:
            return ConnectorInfo(name="sick", kind=self.kind, capabilities=[Capability.READ_ALERTS])

        async def health(self) -> HealthStatus:
            return HealthStatus(healthy=False, detail="connection refused")

    reg = ConnectorRegistry()
    reg.register(SickConnector("sick"))
    out = await MaintAgent().run(_case({"title": "x", "severity": "low"}), _svc(registry=reg))
    assert out.metadata["unhealthy_connectors"] == 1


async def test_mgr_sets_regulatory_clocks() -> None:
    case = _case({"title": "breach", "severity": "critical"}, verdict_class="malicious")
    out = await MgrAgent().run(case, _svc())
    assert case.regulatory_clocks  # MGR owns clocks on the case
    frameworks = {c["framework"] for c in out.metadata["clocks"]}
    assert {"DORA", "NIS2", "GDPR", "SEC"} <= frameworks


def test_compliance_only_for_reportable() -> None:
    assert clocks_for_case(_case({"title": "x", "severity": "low"}, verdict_class="benign")) == []
    assert clocks_for_case(_case({"title": "x", "severity": "high"}, verdict_class="malicious"))
