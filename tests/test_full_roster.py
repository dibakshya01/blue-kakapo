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


def _finding(out) -> dict:  # type: ignore[no-untyped-def]
    """Every deepened agent returns a typed finding under metadata['finding']."""
    assert "finding" in out.metadata, "agent must emit a typed finding"
    return out.metadata["finding"]


async def test_watch_detects_burst() -> None:
    store = Store.in_memory()
    repo = CaseRepo(store)
    for i in range(6):
        repo.save(_case({"title": f"a{i}", "severity": "medium"}))  # source defaults to 'webhook'
    out = await WatchAgent().run(_case({"title": "new", "severity": "medium"}), _svc(repo=repo))
    assert any("Burst" in e.summary for e in out.evidence)
    f = _finding(out)
    assert f["burst_count"] >= 5
    from blue_kakapo.schema.findings import WatchSignal  # typed contract holds

    WatchSignal.model_validate(f)


async def test_watch_flags_shared_indicator_campaign() -> None:
    store = Store.in_memory()
    repo = CaseRepo(store)
    # Two prior cases sharing BOTH an IP and a domain with the incoming case → campaign signal.
    for i in range(2):
        repo.save(
            _case(
                {
                    "title": f"p{i}",
                    "severity": "high",
                    "dst_ip": "203.0.113.9",
                    "domain": "evil.example",
                }
            )
        )
    out = await WatchAgent().run(
        _case(
            {"title": "new", "severity": "high", "dst_ip": "203.0.113.9", "domain": "evil.example"}
        ),
        _svc(repo=repo),
    )
    f = _finding(out)
    assert "203.0.113.9" in f["shared_indicators"]
    assert f["likely_campaign"] is True
    assert any(e.supports == "campaign" for e in out.evidence)


async def test_hunt_runs_query_and_plans_pivot() -> None:
    reg = ConnectorRegistry()
    reg.register(MockSIEM())
    out = await HuntAgent().run(
        _case({"title": "x", "severity": "high", "host": "WS-9"}, techniques=["T1071"]),
        _svc(registry=reg),
    )
    assert any(e.supports == "hunt" for e in out.evidence)
    f = _finding(out)
    assert f["query"] and f["hypothesis"] and f["next_pivot"]
    assert "T1071" in f["techniques"]


async def test_det_finds_gap_and_proposes_sigma() -> None:
    out = await DetAgent().run(
        _case({"title": "ransomware", "severity": "high"}, techniques=["T1486"]), _svc()
    )
    f = _finding(out)
    assert "T1486" in f["gaps"]
    assert f["priority_gap"] == "T1486"  # active in this case -> prioritized
    assert "title:" in f["proposed_sigma"]["T1486"]


async def test_vuln_prioritizes_kev_on_involved_asset() -> None:
    out = await VulnAgent().run(
        _case({"title": "x", "severity": "high", "host": "WS-14"}, techniques=["T1190"]), _svc()
    )
    f = _finding(out)
    assert f["items"] and f["items"][0]["cve"] == "CVE-2026-1001" and f["items"][0]["kev"] is True
    assert f["top_cve"] == "CVE-2026-1001"


async def test_insider_privacy_gated_signal() -> None:
    out = await InsiderAgent().run(
        _case({"title": "x", "severity": "high", "user": "jdoe"}), _svc()
    )
    f = _finding(out)
    assert f["privacy"] == "aggregate-only"
    assert f["risk_level"] in ("elevated", "high")  # high severity -> not low
    assert out.metadata["privacy"] == "minimized"
    assert any("privacy" in e.summary for e in out.evidence)
    # Privacy invariant: the username must not appear in the finding or evidence.
    assert "jdoe" not in str(f)
    assert all("jdoe" not in e.summary for e in out.evidence)


async def test_comms_drafts_external_not_sent() -> None:
    out = await CommsAgent().run(
        _case({"title": "x", "severity": "high"}, verdict_class="malicious"), _svc()
    )
    f = _finding(out)
    assert "requires human approval" in f["external_draft"]
    assert f["headline"] and f["summary"]


async def test_rpt_builds_report_with_clocks() -> None:
    out = await RptAgent().run(
        _case({"title": "x", "severity": "high"}, verdict_class="malicious"), _svc()
    )
    f = _finding(out)
    assert "Incident report" in f["report_markdown"]
    assert f["clock_count"] >= 1  # malicious -> reportable
    assert f["executive_summary"]


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
    f = _finding(out)
    assert f["unhealthy"] == 1
    assert "sick" in f["issues"]
    assert f["recommended_action"]


async def test_mgr_sets_regulatory_clocks_and_priority() -> None:
    case = _case({"title": "breach", "severity": "critical"}, verdict_class="malicious")
    out = await MgrAgent().run(case, _svc())
    assert case.regulatory_clocks  # MGR owns clocks on the case
    frameworks = {c.framework for c in case.regulatory_clocks}
    assert {"DORA", "NIS2", "GDPR", "SEC"} <= frameworks
    f = _finding(out)
    assert f["priority"] in ("high", "urgent")  # malicious + critical + deadline
    assert f["clock_count"] >= 4


def test_compliance_only_for_reportable() -> None:
    assert clocks_for_case(_case({"title": "x", "severity": "low"}, verdict_class="benign")) == []
    assert clocks_for_case(_case({"title": "x", "severity": "high"}, verdict_class="malicious"))
