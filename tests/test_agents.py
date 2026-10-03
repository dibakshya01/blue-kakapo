"""S6: the core-5 agents + the SDK (incl. structural Rule-of-Two enforcement)."""

from __future__ import annotations

import pytest

from blue_kakapo.agents import (
    AgentConfigError,
    AgentServices,
    FusionAgent,
    IntelAgent,
    L1Agent,
    L2Agent,
    RespAgent,
    TriageOrchestrator,
)
from blue_kakapo.agents.sdk import Agent
from blue_kakapo.assets import AssetInventory
from blue_kakapo.config import ProviderKind, Settings
from blue_kakapo.connectors import ConnectorRegistry, MockEDR, MockSIEM
from blue_kakapo.core import CaseRepo, Ledger, Store
from blue_kakapo.guardian import GuardedExecutor, Guardian
from blue_kakapo.normalize import normalize_alert
from blue_kakapo.providers import ProviderGateway
from blue_kakapo.schema.common import CaseState, VerdictClass
from blue_kakapo.schema.models import AgBOM, AssetRecord, Case


def _gw() -> ProviderGateway:
    return ProviderGateway(Settings(provider=ProviderKind.OFFLINE))


def _case(raw: dict) -> Case:
    a = normalize_alert(raw, tenant_id="t1")
    return Case(tenant_id="t1", title=a.title, severity=a.severity, alerts=[a])


async def _noop_emit(action: str, **kw: object) -> None:
    return None


def _svc(**kw: object) -> AgentServices:
    return AgentServices(tenant_id="t1", gateway=_gw(), emit=_noop_emit, **kw)  # type: ignore[arg-type]


def test_rule_of_two_is_enforced_at_construction() -> None:
    class RecklessAgent(Agent):
        name = "RECKLESS"
        handles_untrusted_input = True
        holds_sensitive_access = True
        changes_external_state = True

        def agbom(self) -> AgBOM:
            return AgBOM(agent=self.name)

        async def run(self, case: Case, svc: AgentServices):  # pragma: no cover
            ...

    with pytest.raises(AgentConfigError):
        RecklessAgent()
    # The core-5 all satisfy the Rule of Two.
    for a in (L1Agent(), L2Agent(), IntelAgent(), FusionAgent(), RespAgent()):
        assert a.agbom().agent == a.name


async def test_l1_agent_produces_verdict() -> None:
    out = await L1Agent().run(
        _case({"title": "beacon", "severity": "high", "dst_ip": "198.51.100.23"}), _svc()
    )
    assert out.verdict and out.verdict.verdict_class == VerdictClass.MALICIOUS


async def test_l2_agent_enriches_and_queries() -> None:
    reg = ConnectorRegistry()
    reg.register(MockSIEM())
    out = await L2Agent().run(
        _case({"title": "x", "severity": "high", "src_ip": "10.0.0.5"}), _svc(registry=reg)
    )
    assert out.evidence
    assert any("seen" in e.summary for e in out.evidence)  # enrich
    assert any("SIEM returned" in e.summary for e in out.evidence)  # query escape hatch


async def test_intel_agent_flags_known_bad_and_maps_tactics() -> None:
    case = _case(
        {
            "title": "c2",
            "severity": "high",
            "dst_ip": "198.51.100.23",
            "attack_techniques": ["T1071"],
        }
    )
    out = await IntelAgent().run(case, _svc())
    assert any(e.supports == "malicious" for e in out.evidence)
    assert any("ATT&CK tactics" in e.summary for e in out.evidence)  # command-and-control


async def test_fusion_agent_correlates_shared_entities() -> None:
    store = Store.in_memory()
    repo = CaseRepo(store)
    c1 = _case({"title": "a", "severity": "high", "dst_ip": "198.51.100.23"})
    c2 = _case({"title": "b", "severity": "high", "dst_ip": "198.51.100.23"})
    repo.save(c1)
    repo.save(c2)
    out = await FusionAgent().run(c1, _svc(repo=repo))
    assert out.metadata.get("correlated_case_ids") == [c2.id]
    assert any("Correlated with case" in e.summary for e in out.evidence)


async def test_resp_agent_is_guardian_gated() -> None:
    store = Store.in_memory()
    reg = ConnectorRegistry()
    edr = MockEDR()
    reg.register(edr)
    inv = AssetInventory(store)
    inv.upsert(
        AssetRecord(tenant_id="t1", name="WS-1", identifiers=["WS-1"], criticality="crown_jewel")
    )
    guardian = GuardedExecutor(Guardian(inv, reg), reg, Ledger(store), store)

    case = _case({"title": "ransomware", "severity": "high", "host": "WS-1"})
    case.verdict = (await L1Agent().run(case, _svc())).verdict
    case.verdict.verdict_class = VerdictClass.MALICIOUS  # force actionable
    out = await RespAgent().run(
        case, _svc(registry=reg, guardian=guardian, options={"dry_run": False})
    )
    results = out.metadata.get("results", [])
    assert (
        results and results[0]["status"] == "pending_approval"
    )  # crown jewel -> never auto-isolated
    assert "WS-1" not in edr.isolated_hosts


async def test_orchestrator_full_flow_and_gated_respond() -> None:
    store = Store.in_memory()
    gw = _gw()
    reg = ConnectorRegistry()
    edr = MockEDR()
    reg.register(MockSIEM())
    reg.register(edr)
    inv = AssetInventory(store)
    ledger = Ledger(store)
    guardian = GuardedExecutor(Guardian(inv, reg), reg, ledger, store)
    orch = TriageOrchestrator(
        store, gw, ledger=ledger, registry=reg, inventory=inv, guardian=guardian
    )

    case = await orch.triage_alert(
        {"title": "C2 beacon", "severity": "high", "dst_ip": "198.51.100.23", "host": "WS-5"},
        tenant_id="t1",
    )
    assert case.state == CaseState.ESCALATED
    sources = {e.source for e in case.evidence}
    assert {"builtin-intel", "threat-intel", "fusion"} & sources  # investigation ran
    assert ledger.verify("t1") is True

    # Explicit, gated response (dry-run): nothing actually isolated.
    responded = await orch.respond(case.id, dry_run=True)
    assert responded.state in (CaseState.RESOLVED, CaseState.AWAITING_APPROVAL)
    assert "WS-5" not in edr.isolated_hosts
