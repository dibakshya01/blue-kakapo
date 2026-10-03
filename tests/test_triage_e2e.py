"""S2: the walking skeleton end-to-end — orchestrator + API, offline, no key."""

from __future__ import annotations

from fastapi.testclient import TestClient

from blue_kakapo.agents import TriageOrchestrator
from blue_kakapo.api import create_app
from blue_kakapo.config import ProviderKind, Settings
from blue_kakapo.core import Store
from blue_kakapo.providers import ProviderGateway
from blue_kakapo.schema.common import CaseState, RoutingDisposition, VerdictClass


async def test_orchestrator_triages_malicious_end_to_end() -> None:
    store = Store.in_memory()
    orch = TriageOrchestrator(store, ProviderGateway(Settings(provider=ProviderKind.OFFLINE)))
    case = await orch.triage_alert(
        {"title": "C2 beacon", "severity": "high", "dst_ip": "198.51.100.23"}, tenant_id="t1"
    )
    assert case.verdict is not None
    assert case.verdict.verdict_class == VerdictClass.MALICIOUS
    assert case.state == CaseState.ESCALATED
    assert len(case.evidence) >= 1  # evidence-cited

    # The decision path is in the ledger and the chain verifies (the glass-box trail).
    entries = orch.ledger.replay("t1", case_id=case.id)
    actions = [e.action for e in entries]
    assert any(a.startswith("node.enter:intake") for a in actions)
    assert any(a.startswith("l1.verdict:") for a in actions)
    assert orch.ledger.verify("t1") is True


async def test_orchestrator_autocloses_benign() -> None:
    store = Store.in_memory()
    orch = TriageOrchestrator(store, ProviderGateway(Settings(provider=ProviderKind.OFFLINE)))
    case = await orch.triage_alert(
        {"title": "Scheduled backup (test)", "severity": "low", "domain": "internal.example"},
        tenant_id="t1",
    )
    assert case.verdict.routing == RoutingDisposition.AUTO_CLOSE
    assert case.state == CaseState.RESOLVED


def _api() -> TestClient:
    app = create_app(Settings(provider=ProviderKind.OFFLINE), store=Store.in_memory())
    return TestClient(app)


def test_api_ingest_and_retrieve() -> None:
    client = _api()
    r = client.post(
        "/api/ingest",
        json={"alert": {"title": "beacon", "severity": "high", "dst_ip": "198.51.100.23"}},
    )
    assert r.status_code == 200
    case = r.json()["case"]
    assert case["verdict"]["verdict_class"] == "malicious"
    case_id = case["id"]

    # list
    cases = client.get("/api/cases").json()
    assert any(c["id"] == case_id for c in cases)

    # detail
    detail = client.get(f"/api/cases/{case_id}").json()
    assert detail["id"] == case_id

    # ledger replay is verified
    led = client.get(f"/api/cases/{case_id}/ledger").json()
    assert led["verified"] is True
    assert any(e["action"].startswith("l1.verdict:") for e in led["entries"])


def test_api_404_for_unknown_case() -> None:
    client = _api()
    assert client.get("/api/cases/case_doesnotexist").status_code == 404


def test_api_serves_ui() -> None:
    client = _api()
    r = client.get("/")
    assert r.status_code == 200
    assert "blue-kakapo" in r.text
