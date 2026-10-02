"""S0: the control-plane API comes up and reports health/provider status."""

from __future__ import annotations

from fastapi.testclient import TestClient

from blue_kakapo.api import create_app
from blue_kakapo.config import ProviderKind, Settings


def _client() -> TestClient:
    app = create_app(Settings(provider=ProviderKind.OFFLINE))
    return TestClient(app)


def test_healthz() -> None:
    r = _client().get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_readyz_reports_provider() -> None:
    r = _client().get("/readyz")
    assert r.status_code == 200
    body = r.json()
    assert body["ready"] is True
    assert body["provider"] == "offline"


def test_provider_status_redacts_and_reports_offline() -> None:
    r = _client().get("/api/provider")
    assert r.status_code == 200
    body = r.json()
    assert body["provider"] == "offline"
    assert body["offline"] is True
    # No secrets should ever appear in this payload.
    assert "api_key" not in str(body).lower()
