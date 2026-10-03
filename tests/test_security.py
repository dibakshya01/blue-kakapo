"""S8: auth (open/local/OIDC), RBAC, SCIM deprovision cascade, API enforcement, tenant isolation."""

from __future__ import annotations

import datetime as _dt

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from blue_kakapo.api import create_app
from blue_kakapo.config import ProviderKind, Settings
from blue_kakapo.core import Store
from blue_kakapo.security import (
    Authenticator,
    AuthError,
    EnvSecretStore,
    OIDCVerifier,
    Permission,
    Principal,
    Role,
    permissions_for,
)
from blue_kakapo.security.oidc import OIDCError
from blue_kakapo.security.scim import UserStore


def _rsa_jwt_with(**claims: object) -> tuple[str, dict]:
    """Mint a signed RS256 JWT with arbitrary claims + its JWKS (for adversarial OIDC tests)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_jwk = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    pub_jwk["kid"] = "k1"
    now = _dt.datetime.now(_dt.UTC)
    base = {"iss": "https://idp.example", "iat": now, "exp": now + _dt.timedelta(hours=1)}
    token = jwt.encode({**base, **claims}, key, algorithm="RS256", headers={"kid": "k1"})
    return token, {"keys": [pub_jwk]}


def test_role_permissions() -> None:
    assert Permission.VIEW in permissions_for([Role.VIEWER.value])
    assert Permission.PROPOSE_RESPONSE not in permissions_for([Role.ANALYST.value])
    assert Permission.PROPOSE_RESPONSE in permissions_for([Role.RESPONDER.value])
    assert permissions_for([Role.ADMIN.value]) == set(Permission)
    assert Principal(id="u", tenant_id="t", roles=["responder"]).can(Permission.APPROVE_RESPONSE)


def test_open_mode_grants_local_admin() -> None:
    auth = Authenticator(Settings(auth_enabled=False))
    p = auth.authenticate(None)
    assert p.auth_method == "open" and p.can(Permission.ADMIN)


def test_local_token_auth() -> None:
    auth = Authenticator(Settings(auth_enabled=True, api_tokens=["sek:acme:responder|viewer"]))
    p = auth.authenticate("Bearer sek")
    assert p.tenant_id == "acme" and "responder" in p.roles
    with pytest.raises(AuthError):
        auth.authenticate(None)
    with pytest.raises(AuthError):
        auth.authenticate("Bearer nope")


# --- OIDC ---


def _rsa_jwt() -> tuple[str, dict]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_jwk = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    pub_jwk["kid"] = "k1"
    now = _dt.datetime.now(_dt.UTC)
    token = jwt.encode(
        {
            "sub": "u-123",
            "preferred_username": "alice",
            "tenant": "acme",
            "roles": ["analyst", "responder"],
            "iss": "https://idp.example",
            "aud": "blue-kakapo",
            "iat": now,
            "exp": now + _dt.timedelta(hours=1),
        },
        key,
        algorithm="RS256",
        headers={"kid": "k1"},
    )
    return token, {"keys": [pub_jwk]}


def test_oidc_verify_maps_claims() -> None:
    token, jwks = _rsa_jwt()
    v = OIDCVerifier(
        issuer="https://idp.example",
        jwks_url="https://idp.example/jwks",
        audience="blue-kakapo",
        jwks=jwks,
    )
    p = v.verify(token)
    assert p.tenant_id == "acme" and p.auth_method == "oidc" and "responder" in p.roles
    assert p.display_name == "alice"


def test_scim_deprovision_cascades_to_auth() -> None:
    token, jwks = _rsa_jwt()
    store = Store.in_memory()
    users = UserStore(store)
    auth = Authenticator(Settings(auth_enabled=True))
    auth.set_oidc(
        OIDCVerifier(issuer="https://idp.example", jwks_url="x", audience="blue-kakapo", jwks=jwks)
    )
    auth.set_user_store(users)

    # Unknown user is allowed (token/OIDC vouched); then provision + deprovision.
    assert auth.authenticate(f"Bearer {token}").id == "u-123"
    rec = users.provision(tenant_id="acme", username="alice", roles=["analyst"])
    assert auth.authenticate(f"Bearer {token}").id == "u-123"  # active
    users.set_active(rec["id"], False)
    with pytest.raises(AuthError, match="deprovisioned"):
        auth.authenticate(f"Bearer {token}")


# round-2 🟡-M2 — the audience fail-closed must live in the verifier, not only in config.
def test_oidc_verifier_refuses_audienceless_construction() -> None:
    with pytest.raises(OIDCError, match="audience"):
        OIDCVerifier(issuer="https://idp.example", jwks_url="x")  # no audience, no opt-in
    # Explicit opt-in is allowed (documented air-gap escape hatch).
    OIDCVerifier(issuer="https://idp.example", jwks_url="x", insecure_skip_aud=True)


# round-2 🟡-M2 — an audience-less verifier must NOT accept a token minted for another audience.
def test_oidc_rejects_wrong_audience_even_via_set_oidc() -> None:
    token, jwks = _rsa_jwt_with(sub="u-9", aud="some-OTHER-app", tenant="victim", roles=["admin"])
    auth = Authenticator(Settings(auth_enabled=True))
    # Correct verifier (bound to our audience) rejects the foreign-audience token.
    auth.set_oidc(
        OIDCVerifier(issuer="https://idp.example", jwks_url="x", audience="blue-kakapo", jwks=jwks)
    )
    with pytest.raises(AuthError):
        auth.authenticate(f"Bearer {token}")


# round-2 🟡-M3 — deprovision cascades even when the token carries a `name` claim (Entra/Okta default).
def test_scim_deprovision_cascades_with_name_claim() -> None:
    token, jwks = _rsa_jwt_with(
        sub="u-777", preferred_username="jdoe", name="John Doe", tenant="acme", aud="blue-kakapo"
    )
    store = Store.in_memory()
    users = UserStore(store)
    auth = Authenticator(Settings(auth_enabled=True))
    auth.set_oidc(
        OIDCVerifier(issuer="https://idp.example", jwks_url="x", audience="blue-kakapo", jwks=jwks)
    )
    auth.set_user_store(users)

    rec = users.provision(tenant_id="acme", username="jdoe", roles=["analyst"], external_id="u-777")
    assert auth.authenticate(f"Bearer {token}").id == "u-777"  # active
    users.set_active(rec["id"], False)
    with pytest.raises(AuthError, match="deprovisioned"):
        auth.authenticate(f"Bearer {token}")  # name claim no longer masks the deprovision


def test_env_secret_store(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BK_SECRET_SPLUNK_TOKEN", "s3cr3t")
    assert EnvSecretStore().get("splunk_token") == "s3cr3t"
    assert EnvSecretStore().get("missing") is None


# --- API enforcement + tenant isolation ---


def _app() -> TestClient:
    settings = Settings(
        provider=ProviderKind.OFFLINE,
        auth_enabled=True,
        api_tokens=[
            "viewtok::viewer",
            "resptok::responder",
            "admtok::admin",
            "atok:tenantA:analyst",
            "btok:tenantB:analyst",
        ],
    )
    return TestClient(create_app(settings, store=Store.in_memory()))


def _h(tok: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {tok}"}


def test_api_requires_auth_and_permissions() -> None:
    c = _app()
    assert c.get("/api/cases").status_code == 401  # no token
    assert c.get("/api/cases", headers=_h("viewtok")).status_code == 200  # viewer can view
    # viewer cannot triage
    assert (
        c.post("/api/ingest", json={"alert": {"title": "x"}}, headers=_h("viewtok")).status_code
        == 403
    )
    # analyst can triage
    r = c.post(
        "/api/ingest",
        json={"alert": {"title": "x", "severity": "high", "dst_ip": "198.51.100.23"}},
        headers=_h("atok"),
    )
    assert r.status_code == 200
    case_id = r.json()["case"]["id"]
    # analyst cannot respond (needs responder)
    assert (
        c.post(
            f"/api/cases/{case_id}/respond", json={"dry_run": True}, headers=_h("atok")
        ).status_code
        == 403
    )


def test_api_tenant_isolation() -> None:
    c = _app()
    r = c.post(
        "/api/ingest", json={"alert": {"title": "secret", "severity": "high"}}, headers=_h("atok")
    )
    case_id = r.json()["case"]["id"]
    # tenantB cannot see tenantA's case (404, not 403 — no existence leak)
    assert c.get(f"/api/cases/{case_id}", headers=_h("btok")).status_code == 404
    assert c.get(f"/api/cases/{case_id}", headers=_h("atok")).status_code == 200
    # tenantB lists only its own (empty) cases
    assert c.get("/api/cases", headers=_h("btok")).json() == []


def test_scim_endpoints_admin_only() -> None:
    c = _app()
    assert c.get("/scim/v2/Users", headers=_h("viewtok")).status_code == 403
    created = c.post(
        "/scim/v2/Users", json={"userName": "bob", "roles": ["analyst"]}, headers=_h("admtok")
    )
    assert created.status_code == 201
    uid = created.json()["id"]
    assert (
        c.patch(f"/scim/v2/Users/{uid}", json={"active": False}, headers=_h("admtok")).json()[
            "active"
        ]
        is False
    )
