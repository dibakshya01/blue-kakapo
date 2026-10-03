"""Authentication resolver: open (localhost) / local tokens / OIDC.

When ``auth_enabled`` is false (the localhost default) every request runs as an implicit local admin on
the default tenant — zero-friction dev. When enabled, a bearer token is matched against static service
tokens first, then verified as an OIDC JWT. There is no anonymous access once auth is enabled.
"""

from __future__ import annotations

from ..config import Settings
from .oidc import OIDCError, OIDCVerifier
from .principal import Principal, open_principal


class AuthError(RuntimeError):
    pass


def _parse_token_spec(spec: str) -> tuple[str, Principal]:
    # "token:tenant:role1|role2"
    parts = spec.split(":")
    token = parts[0]
    tenant = parts[1] if len(parts) > 1 and parts[1] else "default"
    roles = parts[2].split("|") if len(parts) > 2 and parts[2] else ["analyst"]
    pid = f"token:{token[:6]}…"
    return token, Principal(id=pid, tenant_id=tenant, roles=roles, auth_method="local")


class Authenticator:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.enabled = settings.auth_enabled
        self._tokens: dict[str, Principal] = {}
        for spec in settings.api_tokens:
            if spec.strip():
                token, principal = _parse_token_spec(spec.strip())
                self._tokens[token] = principal
        self._user_store: object | None = None  # optional SCIM UserStore for deprovision checks
        self._oidc: OIDCVerifier | None = None
        if settings.oidc_issuer and settings.oidc_jwks_url:
            if not settings.oidc_audience:
                # Fail closed: without an expected audience, a token minted for *another* relying
                # party on the same issuer would be accepted (confused-deputy). Refuse to start.
                raise AuthError(
                    "OIDC is configured but BK_OIDC_AUDIENCE is unset; audience verification must "
                    "not be disabled. Set the audience to this service's client id."
                )
            self._oidc = OIDCVerifier(
                issuer=settings.oidc_issuer,
                jwks_url=settings.oidc_jwks_url,
                audience=settings.oidc_audience,
                tenant_claim=settings.oidc_tenant_claim,
                roles_claim=settings.oidc_roles_claim,
                default_tenant=settings.default_tenant,
            )

    def set_oidc(self, verifier: OIDCVerifier) -> None:
        """Inject a verifier (used for air-gapped inline JWKS or tests)."""
        self._oidc = verifier

    def set_user_store(self, user_store: object) -> None:
        """Attach a SCIM UserStore so deprovisioned users are denied at auth time."""
        self._user_store = user_store

    def _check_active(self, principal: Principal) -> Principal:
        if self._user_store is not None:
            username = principal.display_name or principal.id
            if not self._user_store.is_active(principal.tenant_id, username):  # type: ignore[attr-defined]
                raise AuthError(f"user {username!r} is deprovisioned")
        return principal

    @staticmethod
    def _bearer(authorization: str | None) -> str | None:
        if not authorization:
            return None
        scheme, _, token = authorization.partition(" ")
        return token.strip() if scheme.lower() == "bearer" and token else None

    def authenticate(self, authorization: str | None) -> Principal:
        if not self.enabled:
            return open_principal(self.settings.default_tenant)
        token = self._bearer(authorization)
        if token is None:
            raise AuthError("missing bearer token")
        if token in self._tokens:
            return self._check_active(self._tokens[token])
        if self._oidc is not None:
            try:
                return self._check_active(self._oidc.verify(token))
            except OIDCError as exc:
                raise AuthError(str(exc)) from exc
        raise AuthError("invalid token")
