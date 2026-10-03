"""OIDC bearer-token verification (RS256 via JWKS) for enterprise SSO.

Validates a signed JWT against the IdP's JWKS (Keycloak/Entra/Okta/Dex/...), checking signature,
issuer, audience, and expiry, then maps claims to a Principal (tenant + roles). SAML deployments front
blue-kakapo with an OIDC-bridging proxy (oauth2-proxy / Keycloak); SCIM handles provisioning.
"""

from __future__ import annotations

from typing import Any

import httpx
import jwt
from jwt import PyJWKClient

from .principal import Principal


class OIDCError(RuntimeError):
    pass


class OIDCVerifier:
    def __init__(
        self,
        *,
        issuer: str,
        jwks_url: str,
        audience: str | None = None,
        tenant_claim: str = "tenant",
        roles_claim: str = "roles",
        default_tenant: str = "default",
        jwks: dict[str, Any] | None = None,
        insecure_skip_aud: bool = False,
    ) -> None:
        # Fail closed at the verifier level (not just config): without an expected audience, a token
        # minted for another relying party on the same issuer would be accepted (confused deputy).
        # Skipping audience must be an explicit, named opt-in — never a silent default.
        if audience is None and not insecure_skip_aud:
            raise OIDCError(
                "OIDCVerifier requires an audience; pass insecure_skip_aud=True only if you "
                "genuinely accept tokens for any audience on this issuer."
            )
        self.issuer = issuer
        self.jwks_url = jwks_url
        self.audience = audience
        self.tenant_claim = tenant_claim
        self.roles_claim = roles_claim
        self.default_tenant = default_tenant
        self._jwks = jwks  # inline JWKS (tests / air-gap); else fetched from jwks_url
        self._jwk_client: PyJWKClient | None = None

    def _signing_key(self, token: str) -> Any:
        if self._jwks is not None:
            header = jwt.get_unverified_header(token)
            for key in self._jwks.get("keys", []):
                if key.get("kid") == header.get("kid"):
                    return jwt.algorithms.RSAAlgorithm.from_jwk(key)
            raise OIDCError("no matching JWK for token kid")
        if self._jwk_client is None:
            self._jwk_client = PyJWKClient(self.jwks_url)
        return self._jwk_client.get_signing_key_from_jwt(token).key

    def verify(self, token: str) -> Principal:
        try:
            key = self._signing_key(token)
            claims = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                audience=self.audience,
                issuer=self.issuer,
                options={"verify_aud": self.audience is not None},
            )
        except (jwt.PyJWTError, httpx.HTTPError, OIDCError) as exc:
            raise OIDCError(f"OIDC token verification failed: {exc}") from exc

        roles = claims.get(self.roles_claim) or []
        if isinstance(roles, str):
            roles = [r for r in roles.replace(",", " ").split() if r]
        return Principal(
            id=str(claims.get("sub", "unknown")),
            tenant_id=str(claims.get(self.tenant_claim, self.default_tenant)),
            roles=list(roles) or ["viewer"],
            username=claims.get("preferred_username") or claims.get("email"),
            display_name=claims.get("name") or claims.get("preferred_username"),
            auth_method="oidc",
        )
