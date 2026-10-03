"""blue-kakapo security — authn (open/local/OIDC), RBAC, secrets, SCIM."""

from __future__ import annotations

from .auth import Authenticator, AuthError
from .deps import get_principal, require
from .oidc import OIDCError, OIDCVerifier
from .principal import Permission, Principal, Role, open_principal, permissions_for
from .secrets import (
    EnvSecretStore,
    FileSecretStore,
    OpenBaoSecretStore,
    SecretStore,
    build_secret_store,
)

__all__ = [
    "Authenticator",
    "AuthError",
    "OIDCVerifier",
    "OIDCError",
    "Principal",
    "Permission",
    "Role",
    "open_principal",
    "permissions_for",
    "get_principal",
    "require",
    "SecretStore",
    "EnvSecretStore",
    "FileSecretStore",
    "OpenBaoSecretStore",
    "build_secret_store",
]
