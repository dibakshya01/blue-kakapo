"""Principals, roles, and permissions — the authorization model.

A ``Principal`` is an authenticated actor (human or service) bound to a **tenant** and a set of
**roles**. Roles expand to permissions; sensitive operations (propose/approve containment, manage
settings) require specific permissions. High-risk actions are additionally gated by the Guardian and
maker-checker — RBAC is the first gate, not the only one.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field

from ..schema.common import BKModel


class Permission(StrEnum):
    VIEW = "view"  # read cases, ledger, roster
    TRIAGE = "triage"  # ingest/triage alerts
    PROPOSE_RESPONSE = "propose_response"  # run RESP (propose containment)
    APPROVE_RESPONSE = "approve_response"  # approve/deny gated actions (maker-checker)
    MANAGE = "manage"  # provider switch, connectors, memory config
    ADMIN = "admin"  # user/tenant administration


class Role(StrEnum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    RESPONDER = "responder"
    ADMIN = "admin"


_ROLE_PERMS: dict[str, set[Permission]] = {
    Role.VIEWER: {Permission.VIEW},
    Role.ANALYST: {Permission.VIEW, Permission.TRIAGE},
    Role.RESPONDER: {
        Permission.VIEW,
        Permission.TRIAGE,
        Permission.PROPOSE_RESPONSE,
        Permission.APPROVE_RESPONSE,
    },
    Role.ADMIN: set(Permission),
}


def permissions_for(roles: list[str]) -> set[Permission]:
    out: set[Permission] = set()
    for role in roles:
        out |= _ROLE_PERMS.get(role, set())
    return out


class Principal(BKModel):
    id: str  # stable subject (OIDC `sub` / token id) — used for maker-checker + SCIM external_id
    tenant_id: str
    roles: list[str] = Field(default_factory=lambda: [Role.VIEWER.value])
    username: str | None = None  # stable login (OIDC preferred_username / SCIM userName)
    display_name: str | None = None
    auth_method: str = "local"  # local | oidc | open

    def permissions(self) -> set[Permission]:
        return permissions_for(self.roles)

    def can(self, permission: Permission) -> bool:
        return permission in self.permissions()


# The implicit principal used on localhost when auth is disabled: full access, default tenant.
def open_principal(tenant_id: str) -> Principal:
    return Principal(
        id="local-admin",
        tenant_id=tenant_id,
        roles=[Role.ADMIN.value],
        display_name="Local admin (auth disabled)",
        auth_method="open",
    )
