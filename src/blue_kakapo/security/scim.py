"""Minimal SCIM 2.0 user provisioning (create / list / get / deactivate / delete).

Lets an IdP provision and — crucially — **deprovision** users. A deactivated user is denied at auth
time (``UserStore.is_active``), so disabling someone in the IdP cascades to blue-kakapo. This is a
pragmatic subset of RFC 7644, enough for lifecycle management.
"""

from __future__ import annotations

from typing import Any

from ..core.store import Store
from ..schema.common import new_id, utcnow


class UserStore:
    def __init__(self, store: Store) -> None:
        self.store = store

    def provision(
        self,
        *,
        tenant_id: str,
        username: str,
        roles: list[str],
        external_id: str | None = None,
        display_name: str | None = None,
    ) -> dict[str, Any]:
        existing = self.store.get_user_by_username(tenant_id, username)
        uid = existing["id"] if existing else new_id("user")
        record = {
            "id": uid,
            "tenant_id": tenant_id,
            "username": username,
            "active": True,
            "external_id": external_id,
            "roles": roles,
            "display_name": display_name,
            "created_at": utcnow().isoformat(),
        }
        self.store.upsert_user(
            {
                "id": uid,
                "tenant_id": tenant_id,
                "username": username,
                "active": True,
                "external_id": external_id,
                "data": record,
            }
        )
        return record

    def set_active(self, user_id: str, active: bool) -> dict[str, Any] | None:
        row = self.store.get_user(user_id)
        if row is None:
            return None
        data = dict(row["data"])
        data["active"] = active
        self.store.upsert_user(
            {
                "id": row["id"],
                "tenant_id": row["tenant_id"],
                "username": row["username"],
                "active": active,
                "external_id": row["external_id"],
                "data": data,
            }
        )
        return data

    def get(self, user_id: str) -> dict[str, Any] | None:
        row = self.store.get_user(user_id)
        return dict(row["data"]) if row else None

    def list(self, tenant_id: str) -> list[dict[str, Any]]:
        return [dict(r["data"]) for r in self.store.list_users(tenant_id)]

    def delete(self, user_id: str) -> None:
        self.store.delete_user(user_id)

    def is_active(
        self, tenant_id: str, username: str | None = None, *, external_id: str | None = None
    ) -> bool:
        """True if the user is unknown (not provisioned) OR provisioned-and-active.

        Resolves the SCIM record by a **stable identifier** — the IdP subject (``external_id``) first,
        then ``userName`` — never by display name, so a deprovision cascades regardless of whether the
        token carries a ``name`` claim (Entra/Okta/Google default). Unknown users aren't blocked here
        (token/OIDC auth already vouched for them); only an explicitly-deprovisioned user is denied.
        """
        if external_id:
            row = self.store.get_user_by_external_id(tenant_id, external_id)
            if row is not None:
                return bool(row["active"])
        if username:
            row = self.store.get_user_by_username(tenant_id, username)
            if row is not None:
                return bool(row["active"])
        return True
