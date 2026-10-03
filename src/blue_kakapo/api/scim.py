"""SCIM 2.0 user provisioning endpoints (admin-gated). A pragmatic RFC 7644 subset."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from ..security import Permission, Principal, require
from ..security.scim import UserStore

scim_router = APIRouter(prefix="/scim/v2", tags=["scim"])

_req_admin = Depends(require(Permission.ADMIN))


class ScimUserCreate(BaseModel):
    userName: str
    externalId: str | None = None
    displayName: str | None = None
    roles: list[str] = Field(default_factory=lambda: ["analyst"])
    active: bool = True


class ScimPatch(BaseModel):
    active: bool


def _store(request: Request) -> UserStore:
    return request.app.state.user_store


@scim_router.post("/Users", status_code=201)
async def create_user(
    body: ScimUserCreate,
    request: Request,
    principal: Principal = _req_admin,
) -> dict[str, Any]:
    return _store(request).provision(
        tenant_id=principal.tenant_id,
        username=body.userName,
        roles=body.roles,
        external_id=body.externalId,
        display_name=body.displayName,
    )


@scim_router.get("/Users")
async def list_users(request: Request, principal: Principal = _req_admin) -> dict[str, Any]:
    resources = _store(request).list(principal.tenant_id)
    return {"totalResults": len(resources), "Resources": resources}


@scim_router.get("/Users/{user_id}")
async def get_user(user_id: str, request: Request, _: Principal = _req_admin) -> dict[str, Any]:
    user = _store(request).get(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    return user


@scim_router.patch("/Users/{user_id}")
async def patch_user(
    user_id: str,
    body: ScimPatch,
    request: Request,
    _: Principal = _req_admin,
) -> dict[str, Any]:
    """Deprovision/reactivate — a deactivated user is denied at auth time (cascades from the IdP)."""
    user = _store(request).set_active(user_id, body.active)
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    return user


@scim_router.delete("/Users/{user_id}", status_code=204)
async def delete_user(user_id: str, request: Request, _: Principal = _req_admin) -> None:
    _store(request).delete(user_id)
