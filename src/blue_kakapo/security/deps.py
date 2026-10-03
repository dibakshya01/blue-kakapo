"""FastAPI auth/authz dependencies."""

from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends, HTTPException, Request

from .auth import Authenticator, AuthError
from .principal import Permission, Principal


def get_authenticator(request: Request) -> Authenticator:
    return request.app.state.authenticator


def get_principal(
    request: Request, authenticator: Authenticator = Depends(get_authenticator)
) -> Principal:
    try:
        return authenticator.authenticate(request.headers.get("authorization"))
    except AuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


def require(permission: Permission) -> Callable[[Principal], Principal]:
    """Return a dependency that enforces ``permission`` on the authenticated principal."""

    def _dep(principal: Principal = Depends(get_principal)) -> Principal:
        if not principal.can(permission):
            raise HTTPException(
                status_code=403,
                detail=f"permission '{permission}' required (roles: {principal.roles})",
            )
        return principal

    return _dep
