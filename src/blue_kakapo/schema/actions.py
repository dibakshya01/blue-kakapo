"""Action and Guardian-disposition models.

An ``Action`` is any state-changing operation an agent proposes (isolate host, disable user, block
IOC, ...). Every action passes through the Guardian, which returns a ``Disposition`` (ACS: allow /
deny / modify / ask / defer). These live in ``schema`` because they are data; the Guardian *engine*
that produces dispositions lives in ``blue_kakapo.guardian``.
"""

from __future__ import annotations

from typing import Any

from pydantic import Field

from .common import ACSDisposition, BKModel, TenantScoped, new_id, new_token


class Action(TenantScoped):
    """A proposed state-changing action, pending a Guardian disposition."""

    id: str = Field(default_factory=lambda: new_id("act"))
    verb: str = Field(
        ..., description="isolate_host | disable_user | block_ioc | kill_process | ..."
    )
    target: str = Field(..., description="The thing acted upon (host id, user, ioc, ...).")
    args: dict[str, Any] = Field(default_factory=dict)
    connector: str | None = Field(default=None, description="Connector that would execute it.")
    reversible: bool = Field(default=True)
    dry_run: bool = Field(default=False)
    idempotency_key: str = Field(default_factory=lambda: new_token(12))
    blast_radius_estimate: int = Field(
        default=1, ge=0, description="Approx number of entities affected."
    )
    proposed_by: str = Field(default="RESP", description="Agent proposing the action.")
    case_id: str | None = None


class Disposition(BKModel):
    """The Guardian's decision on an action. Default is ``ask`` — never fail-open."""

    decision: str = Field(default=ACSDisposition.ASK, description="One of ACSDisposition.*")
    reason: str = Field(default="")
    policy_id: str | None = None
    required_approvals: int = Field(default=0, ge=0)
    reversibility: str = Field(default="unknown", description="reversible | irreversible | unknown")
    modified_action: Action | None = Field(
        default=None,
        description="Present only when decision == 'modify': the sole action the caller may execute.",
    )

    @property
    def is_allowed(self) -> bool:
        return self.decision == ACSDisposition.ALLOW

    @property
    def needs_human(self) -> bool:
        return self.decision in (ACSDisposition.ASK, ACSDisposition.DEFER)
