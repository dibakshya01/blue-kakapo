"""The Guardian policy engine — a typed, built-in policy DSL (OPA/Rego adapter is optional).

Policies are functions ``(DecisionInput) -> Disposition | None`` (None = no opinion). The engine
aggregates them by precedence: **deny > ask > modify(=allow a rewritten action) > allow**, defaulting
to **ask** when no policy is decisive (never fail-open). The decision input carries the action, the
target's asset criticality, blast-radius state, actor roles, and whether any connector can even
perform the action.
"""

from __future__ import annotations

from collections.abc import Callable

from ..schema.actions import Action, Disposition
from ..schema.common import ACSDisposition, AssetCriticality, BKModel

HIGH_IMPACT_VERBS = frozenset(
    {"isolate_host", "disable_user", "kill_process", "quarantine_file", "firewall_drop"}
)
IRREVERSIBLE_VERBS = frozenset({"kill_process", "quarantine_file", "delete", "wipe"})
CONTAINMENT_VERBS = frozenset({"isolate_host", "firewall_drop"})


class DecisionInput(BKModel):
    tenant_id: str
    action: Action
    actor_roles: list[str] = []
    asset_criticality: str = AssetCriticality.NORMAL
    blast_radius_estimate: int = 1
    in_flight_actions: int = 0
    max_concurrent_actions: int = 5
    confidence: float | None = None
    case_id: str | None = None
    connector_supports: bool = True
    containment_ttl_seconds: int = 3600


Policy = Callable[[DecisionInput], Disposition | None]


# --- built-in policies ---


def capability_gate(d: DecisionInput) -> Disposition | None:
    if not d.connector_supports:
        return Disposition(
            decision=ACSDisposition.DENY,
            reason=f"No connector can perform {d.action.verb!r}.",
            policy_id="capability_gate",
            reversibility="n/a",
        )
    return None


def high_impact_guard(d: DecisionInput) -> Disposition | None:
    """High-impact actions ALWAYS require two humans — on every asset, known or unknown.

    This is the load-bearing "human-in-the-loop by default" guarantee. A high-impact verb
    (isolate_host, disable_user, kill_process, quarantine_file, firewall_drop) is never
    auto-executed, regardless of asset criticality — including the common case of an *unknown*
    asset that defaults to ``normal``. The returned disposition is ``ask`` (not ``modify``), so a
    TTL rewrite can never silently authorize execution: for open-ended containment we attach a
    time-box as the *effective* action the approvers will run, but a human must still approve it.
    """
    if d.action.verb not in HIGH_IMPACT_VERBS:
        return None
    crit = (
        f" on a {d.asset_criticality} asset"
        if d.asset_criticality in (AssetCriticality.CRITICAL, AssetCriticality.CROWN_JEWEL)
        else ""
    )
    modified = None
    if d.action.verb in CONTAINMENT_VERBS and "ttl_seconds" not in d.action.args:
        modified = d.action.model_copy(deep=True)
        modified.args = {**d.action.args, "ttl_seconds": d.containment_ttl_seconds}
    return Disposition(
        decision=ACSDisposition.ASK,
        reason=(
            f"{d.action.verb}{crit} is high-impact; requires two-person approval"
            + (
                f" (time-boxed to {d.containment_ttl_seconds}s on approval)."
                if modified is not None
                else "."
            )
        ),
        policy_id="high_impact_guard",
        required_approvals=2,
        reversibility="reversible" if d.action.reversible else "irreversible",
        modified_action=modified,
    )


def blast_radius_guard(d: DecisionInput) -> Disposition | None:
    if (
        d.blast_radius_estimate > d.max_concurrent_actions
        or d.in_flight_actions >= d.max_concurrent_actions
    ):
        return Disposition(
            decision=ACSDisposition.ASK,
            reason=(
                f"Blast radius {d.blast_radius_estimate} / in-flight {d.in_flight_actions} "
                f"exceeds the cap of {d.max_concurrent_actions}."
            ),
            policy_id="blast_radius_guard",
            required_approvals=1,
        )
    return None


def irreversible_guard(d: DecisionInput) -> Disposition | None:
    if d.action.verb in IRREVERSIBLE_VERBS or not d.action.reversible:
        return Disposition(
            decision=ACSDisposition.ASK,
            reason=f"{d.action.verb} is irreversible; requires human approval.",
            policy_id="irreversible_guard",
            required_approvals=1,
            reversibility="irreversible",
        )
    return None


def low_impact_allow(d: DecisionInput) -> Disposition | None:
    """Allow clearly low-risk, reversible, non-high-impact actions outright."""
    if (
        d.action.verb not in HIGH_IMPACT_VERBS
        and d.action.reversible
        and d.asset_criticality not in (AssetCriticality.CRITICAL, AssetCriticality.CROWN_JEWEL)
    ):
        return Disposition(
            decision=ACSDisposition.ALLOW,
            reason="Low-impact reversible action.",
            policy_id="low_impact_allow",
            reversibility="reversible",
        )
    return None


DEFAULT_POLICIES: list[Policy] = [
    capability_gate,
    high_impact_guard,
    blast_radius_guard,
    irreversible_guard,
    low_impact_allow,
]

_PRECEDENCE = {
    ACSDisposition.DENY: 4,
    ACSDisposition.ASK: 3,
    ACSDisposition.DEFER: 3,
    ACSDisposition.MODIFY: 2,
    ACSDisposition.ALLOW: 1,
}


class PolicyEngine:
    def __init__(
        self, policies: list[Policy] | None = None, *, default_disposition: str = ACSDisposition.ASK
    ) -> None:
        self.policies = policies if policies is not None else list(DEFAULT_POLICIES)
        self.default_disposition = default_disposition

    def decide(self, d: DecisionInput) -> Disposition:
        decisive: list[Disposition] = []
        for policy in self.policies:
            opinion = policy(d)
            if opinion is not None:
                decisive.append(opinion)
        if not decisive:
            return Disposition(
                decision=self.default_disposition,
                reason="No policy was decisive; defaulting conservatively.",
                policy_id="default",
            )
        # Highest precedence wins; among equals, the one demanding the most approvals wins (so a
        # high-impact two-person gate is never weakened by a co-decisive one-person opinion). Ties
        # beyond that keep the earliest policy's opinion (and its modified_action).
        return max(
            decisive,
            key=lambda o: (_PRECEDENCE.get(o.decision, 0), o.required_approvals),
        )
