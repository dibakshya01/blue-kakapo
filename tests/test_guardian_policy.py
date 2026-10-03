"""S4: the Guardian policy engine decisions (unit)."""

from __future__ import annotations

from blue_kakapo.guardian import DecisionInput, PolicyEngine
from blue_kakapo.schema.actions import Action
from blue_kakapo.schema.common import ACSDisposition, AssetCriticality


def _d(verb: str, **kw) -> DecisionInput:
    reversible = kw.pop("reversible", True)
    action = Action(
        tenant_id="t1", verb=verb, target=kw.pop("target", "host-1"), reversible=reversible
    )
    return DecisionInput(tenant_id="t1", action=action, **kw)


def test_low_impact_reversible_allowed() -> None:
    disp = PolicyEngine().decide(_d("block_ioc"))
    assert disp.decision == ACSDisposition.ALLOW


def test_irreversible_requires_approval() -> None:
    disp = PolicyEngine().decide(_d("kill_process", reversible=False))
    assert disp.decision == ACSDisposition.ASK


def test_containment_gets_ttl_modify() -> None:
    disp = PolicyEngine().decide(_d("isolate_host"))
    assert disp.decision == ACSDisposition.MODIFY
    assert disp.modified_action is not None
    assert disp.modified_action.args.get("ttl_seconds") == 3600


def test_crown_jewel_isolate_asks_with_two_approvals() -> None:
    disp = PolicyEngine().decide(_d("isolate_host", asset_criticality=AssetCriticality.CROWN_JEWEL))
    assert disp.decision == ACSDisposition.ASK  # ask beats the ttl-modify by precedence
    assert disp.required_approvals == 2


def test_capability_gate_denies_unsupported() -> None:
    disp = PolicyEngine().decide(_d("block_ioc", connector_supports=False))
    assert disp.decision == ACSDisposition.DENY


def test_blast_radius_over_cap_asks() -> None:
    disp = PolicyEngine().decide(
        _d("block_ioc", blast_radius_estimate=50, max_concurrent_actions=5)
    )
    assert disp.decision == ACSDisposition.ASK


def test_default_is_ask_when_no_policy_decisive() -> None:
    # A high-impact but reversible action on a normal asset with no connector gate... still gets ttl
    # modify for containment, but a non-containment high-impact reversible verb (quarantine_file is
    # irreversible, disable_user is high-impact reversible) -> disable_user is high-impact, not
    # containment, reversible -> no allow (high impact), no modify (not containment) -> default ask.
    disp = PolicyEngine().decide(_d("disable_user"))
    assert disp.decision == ACSDisposition.ASK
