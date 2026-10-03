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


def test_containment_on_normal_asset_asks_two_humans_with_ttl() -> None:
    # Containment is high-impact: ASK (never auto-MODIFY) even on a normal/unknown asset, with the
    # TTL carried as the effective action approvers will run. Two humans required.
    disp = PolicyEngine().decide(_d("isolate_host"))
    assert disp.decision == ACSDisposition.ASK
    assert disp.required_approvals == 2
    assert disp.modified_action is not None
    assert disp.modified_action.args.get("ttl_seconds") == 3600


def test_crown_jewel_isolate_asks_with_two_approvals() -> None:
    disp = PolicyEngine().decide(_d("isolate_host", asset_criticality=AssetCriticality.CROWN_JEWEL))
    assert disp.decision == ACSDisposition.ASK
    assert disp.required_approvals == 2


def test_all_high_impact_verbs_require_two_humans_on_normal_assets() -> None:
    # The core "human-in-the-loop by default" guarantee: no high-impact verb auto-executes.
    for verb in (
        "isolate_host",
        "disable_user",
        "kill_process",
        "quarantine_file",
        "firewall_drop",
    ):
        disp = PolicyEngine().decide(_d(verb))
        assert disp.decision == ACSDisposition.ASK, verb
        assert disp.required_approvals == 2, verb


def test_capability_gate_denies_unsupported() -> None:
    disp = PolicyEngine().decide(_d("block_ioc", connector_supports=False))
    assert disp.decision == ACSDisposition.DENY


def test_blast_radius_over_cap_asks() -> None:
    disp = PolicyEngine().decide(
        _d("block_ioc", blast_radius_estimate=50, max_concurrent_actions=5)
    )
    assert disp.decision == ACSDisposition.ASK


def test_high_impact_non_containment_asks() -> None:
    # disable_user is high-impact but not containment: ASK with two approvals, no TTL rewrite.
    disp = PolicyEngine().decide(_d("disable_user"))
    assert disp.decision == ACSDisposition.ASK
    assert disp.required_approvals == 2
    assert disp.modified_action is None
