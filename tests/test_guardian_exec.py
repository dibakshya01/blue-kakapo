"""S4: GuardedExecutor — the egress gate. Allow/deny/modify/ask + maker-checker approvals."""

from __future__ import annotations

import pytest

from blue_kakapo.assets import AssetInventory
from blue_kakapo.connectors import ConnectorRegistry, MockEDR
from blue_kakapo.core import Ledger, Store
from blue_kakapo.guardian import GuardedExecutor, Guardian
from blue_kakapo.schema.actions import Action
from blue_kakapo.schema.models import AssetRecord


def _setup() -> tuple[GuardedExecutor, MockEDR, AssetInventory, Ledger]:
    store = Store.in_memory()
    ledger = Ledger(store)
    registry = ConnectorRegistry()
    edr = MockEDR()
    registry.register(edr)
    inv = AssetInventory(store)
    guardian = Guardian(inv, registry)
    return GuardedExecutor(guardian, registry, ledger, store), edr, inv, ledger


async def test_low_impact_allow_executes_and_is_ledgered() -> None:
    ex, edr, _, ledger = _setup()
    res = await ex.execute(
        Action(tenant_id="t1", verb="block_ioc", target="198.51.100.23"), case_id="c1"
    )
    assert res.status == "ok"
    assert "198.51.100.23" in edr.blocked_iocs
    actions = [e.action for e in ledger.replay("t1", case_id="c1")]
    assert any(a.startswith("guardian.disposition:block_ioc:allow") for a in actions)
    assert any(a.startswith("action.executed:block_ioc") for a in actions)
    assert ledger.verify("t1") is True


async def test_containment_on_normal_asset_requires_two_humans_never_auto_executes() -> None:
    """Regression for the round-1 critical: a high-impact containment on a NORMAL (or unknown)
    asset must ASK for two humans — a TTL modify must never silently authorize execution."""
    ex, edr, _, _ = _setup()
    res = await ex.execute(
        Action(tenant_id="t1", verb="isolate_host", target="host-7"), case_id="c1"
    )
    # ASK, not MODIFY: no auto-execution on a normal/unknown asset.
    assert res.disposition.decision == "ask"
    assert res.status == "pending_approval"
    assert res.disposition.required_approvals == 2
    assert "host-7" not in edr.isolated_hosts  # nothing ran
    # The TTL is carried as the *effective* action the approvers will run (modify composes with ask).
    assert res.disposition.modified_action.args.get("ttl_seconds") == 3600

    # Two distinct humans are required; the TTL'd action runs only after the second.
    r1 = await ex.approve(res.approval_id, "alice")
    assert r1.status == "pending_approval"
    assert "host-7" not in edr.isolated_hosts
    r2 = await ex.approve(res.approval_id, "bob")
    assert r2.status == "ok"
    assert "host-7" in edr.isolated_hosts
    # The executed action was the containment (approval ran the stored effective action).
    assert edr.action_log[-1].verb == "isolate_host"
    assert edr.action_log[-1].target == "host-7"


async def test_crown_jewel_isolate_requires_two_approvals() -> None:
    ex, edr, inv, _ = _setup()
    inv.upsert(
        AssetRecord(tenant_id="t1", name="dc01", identifiers=["dc01"], criticality="crown_jewel")
    )
    res = await ex.execute(Action(tenant_id="t1", verb="isolate_host", target="dc01"), case_id="c1")
    assert res.status == "pending_approval"  # never auto-isolate a crown jewel
    assert "dc01" not in edr.isolated_hosts  # nothing executed yet

    # maker-checker: one approval is not enough (requires 2)
    r1 = await ex.approve(res.approval_id, "alice")
    assert r1.status == "pending_approval"
    assert "dc01" not in edr.isolated_hosts
    # duplicate approver rejected (two-person rule)
    with pytest.raises(ValueError, match="duplicate approver"):
        await ex.approve(res.approval_id, "alice")
    # second distinct approver executes it
    r2 = await ex.approve(res.approval_id, "bob")
    assert r2.status == "ok"
    assert "dc01" in edr.isolated_hosts


async def test_deny_unsupported_action_never_touches_a_connector() -> None:
    ex, edr, _, ledger = _setup()
    res = await ex.execute(
        Action(tenant_id="t1", verb="format_disk", target="host-9"), case_id="c1"
    )
    assert res.status == "denied"
    assert len(edr.action_log) == 0
    # a disposition was still recorded (no action bypasses the gate)
    actions = [e.action for e in ledger.replay("t1", case_id="c1")]
    assert any("guardian.disposition:format_disk:deny" in a for a in actions)


async def test_irreversible_action_is_gated() -> None:
    ex, edr, _, _ = _setup()
    res = await ex.execute(
        Action(tenant_id="t1", verb="kill_process", target="pid-123", reversible=False),
        case_id="c1",
    )
    assert res.status == "pending_approval"
    assert len(edr.action_log) == 0


async def test_approval_denial_blocks_execution() -> None:
    ex, edr, inv, _ = _setup()
    inv.upsert(
        AssetRecord(tenant_id="t1", name="dc01", identifiers=["dc01"], criticality="crown_jewel")
    )
    res = await ex.execute(Action(tenant_id="t1", verb="isolate_host", target="dc01"), case_id="c1")
    denied = await ex.deny(res.approval_id, "carol")
    assert denied.status == "denied"
    assert "dc01" not in edr.isolated_hosts
