"""S0: the tenant-aware data model holds its invariants."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from blue_kakapo.schema import (
    Action,
    Alert,
    AssetRecord,
    Case,
    CaseState,
    Event,
    Evidence,
    LedgerEntry,
    MemoryRecord,
    MemoryTrustTier,
    RoutingDisposition,
    Severity,
    Verdict,
    VerdictClass,
    new_id,
    new_ulid,
)


def test_ids_are_prefixed_and_sortable() -> None:
    a = new_id("case")
    b = new_id("case")
    assert a.startswith("case_") and b.startswith("case_")
    # ULIDs are time-ordered at millisecond granularity: the 10-char time prefix
    # (after the 5-char "case_") is non-decreasing. (We don't add intra-ms monotonicity.)
    assert a[:15] <= b[:15]
    assert len(new_ulid()) == 26


def test_tenant_scoped_models_require_tenant_id() -> None:
    # Every core object must carry a tenant boundary (threaded from S1).
    with pytest.raises(ValidationError):
        Event(source="test")  # missing tenant_id
    ev = Event(tenant_id="t1", source="test")
    assert ev.tenant_id == "t1"
    assert ev.type_uid == ev.class_uid * 100 + ev.activity_id


def test_case_defaults_and_lifecycle() -> None:
    c = Case(tenant_id="t1", title="suspicious login")
    assert c.state == CaseState.NEW
    assert c.memory_enabled is False  # opt-in per case
    assert c.cost.usd == 0.0
    ev = Evidence(tenant_id="t1", source="mock", summary="ip is on a blocklist")
    c.add_evidence(ev)
    assert len(c.evidence) == 1


def test_verdict_class_distinct_from_routing() -> None:
    v = Verdict(
        verdict_class=VerdictClass.FALSE_POSITIVE,
        routing=RoutingDisposition.AUTO_CLOSE,
        confidence=0.9,
    )
    assert v.verdict_class == "false_positive"
    assert v.routing == "auto_close"
    with pytest.raises(ValidationError):
        Verdict(
            verdict_class=VerdictClass.BENIGN, routing=RoutingDisposition.ESCALATE, confidence=1.5
        )


def test_severity_mapping() -> None:
    alert = Alert(tenant_id="t1", title="x", source="mock", severity=Severity.HIGH)
    assert alert.severity == Severity.HIGH
    ev = Event(tenant_id="t1", source="mock", severity=Severity.HIGH)
    assert ev.severity_id == 4


def test_memory_record_defaults_to_quarantined() -> None:
    m = MemoryRecord(tenant_id="t1", case_summary="past case")
    assert (
        m.trust_tier == MemoryTrustTier.QUARANTINED
    )  # agent-authored memory not usable until promoted


def test_action_and_asset_models() -> None:
    act = Action(tenant_id="t1", verb="isolate_host", target="host-1")
    assert act.reversible is True and act.idempotency_key
    asset = AssetRecord(tenant_id="t1", name="dc01", criticality="crown_jewel")
    assert asset.criticality == "crown_jewel"


def test_ledger_entry_shape() -> None:
    e = LedgerEntry(tenant_id="t1", seq=0, prev_hash="0" * 64, action="node.enter:L1")
    assert e.seq == 0 and e.hash == ""  # hash filled by the ledger engine (S1)
