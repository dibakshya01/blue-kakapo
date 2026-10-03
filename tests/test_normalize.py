"""S2: the generic alert normalizer produces OCSF-aligned Alerts."""

from __future__ import annotations

from blue_kakapo.normalize import extract_observables, normalize_alert
from blue_kakapo.schema.common import Severity
from blue_kakapo.schema.ocsf import ObservableType


def test_normalize_extracts_core_fields() -> None:
    raw = {
        "title": "Suspicious login",
        "severity": "high",
        "rule_name": "Impossible travel",
        "src_ip": "198.51.100.23",
        "user": "jdoe",
        "attack_techniques": "T1078",
    }
    alert = normalize_alert(raw, tenant_id="t1", source="webhook")
    assert alert.tenant_id == "t1"
    assert alert.title == "Suspicious login"
    assert alert.severity == Severity.HIGH
    assert alert.rule_name == "Impossible travel"
    assert alert.attack_techniques == ["T1078"]
    assert len(alert.events) == 1
    assert alert.events[0].raw == raw  # raw retained


def test_observable_extraction_and_pii_flag() -> None:
    obs = extract_observables({"src_ip": "10.0.0.5", "user": "alice", "domain": "evil.test"})
    kinds = {o.type: o for o in obs}
    assert kinds[ObservableType.IP].value == "10.0.0.5"
    assert kinds[ObservableType.USER].value == "alice"
    assert kinds[ObservableType.USER].contains_pii is True  # users are PII -> tokenize downstream
    assert kinds[ObservableType.DOMAIN].value == "evil.test"


def test_hash_scan_and_severity_coercion() -> None:
    raw = {"message": "dropped file d41d8cd98f00b204e9800998ecf8427e", "priority": "2"}
    alert = normalize_alert(raw, tenant_id="t1")
    hashes = [o.value for o in alert.events[0].observables if o.type == ObservableType.FILE_HASH]
    assert "d41d8cd98f00b204e9800998ecf8427e" in hashes
    assert alert.severity == Severity.LOW  # numeric 2 -> low


def test_untitled_and_defaults() -> None:
    alert = normalize_alert({}, tenant_id="t1")
    assert alert.title == "Untitled alert"
    assert alert.severity == Severity.MEDIUM
