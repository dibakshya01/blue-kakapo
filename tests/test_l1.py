"""S2: L1 deterministic triage — evidence-cited, conservative (escalate on uncertainty)."""

from __future__ import annotations

from blue_kakapo.agents.l1 import deterministic_triage
from blue_kakapo.normalize import normalize_alert
from blue_kakapo.schema.common import RoutingDisposition, VerdictClass
from blue_kakapo.schema.models import Case


def _case(raw: dict) -> Case:
    alert = normalize_alert(raw, tenant_id="t1")
    return Case(tenant_id="t1", title=alert.title, severity=alert.severity, alerts=[alert])


def test_known_bad_indicator_is_malicious_and_escalates() -> None:
    verdict, evidence = deterministic_triage(
        _case({"title": "beacon", "severity": "high", "dst_ip": "198.51.100.23"})
    )
    assert verdict.verdict_class == VerdictClass.MALICIOUS
    assert verdict.routing == RoutingDisposition.ESCALATE
    assert verdict.confidence >= 0.7
    assert verdict.evidence_ids and len(verdict.evidence_ids) == len(evidence)
    assert any(e.supports == "malicious" for e in evidence)  # cited evidence


def test_benign_low_severity_auto_closes_as_false_positive() -> None:
    verdict, _ = deterministic_triage(
        _case(
            {
                "title": "Scheduled backup login (test)",
                "severity": "low",
                "src_ip": "10.0.0.9",
                "domain": "internal.example",
            }
        )
    )
    assert verdict.verdict_class == VerdictClass.FALSE_POSITIVE
    assert verdict.routing == RoutingDisposition.AUTO_CLOSE


def test_suspicious_keyword_escalates() -> None:
    verdict, _ = deterministic_triage(
        _case({"title": "Possible ransomware activity", "severity": "medium"})
    )
    assert verdict.verdict_class == VerdictClass.SUSPICIOUS
    assert verdict.routing == RoutingDisposition.ESCALATE


def test_uncertain_defaults_to_escalation_never_autoclose() -> None:
    verdict, _ = deterministic_triage(_case({"title": "unlabeled event", "severity": "medium"}))
    assert verdict.routing != RoutingDisposition.AUTO_CLOSE  # bias: never auto-close on uncertainty


def test_offline_verdict_is_labeled_non_inferential() -> None:
    verdict, _ = deterministic_triage(_case({"title": "x", "severity": "low"}))
    assert verdict.model_id == "offline-deterministic"
