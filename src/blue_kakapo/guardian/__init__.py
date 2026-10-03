"""blue-kakapo Guardian — the ACS safety gate: policy engine, approvals, injection + Rule-of-Two."""

from __future__ import annotations

from .guardian import ApprovalRequest, ExecutionResult, GuardedExecutor, Guardian
from .injection import (
    as_untrusted,
    contains_injection,
    contains_unsafe_output,
    rule_of_two_ok,
    scan_injection,
)
from .policy import (
    CONTAINMENT_VERBS,
    DEFAULT_POLICIES,
    HIGH_IMPACT_VERBS,
    IRREVERSIBLE_VERBS,
    DecisionInput,
    PolicyEngine,
)

__all__ = [
    "Guardian",
    "GuardedExecutor",
    "ExecutionResult",
    "ApprovalRequest",
    "PolicyEngine",
    "DecisionInput",
    "DEFAULT_POLICIES",
    "HIGH_IMPACT_VERBS",
    "IRREVERSIBLE_VERBS",
    "CONTAINMENT_VERBS",
    "scan_injection",
    "contains_injection",
    "contains_unsafe_output",
    "as_untrusted",
    "rule_of_two_ok",
]
