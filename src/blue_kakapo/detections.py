"""Detection inventory + Sigma skeleton generation for the DET agent.

A small built-in inventory (rule → ATT&CK techniques) lets DET compute coverage gaps against a target
technique set and propose a Sigma rule skeleton for a gap. Real deployments load their own
detection-as-code repo; this is the offline/demo stand-in.
"""

from __future__ import annotations

from .schema.common import BKModel


class DetectionRule(BKModel):
    id: str
    name: str
    techniques: list[str] = []


_INVENTORY: list[DetectionRule] = [
    DetectionRule(id="rule-0001", name="Suspicious PowerShell", techniques=["T1059"]),
    DetectionRule(id="rule-0002", name="Brute force logon", techniques=["T1110"]),
    DetectionRule(id="rule-0003", name="C2 beacon pattern", techniques=["T1071"]),
    DetectionRule(id="rule-0004", name="Credential dumping", techniques=["T1003"]),
]


def detection_inventory() -> list[DetectionRule]:
    return list(_INVENTORY)


def coverage_gaps(
    target_techniques: list[str], inventory: list[DetectionRule] | None = None
) -> list[str]:
    """Techniques in the target set with no covering rule."""
    inv = inventory if inventory is not None else _INVENTORY
    covered = {t for rule in inv for t in rule.techniques}
    return [t for t in dict.fromkeys(target_techniques) if t not in covered]


def sigma_skeleton(technique: str, *, title: str | None = None) -> str:
    """A minimal, valid-shaped Sigma YAML skeleton for a coverage gap (for human review, not auto-deploy)."""
    return (
        f"title: {title or f'Detection for {technique} (DRAFT)'}\n"
        f"id: auto-{technique.lower()}\n"
        "status: experimental\n"
        f"description: Proposed by blue-kakapo DET to cover ATT&CK {technique}. Review before deploy.\n"
        "logsource:\n"
        "  product: windows\n"
        "  service: security\n"
        "detection:\n"
        "  selection:\n"
        "    EventID: 0  # TODO: define real selection criteria\n"
        "  condition: selection\n"
        "falsepositives:\n"
        "  - Unknown (tune before enabling)\n"
        "level: medium\n"
        f"tags:\n  - attack.{technique.lower()}\n"
    )
