"""Regulatory incident-reporting clocks (DORA / NIS2 / GDPR / SEC).

All clocks start at *awareness* (case creation), not at end-of-investigation — which is exactly why
fast triage reduces legal exposure (see finding.md §1). This computes the deadlines a qualifying case
is subject to so the MGR agent can flag them. **Aid, not legal advice** (see honest limits).
"""

from __future__ import annotations

import datetime as _dt

from .schema.common import VerdictClass
from .schema.models import Case, RegulatoryClock

# framework -> list of (label, hours-from-awareness)
_FRAMEWORKS: dict[str, list[tuple[str, float]]] = {
    "DORA": [("initial notification", 4.0), ("intermediate report", 24.0)],
    "NIS2": [("early warning", 24.0), ("incident notification", 72.0)],
    "GDPR": [("supervisory-authority notification", 72.0)],
    "SEC": [("Form 8-K (material)", 4 * 24.0)],  # 4 business days (approx. as hours)
}

_REPORTABLE = {VerdictClass.MALICIOUS, VerdictClass.SUSPICIOUS}


def clocks_for_case(
    case: Case, frameworks: list[str] | None = None, *, now: _dt.datetime | None = None
) -> list[RegulatoryClock]:
    """Return the regulatory clocks a (reportable) case is subject to."""
    if case.verdict is None or case.verdict.verdict_class not in _REPORTABLE:
        return []
    start = now or case.created_at
    selected = frameworks or list(_FRAMEWORKS)
    out: list[RegulatoryClock] = []
    for fw in selected:
        for label, hours in _FRAMEWORKS.get(fw, []):
            out.append(
                RegulatoryClock(
                    framework=fw,
                    label=label,
                    started_at=start,
                    deadline_at=start + _dt.timedelta(hours=hours),
                    status="open",
                )
            )
    return out


def soonest_deadline(clocks: list[RegulatoryClock]) -> RegulatoryClock | None:
    return min(clocks, key=lambda c: c.deadline_at) if clocks else None
