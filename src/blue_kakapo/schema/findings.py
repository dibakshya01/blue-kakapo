"""Typed, schema-validated agent outputs ("findings").

Every roster agent returns a structured finding (not a loose dict), so its output is contract-checked,
renderable, and auditable — the same discipline as L1's ``Verdict``. Agents attach the finding to
``AgentOutput.metadata["finding"]`` (JSON) alongside evidence. Confidence/risk fields are the agent's
own estimate; only the triage **Verdict** is calibrated by the eval harness (see docs/eval.md).
"""

from __future__ import annotations

from pydantic import Field

from .common import BKModel


class WatchSignal(BKModel):
    """WATCH — early warning over the recent case stream."""

    sources_scanned: int = 0
    cases_considered: int = 0
    burst_source: str | None = None
    burst_count: int = 0
    shared_indicators: list[str] = Field(default_factory=list)
    likely_campaign: bool = False
    assessment: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class HuntPlan(BKModel):
    """HUNT — a hypothesis-driven hunt and its result."""

    hypothesis: str = ""
    query: str = ""
    hits: int = 0
    techniques: list[str] = Field(default_factory=list)
    next_pivot: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class DetectionGapReport(BKModel):
    """DET — detection coverage gaps + proposed (never auto-deployed) Sigma."""

    techniques_seen: list[str] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)
    priority_gap: str | None = None
    proposed_sigma: dict[str, str] = Field(default_factory=dict)
    rationale: str = ""


class ExposureItem(BKModel):
    cve: str
    cvss: float = 0.0
    kev: bool = False
    technique: str | None = None
    asset: str | None = None
    score: float = 0.0


class ExposureReport(BKModel):
    """VULN — KEV/CVSS × asset × active-threat exposure prioritization."""

    items: list[ExposureItem] = Field(default_factory=list)
    top_cve: str | None = None
    remediation: str = ""


class InsiderSignal(BKModel):
    """INSIDER — privacy-gated, aggregate behavioral signal (no raw user activity)."""

    users_observed: int = 0
    off_hours_events: int = 0
    high_severity: bool = False
    risk_level: str = Field(default="low", description="low | elevated | high")
    rationale: str = ""
    privacy: str = "aggregate-only"


class CommsBrief(BKModel):
    """COMMS — analyst-facing summary + a drafted (never auto-sent) external message."""

    headline: str = ""
    summary: str = ""
    external_draft: str = ""


class IncidentReport(BKModel):
    """RPT — an incident/compliance report built from the case."""

    report_markdown: str = ""
    executive_summary: str = ""
    clock_count: int = 0
    cost_usd: float = 0.0


class PipelineHealth(BKModel):
    """MAINT — connector/pipeline health."""

    checked: int = 0
    unhealthy: int = 0
    issues: list[str] = Field(default_factory=list)
    impact: str = ""
    recommended_action: str = ""


class ShiftStatus(BKModel):
    """MGR — shift prioritization + regulatory-clock status."""

    clock_count: int = 0
    soonest: str | None = None
    priority: str = Field(default="normal", description="low | normal | high | urgent")
    next_step: str = ""
    rationale: str = ""
