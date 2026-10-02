"""Core domain models: Alert, Entity, Evidence, Verdict, Case, Asset, Memory, AgBOM.

All are tenant-scoped. The ``Case`` is the central unit of work the orchestration kernel drives
through its lifecycle; every meaningful change is also recorded in the append-only ledger.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any

from pydantic import Field

from .common import (
    AutonomyLevel,
    BKModel,
    CaseState,
    MemoryTrustTier,
    Severity,
    TenantScoped,
    new_id,
    utcnow,
)
from .ocsf import Event


class Alert(TenantScoped):
    """One or more normalized events plus detection context."""

    id: str = Field(default_factory=lambda: new_id("alert"))
    title: str
    source: str = Field(..., description="Connector/source that raised the alert.")
    severity: str = Field(default=Severity.MEDIUM)
    rule_id: str | None = None
    rule_name: str | None = None
    attack_techniques: list[str] = Field(
        default_factory=list, description="MITRE ATT&CK technique IDs."
    )
    dedup_key: str | None = Field(
        default=None, description="Stable key for deduplication/grouping."
    )
    events: list[Event] = Field(default_factory=list)
    first_seen: _dt.datetime = Field(default_factory=utcnow)
    last_seen: _dt.datetime = Field(default_factory=utcnow)
    raw: dict[str, Any] = Field(default_factory=dict)


class Entity(BKModel):
    """A resolved actor/asset referenced by a case (host, user, ip, ...)."""

    type: str = Field(..., description="host | user | ip | domain | file | process | ...")
    value: str
    identifiers: list[str] = Field(
        default_factory=list, description="All aliases seen (FQDN, IP, SID...)."
    )
    asset_id: str | None = Field(default=None, description="Linked AssetRecord id, if resolved.")
    resolution_confidence: float = Field(default=1.0, ge=0.0, le=1.0)


class Evidence(TenantScoped):
    """A single cited fact gathered during triage/investigation."""

    id: str = Field(default_factory=lambda: new_id("ev"))
    source: str = Field(..., description="Connector/tool that produced this evidence.")
    connector: str | None = None
    query: str | None = Field(
        default=None, description="The query/lookup that produced it, if any."
    )
    summary: str = Field(..., description="Human-readable statement of the fact.")
    supports: str | None = Field(default=None, description="Which claim/verdict this supports.")
    result_ref: str | None = Field(
        default=None, description="Pointer to stored raw result (may be tokenized)."
    )
    collected_at: _dt.datetime = Field(default_factory=utcnow)


class CostAccounting(BKModel):
    """Per-case resource accounting, so 'predictable cost' is measured, not claimed."""

    tokens_in: int = 0
    tokens_out: int = 0
    usd: float = 0.0
    model_calls: int = 0

    def add(self, tokens_in: int, tokens_out: int, usd: float) -> None:
        self.tokens_in += tokens_in
        self.tokens_out += tokens_out
        self.usd += usd
        self.model_calls += 1


class Verdict(BKModel):
    """A triage verdict: the class (what it *is*) + routing disposition (what happens next)."""

    verdict_class: str = Field(..., description="One of VerdictClass.*")
    routing: str = Field(..., description="One of RoutingDisposition.*")
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Calibration is *measured* by the eval harness."
    )
    rationale: str = Field(default="")
    evidence_ids: list[str] = Field(default_factory=list)
    attack_techniques: list[str] = Field(default_factory=list)
    produced_by: str = Field(default="L1", description="Agent that produced the verdict.")
    model_id: str | None = None
    created_at: _dt.datetime = Field(default_factory=utcnow)


class RegulatoryClock(BKModel):
    """A compliance deadline tracked per qualifying case (DORA/NIS2/GDPR/SEC)."""

    framework: str = Field(..., description="DORA | NIS2 | GDPR | SEC | ...")
    label: str = Field(..., description="e.g. 'initial notification'")
    started_at: _dt.datetime = Field(default_factory=utcnow)
    deadline_at: _dt.datetime
    status: str = Field(default="open", description="open | met | breached | n/a")


class Case(TenantScoped):
    """The central unit of work; the kernel drives it through CaseState."""

    id: str = Field(default_factory=lambda: new_id("case"))
    title: str
    state: str = Field(default=CaseState.NEW)
    severity: str = Field(default=Severity.MEDIUM)
    alerts: list[Alert] = Field(default_factory=list)
    entities: list[Entity] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    verdict: Verdict | None = None
    attack_techniques: list[str] = Field(default_factory=list)
    regulatory_clocks: list[RegulatoryClock] = Field(default_factory=list)
    assignee: str | None = None
    memory_enabled: bool = Field(default=False, description="Opt-in: consult/write case memory.")
    cost: CostAccounting = Field(default_factory=CostAccounting)
    created_at: _dt.datetime = Field(default_factory=utcnow)
    updated_at: _dt.datetime = Field(default_factory=utcnow)

    def add_evidence(self, ev: Evidence) -> None:
        self.evidence.append(ev)
        self.updated_at = utcnow()


class AssetRecord(TenantScoped):
    """An inventory asset; drives Guardian blast-radius rules and VULN prioritization."""

    id: str = Field(default_factory=lambda: new_id("asset"))
    name: str
    identifiers: list[str] = Field(
        default_factory=list, description="hostname/FQDN/IP/MAC/asset-tag/UPN/SID"
    )
    criticality: str = Field(default="normal", description="One of AssetCriticality.*")
    tags: list[str] = Field(default_factory=list)
    owner: str | None = None
    source: str = Field(default="manual")


class MemoryRecord(TenantScoped):
    """A compacted past case stored for recall; carries provenance, trust tier, and embedding version."""

    id: str = Field(default_factory=lambda: new_id("mem"))
    case_id: str | None = None
    case_summary: str
    features: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="technique/asset/severity/outcome"
    )
    embedding: list[float] = Field(default_factory=list)
    embedding_model: str = Field(default="")
    embedding_version: str = Field(default="")
    provenance: str = Field(default="agent", description="Who authored this memory.")
    trust_tier: str = Field(default=MemoryTrustTier.QUARANTINED)
    decay: float = Field(
        default=1.0, ge=0.0, le=1.0, description="Aging weight applied at retrieval."
    )
    created_at: _dt.datetime = Field(default_factory=utcnow)


class AgBOM(BKModel):
    """Agent Bill of Materials: the capabilities and reach of a single agent."""

    agent: str
    autonomy_level: str = Field(default=AutonomyLevel.PROPOSE)
    tools: list[str] = Field(default_factory=list)
    models: list[str] = Field(default_factory=list)
    connectors: list[str] = Field(default_factory=list)
    data_scopes: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
