"""OCSF-based normalized event model (targets OCSF 1.9).

We normalize heterogeneous telemetry onto a compact, security-relevant subset of OCSF while
**retaining the raw original**. The goal is source-independent reasoning, not a full OCSF
implementation — connectors map their events here, and the ``raw`` payload is preserved for replay
and for anything the normalized view drops. See https://schema.ocsf.io (OCSF 1.9).
"""

from __future__ import annotations

import datetime as _dt
from typing import Any

from pydantic import Field

from .common import SEVERITY_ID, BKModel, Severity, TenantScoped, new_id, utcnow

# A minimal registry of OCSF categories/classes we care about for triage. Not exhaustive.
OCSF_CATEGORIES: dict[int, str] = {
    1: "System Activity",
    2: "Findings",
    3: "Identity & Access Management",
    4: "Network Activity",
    5: "Discovery",
    6: "Application Activity",
    7: "Remediation",
    8: "Unmanned Systems",
}

# Common class_uids used by triage sources.
OCSF_CLASSES: dict[int, str] = {
    1001: "File System Activity",
    1007: "Process Activity",
    2004: "Detection Finding",
    3002: "Authentication",
    4001: "Network Activity",
    4002: "HTTP Activity",
    4003: "DNS Activity",
}


class ObservableType:
    """Normalized observable kinds we extract for enrichment and entity resolution."""

    IP = "ip"
    HOSTNAME = "hostname"
    FQDN = "fqdn"
    MAC = "mac"
    USER = "user"
    EMAIL = "email"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    FILE_PATH = "file_path"
    PROCESS = "process"
    REGISTRY_KEY = "registry_key"
    ASSET_TAG = "asset_tag"


class Observable(BKModel):
    """A single extracted observable, e.g. an IP, a username, a file hash."""

    type: str = Field(..., description="One of ObservableType.*")
    value: str
    contains_pii: bool = Field(
        default=False,
        description="Hint for storage: tokenize/crypto-shred this value (users, emails, some IPs).",
    )


class Event(TenantScoped):
    """A normalized OCSF-style security event. ``raw`` keeps the untouched source payload."""

    id: str = Field(default_factory=lambda: new_id("evt"))

    # --- OCSF core ---
    category_uid: int = Field(default=2, description="OCSF category (2 = Findings by default).")
    class_uid: int = Field(default=2004, description="OCSF class (2004 = Detection Finding).")
    activity_id: int = Field(default=1)
    severity: str = Field(default=Severity.UNKNOWN)
    time: _dt.datetime = Field(default_factory=utcnow, description="Event time (UTC).")
    ingest_time: _dt.datetime = Field(
        default_factory=utcnow, description="When we received it (UTC)."
    )

    # --- provenance ---
    source: str = Field(..., description="Logical source/connector that produced this event.")
    product: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    # --- content ---
    message: str = Field(default="", description="Human-readable summary of the event.")
    observables: list[Observable] = Field(default_factory=list)
    unmapped: dict[str, Any] = Field(default_factory=dict, description="Fields with no OCSF home.")
    raw: dict[str, Any] = Field(default_factory=dict, description="Untouched original payload.")

    @property
    def type_uid(self) -> int:
        """OCSF ``type_uid`` = class_uid * 100 + activity_id."""
        return self.class_uid * 100 + self.activity_id

    @property
    def severity_id(self) -> int:
        return SEVERITY_ID.get(self.severity, 0)

    @property
    def category_name(self) -> str:
        return OCSF_CATEGORIES.get(self.category_uid, "Unknown")

    @property
    def class_name(self) -> str:
        return OCSF_CLASSES.get(self.class_uid, "Unknown")

    def observable_values(self, kind: str) -> list[str]:
        return [o.value for o in self.observables if o.type == kind]
