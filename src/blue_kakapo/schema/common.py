"""Common types, enums, and helpers shared across every data model.

Design rules enforced here:
- Every domain object is **tenant-scoped** (carries ``tenant_id``) from the first commit.
- Timestamps are timezone-aware UTC.
- IDs are time-sortable (ULID-style) with a type prefix, so logs and ledgers sort chronologically.
"""

from __future__ import annotations

import datetime as _dt
import os
import secrets
import time

from pydantic import BaseModel, ConfigDict, Field

# --- Crockford base32 ULID-style id generation (no external dependency) ---

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _encode_base32(value: int, length: int) -> str:
    chars = []
    for _ in range(length):
        chars.append(_CROCKFORD[value & 0x1F])
        value >>= 5
    return "".join(reversed(chars))


def new_ulid() -> str:
    """Return a 26-char Crockford-base32 ULID (48-bit time + 80-bit randomness)."""
    ms = int(time.time() * 1000)
    rand = int.from_bytes(os.urandom(10), "big")
    return _encode_base32(ms, 10) + _encode_base32(rand, 16)


def new_id(prefix: str) -> str:
    """Return a prefixed, time-sortable id, e.g. ``case_01J9Z...``."""
    return f"{prefix}_{new_ulid()}"


def utcnow() -> _dt.datetime:
    """Timezone-aware current UTC time."""
    return _dt.datetime.now(_dt.UTC)


def new_token(nbytes: int = 24) -> str:
    """A URL-safe random token (for resume tokens, idempotency keys, etc.)."""
    return secrets.token_urlsafe(nbytes)


# --- Enumerations (strings for stable serialization / JSON) ---


class Severity(str):
    """OCSF-aligned severity labels. Mapped to OCSF ``severity_id`` 0..6 via :data:`SEVERITY_ID`."""

    UNKNOWN = "unknown"
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    FATAL = "fatal"


SEVERITY_ID: dict[str, int] = {
    Severity.UNKNOWN: 0,
    Severity.INFORMATIONAL: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
    Severity.FATAL: 6,
}

SEVERITY_RANK: dict[str, int] = {
    Severity.UNKNOWN: 0,
    Severity.INFORMATIONAL: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
    Severity.FATAL: 6,
}


class VerdictClass:
    """What a triage verdict *is* — kept distinct from the routing disposition."""

    BENIGN = "benign"
    FALSE_POSITIVE = "false_positive"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    INCONCLUSIVE = "inconclusive"


class RoutingDisposition:
    """What happens *next* with a case — distinct from the verdict class."""

    AUTO_CLOSE = "auto_close"
    ESCALATE = "escalate"
    AWAIT_APPROVAL = "await_approval"


class CaseState:
    """Lifecycle states driven by the orchestration kernel."""

    NEW = "new"
    TRIAGING = "triaging"
    INVESTIGATING = "investigating"
    AWAITING_APPROVAL = "awaiting_approval"
    RESPONDING = "responding"
    RESOLVED = "resolved"
    ESCALATED = "escalated"
    CLOSED = "closed"


class AutonomyLevel:
    """How much an agent is allowed to do on its own."""

    READ_ONLY = "read_only"
    PROPOSE = "propose"
    ACT_ON_APPROVAL = "act_on_approval"
    SYSTEM = "system"


class ACSDisposition:
    """Agent Control Standard dispositions returned by the Guardian. Default is ``ask`` (never fail-open)."""

    ALLOW = "allow"
    DENY = "deny"
    MODIFY = "modify"
    ASK = "ask"
    DEFER = "defer"


class AssetCriticality:
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"
    CROWN_JEWEL = "crown_jewel"


CRITICALITY_RANK: dict[str, int] = {
    AssetCriticality.LOW: 0,
    AssetCriticality.NORMAL: 1,
    AssetCriticality.HIGH: 2,
    AssetCriticality.CRITICAL: 3,
    AssetCriticality.CROWN_JEWEL: 4,
}


class MemoryTrustTier:
    """Provenance trust tiers. Agent-authored memories are quarantined until promoted."""

    QUARANTINED = "quarantined"  # agent-authored, not yet usable for decisioning
    AGENT = "agent"
    REVIEWED = "reviewed"  # a human has reviewed it
    AUTHORITATIVE = "authoritative"  # runbook / curated


class BKModel(BaseModel):
    """Base model: strict, JSON-friendly, forbids unknown fields unless a subclass opts out."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True, use_enum_values=True)


class TenantScoped(BKModel):
    """Base for every object that belongs to a tenant."""

    tenant_id: str = Field(..., description="Owning tenant; isolation boundary for all access.")
