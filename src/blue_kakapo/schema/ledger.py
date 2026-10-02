"""Ledger-entry and model-reference data models, plus the PII-token model for crypto-shredding.

The hash-chaining *engine* (verification, replay) lives in ``blue_kakapo.core.ledger`` (S1). Here we
define only the serializable shapes. A crucial rule enforced downstream: all retained hashes/digests
are computed over **ciphertext or tokenized refs**, never over raw PII plaintext, so surviving hashes
are not brute-forceable after an erasure (crypto-shred).
"""

from __future__ import annotations

import datetime as _dt

from pydantic import Field

from .common import BKModel, TenantScoped, new_id, utcnow


class ModelRef(BKModel):
    """What model produced an output, for reproducibility and cost accounting."""

    id: str = Field(
        ..., description="Model id, e.g. 'claude-...' / 'qwen3:8b' / 'offline-deterministic'."
    )
    digest: str | None = Field(default=None, description="Weight/version digest where available.")
    params: dict[str, float] = Field(default_factory=dict, description="temperature, seed, ...")
    tokens_in: int = 0
    tokens_out: int = 0
    usd: float = 0.0


class LedgerActor:
    AGENT = "agent"
    HUMAN = "human"
    SYSTEM = "system"


class LedgerEntry(TenantScoped):
    """One append-only, hash-chained record. ``hash`` chains over ``prev_hash`` + canonical content."""

    id: str = Field(default_factory=lambda: new_id("led"))
    seq: int = Field(..., ge=0, description="Monotonic per-(tenant) sequence number.")
    prev_hash: str = Field(..., description="Hash of the previous entry (genesis = 64 zeros).")
    hash: str = Field(
        default="", description="Computed hash of this entry; filled by the ledger engine."
    )

    run_id: str | None = None
    case_id: str | None = None
    actor: str = Field(default=LedgerActor.SYSTEM, description="agent | human | system")
    actor_id: str | None = None
    action: str = Field(
        ..., description="What happened, e.g. 'node.enter:L1' or 'tool.call:isolate_host'."
    )

    # Refs point at stored (possibly crypto-shredded/tokenized) blobs — never inline PII.
    inputs_ref: str | None = None
    outputs_ref: str | None = None

    model: ModelRef | None = None
    disposition: str | None = Field(
        default=None, description="ACS disposition if this was a gated action."
    )
    trace_id: str | None = None
    ts: _dt.datetime = Field(default_factory=utcnow)


class PiiToken(TenantScoped):
    """Maps a token/ref to a per-record encryption key. Destroy the key to crypto-shred (GDPR erasure)."""

    token: str = Field(default_factory=lambda: new_id("pii"))
    key_ref: str = Field(
        ..., description="Where the per-record key lives (OpenBao path / keystore id)."
    )
    algorithm: str = Field(default="aes-256-gcm")
    created_at: _dt.datetime = Field(default_factory=utcnow)
    erased_at: _dt.datetime | None = Field(
        default=None, description="Set when the key is destroyed."
    )

    @property
    def is_erased(self) -> bool:
        return self.erased_at is not None
