"""PII protection at ingest, and GDPR erasure of a stored case.

Two surfaces carry personal data in a case:

1. **Raw payloads** (``alert.raw`` / ``event.raw``) — the free-text bucket where arbitrary PII lands
   with no normalized home. These are **tokenized at ingest** (:func:`protect_case_pii`): encrypted
   under a per-record key via :class:`~blue_kakapo.core.crypto.CryptoShredder` and replaced in the
   model by an opaque ``{_pii_ref: token}`` reference, so the raw payload is never persisted in the
   clear — only AES-256-GCM ciphertext, erasable by destroying its key.
2. **Normalized free-text + observables** (``title`` / ``message`` / ``rule_name`` / evidence
   summaries / verdict rationale, and extracted USER/EMAIL observables + resolved entities) — these
   stay readable **while a case is live**, because triage, display, correlation, and entity
   resolution reason over them. They are **not** encrypted at rest; instead a subject-erasure
   (:func:`erase_case_pii`) redacts PII from all of them: flagged observables/entities, plus any
   email/SSN pattern and any of the case's own PII values found inside the free-text fields.

So the honest guarantee is: **raw payloads are never stored in the clear, and a subject-erasure
removes personal data from every field of the stored case** (while the PII-free, hash-chained ledger
keeps verifying). It is *not* a claim that operational fields are PII-free before an erasure is
requested. See ``docs/gdpr-erasure.md``.
"""

from __future__ import annotations

import json
import re

from ..schema.models import Case
from ..schema.ocsf import ObservableType
from .crypto import CryptoShredder

PII_REF_KEY = "_pii_ref"
REDACTED = "[erased]"
_PII_OBSERVABLE_TYPES = {ObservableType.USER, ObservableType.EMAIL}

# Structured PII that can appear anywhere in free text (titles, messages) with no observable alias.
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


def redact_pii_text(text: str | None, extra_values: set[str]) -> tuple[str | None, int]:
    """Redact emails, SSNs, and any of ``extra_values`` (the case's own PII) from free text.

    Returns ``(redacted_text, count)``. Conservative by design — it removes personal data while
    leaving the surrounding security narrative intact (e.g. ``"beacon from [erased]"``).
    """
    if not text:
        return text, 0
    out = text
    n = 0
    for rx in (_EMAIL_RE, _SSN_RE):
        out, c = rx.subn(REDACTED, out)
        n += c
    for val in sorted(extra_values, key=len, reverse=True):  # longest first, avoid partial overlaps
        if val and val != REDACTED and val in out:
            out = out.replace(val, REDACTED)
            n += 1
    return out, n


def _is_ref(raw: object) -> bool:
    return isinstance(raw, dict) and set(raw.keys()) == {PII_REF_KEY}


def _tokenize(raw: dict, *, tenant_id: str, shredder: CryptoShredder) -> dict:
    if not raw or _is_ref(raw):
        return raw
    token = shredder.protect(tenant_id, json.dumps(raw, default=str, sort_keys=True))
    return {PII_REF_KEY: token}


def protect_case_pii(case: Case, shredder: CryptoShredder) -> int:
    """Tokenize every raw payload in the case in place. Returns how many blobs were protected.

    Idempotent: a payload already replaced by a ``{_pii_ref: ...}`` reference is left untouched, so
    re-saving a case never re-encrypts (or leaks) it.
    """
    count = 0
    for alert in case.alerts:
        if alert.raw and not _is_ref(alert.raw):
            alert.raw = _tokenize(alert.raw, tenant_id=case.tenant_id, shredder=shredder)
            count += 1
        for event in alert.events:
            if event.raw and not _is_ref(event.raw):
                event.raw = _tokenize(event.raw, tenant_id=case.tenant_id, shredder=shredder)
                count += 1
    return count


def erase_case_pii(case: Case, shredder: CryptoShredder) -> dict[str, int]:
    """Subject-erasure: crypto-shred raw blobs and remove PII from **every** field of the case.

    Shreds the tokenized raw blobs, redacts PII-flagged observables + resolved PII entities, and
    scrubs emails/SSNs/the case's own PII values out of all free-text fields (title, alert titles,
    rule names, event messages, evidence summaries, verdict rationale). Returns a small report. The
    ledger is untouched (it carries no PII) and continues to verify. Idempotent.
    """
    shredded = redacted_obs = redacted_ent = redacted_text = 0

    def shred(raw: object) -> None:
        nonlocal shredded
        if (
            isinstance(raw, dict)
            and set(raw.keys()) == {PII_REF_KEY}
            and shredder.erase(raw[PII_REF_KEY])
        ):
            shredded += 1

    # Collect the case's own PII values first, so we can scrub them out of free text everywhere.
    pii_values: set[str] = set()
    for alert in case.alerts:
        for event in alert.events:
            for obs in event.observables:
                if obs.contains_pii and obs.value != REDACTED:
                    pii_values.add(obs.value)
    for ent in case.entities:
        if ent.type in _PII_OBSERVABLE_TYPES and ent.value != REDACTED:
            pii_values.add(ent.value)
            pii_values.update(i for i in ent.identifiers if i)

    def scrub(text: str | None) -> str | None:
        nonlocal redacted_text
        out, n = redact_pii_text(text, pii_values)
        redacted_text += n
        return out

    case.title = scrub(case.title) or REDACTED
    for alert in case.alerts:
        shred(alert.raw)
        alert.title = scrub(alert.title) or REDACTED
        alert.rule_name = scrub(alert.rule_name)
        for event in alert.events:
            shred(event.raw)
            event.message = scrub(event.message) or ""
            for obs in event.observables:
                if obs.contains_pii and obs.value != REDACTED:
                    obs.value = REDACTED
                    redacted_obs += 1

    for ev in case.evidence:
        ev.summary = scrub(ev.summary) or REDACTED
    if case.verdict is not None:
        case.verdict.rationale = scrub(case.verdict.rationale) or ""

    for ent in case.entities:
        if ent.type in _PII_OBSERVABLE_TYPES and ent.value != REDACTED:
            ent.value = REDACTED
            ent.identifiers = [REDACTED for _ in ent.identifiers]
            redacted_ent += 1

    return {
        "blobs_shredded": shredded,
        "observables_redacted": redacted_obs,
        "entities_redacted": redacted_ent,
        "text_fields_redacted": redacted_text,
    }
