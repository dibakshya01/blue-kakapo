"""PII protection at ingest, and GDPR erasure of a stored case.

The leak this closes: a raw alert payload carries arbitrary free-text PII (SSNs, notes, emails) that
has no normalized home, and persisting the ``Case`` verbatim would write all of it into
``cases.data`` in the clear. So at ingest we **tokenize every raw payload** — encrypt it under a
per-record key via :class:`~blue_kakapo.core.crypto.CryptoShredder` and replace it in the model with
an opaque ``{_pii_ref: token}`` reference. The case at rest then holds a token, not the raw PII; the
plaintext lives only as AES-256-GCM ciphertext, erasable by destroying its key.

Normalized **observables** we deliberately extract (usernames, emails) stay in the clear because
triage, correlation, and entity resolution reason over them — but they are flagged ``contains_pii``
and :func:`erase_case_pii` redacts them (and resolved PII entities) on a subject-erasure request,
alongside crypto-shredding the raw blobs. The hash-chained ledger stores no PII (only action strings
and refs), so it keeps verifying after an erasure. See ``docs/gdpr-erasure.md``.
"""

from __future__ import annotations

import json

from ..schema.models import Case
from ..schema.ocsf import ObservableType
from .crypto import CryptoShredder

PII_REF_KEY = "_pii_ref"
REDACTED = "[erased]"
_PII_OBSERVABLE_TYPES = {ObservableType.USER, ObservableType.EMAIL}


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
    """Subject-erasure: crypto-shred raw blobs and redact PII-flagged observables/entities in place.

    Returns a small report ``{blobs_shredded, observables_redacted, entities_redacted}``. The ledger
    is untouched (it carries no PII) and continues to verify. Idempotent.
    """
    shredded = redacted_obs = redacted_ent = 0

    def shred(raw: object) -> None:
        nonlocal shredded
        if (
            isinstance(raw, dict)
            and set(raw.keys()) == {PII_REF_KEY}
            and shredder.erase(raw[PII_REF_KEY])
        ):
            shredded += 1

    for alert in case.alerts:
        shred(alert.raw)
        for event in alert.events:
            shred(event.raw)
            for obs in event.observables:
                if obs.contains_pii and obs.value != REDACTED:
                    obs.value = REDACTED
                    redacted_obs += 1

    for ent in case.entities:
        if ent.type in _PII_OBSERVABLE_TYPES and ent.value != REDACTED:
            ent.value = REDACTED
            ent.identifiers = [REDACTED for _ in ent.identifiers]
            redacted_ent += 1

    return {
        "blobs_shredded": shredded,
        "observables_redacted": redacted_obs,
        "entities_redacted": redacted_ent,
    }
