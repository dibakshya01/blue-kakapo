"""The case ledger: append-only, hash-chained, replayable.

Every meaningful event (node entry/exit, tool call, model call, agent decision, human action, gated
action) becomes a ``LedgerEntry`` whose ``hash`` chains over the previous entry's hash plus this
entry's canonical content. Because PII is referenced by token (never inlined — see crypto.py), the
chain verifies even after an erasure. Replay reconstructs the decision path from the chain.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from ..schema.ledger import LedgerEntry, ModelRef
from .store import Store

GENESIS_HASH = "0" * 64


def _canonical(entry: LedgerEntry) -> str:
    """Deterministic JSON of the entry, excluding the ``hash`` field itself."""
    payload = entry.model_dump(mode="json", exclude={"hash"})
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_hash(prev_hash: str, entry: LedgerEntry) -> str:
    h = hashlib.sha256()
    h.update(prev_hash.encode("utf-8"))
    h.update(_canonical(entry).encode("utf-8"))
    return h.hexdigest()


class Ledger:
    """Append/verify/replay over the hash-chained ledger."""

    def __init__(self, store: Store) -> None:
        self.store = store

    def append(
        self,
        *,
        tenant_id: str,
        action: str,
        actor: str = "system",
        actor_id: str | None = None,
        case_id: str | None = None,
        run_id: str | None = None,
        inputs_ref: str | None = None,
        outputs_ref: str | None = None,
        model: ModelRef | None = None,
        disposition: str | None = None,
        trace_id: str | None = None,
    ) -> LedgerEntry:
        """Build, chain, and persist a ledger entry. Returns the stored entry (with ``hash`` set)."""
        seq = self.store.next_seq(tenant_id)
        prev = self.store.last_hash(tenant_id)
        entry = LedgerEntry(
            tenant_id=tenant_id,
            seq=seq,
            prev_hash=prev,
            action=action,
            actor=actor,
            actor_id=actor_id,
            case_id=case_id,
            run_id=run_id,
            inputs_ref=inputs_ref,
            outputs_ref=outputs_ref,
            model=model,
            disposition=disposition,
            trace_id=trace_id,
        )
        entry.hash = compute_hash(prev, entry)
        self.store.append_ledger(
            {
                "id": entry.id,
                "tenant_id": entry.tenant_id,
                "seq": entry.seq,
                "prev_hash": entry.prev_hash,
                "hash": entry.hash,
                "case_id": entry.case_id,
                "run_id": entry.run_id,
                "action": entry.action,
                "ts": entry.ts,
                "data": entry.model_dump(mode="json"),
            }
        )
        return entry

    def _row_to_entry(self, row: dict[str, Any]) -> LedgerEntry:
        return LedgerEntry.model_validate(row["data"])

    def replay(
        self, tenant_id: str, *, case_id: str | None = None, run_id: str | None = None
    ) -> list[LedgerEntry]:
        """Return the entries for a case/run in order — the reconstructable decision path."""
        rows = self.store.read_ledger(tenant_id, case_id=case_id, run_id=run_id)
        return [self._row_to_entry(r) for r in rows]

    def verify(self, tenant_id: str) -> bool:
        """Recompute the whole chain for a tenant; return True iff every link is intact."""
        rows = self.store.read_ledger(tenant_id)
        prev = GENESIS_HASH
        for expected_seq, row in enumerate(rows):
            entry = self._row_to_entry(row)
            if entry.seq != expected_seq:
                return False
            if entry.prev_hash != prev:
                return False
            if compute_hash(prev, entry) != entry.hash:
                return False
            prev = entry.hash
        return True
