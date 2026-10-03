"""SQL/DB-backed memory — the non-local option (Postgres in production, SQLite in dev/tests).

Case vectors + metadata live in the ``memory`` table. Dense retrieval filters by metadata in SQL and
scores candidates by cosine in Python, which is portable across SQLite and Postgres. On a Postgres
deployment this can be accelerated with a pgvector/HNSW index as a deploy-time optimization; the
retrieval contract (and everything above it) is unchanged.
"""

from __future__ import annotations

from ..core.store import Store
from ..schema.models import MemoryRecord
from .base import ScoredRecord, cosine


class SqlMemoryBackend:
    name = "pgvector"  # the config slot; uses Postgres in prod, SQLite in dev

    def __init__(self, store: Store) -> None:
        self.store = store

    async def upsert(self, record: MemoryRecord) -> None:
        self.store.upsert_memory(
            {
                "id": record.id,
                "tenant_id": record.tenant_id,
                "trust_tier": record.trust_tier,
                "technique": (record.metadata.get("technique") or None),
                "severity": (record.metadata.get("severity") or None),
                "outcome": (record.metadata.get("outcome") or None),
                "embedding": record.embedding,
                "data": record.model_dump(mode="json"),
            }
        )

    async def search(
        self,
        *,
        tenant_id: str,
        embedding: list[float],
        k: int = 20,
        metadata_filters: dict[str, str] | None = None,
    ) -> list[ScoredRecord]:
        rows = self.store.query_memory(tenant_id, filters=metadata_filters)
        scored = [
            ScoredRecord(MemoryRecord.model_validate(r["data"]), cosine(embedding, r["embedding"]))
            for r in rows
        ]
        scored.sort(key=lambda s: s.score, reverse=True)
        return scored[:k]

    async def get(self, tenant_id: str, record_id: str) -> MemoryRecord | None:
        row = self.store.get_memory(record_id)
        if not row or row["tenant_id"] != tenant_id:
            return None
        return MemoryRecord.model_validate(row["data"])

    async def all(self, tenant_id: str) -> list[MemoryRecord]:
        return [MemoryRecord.model_validate(r["data"]) for r in self.store.query_memory(tenant_id)]

    async def count(self, tenant_id: str) -> int:
        return len(self.store.query_memory(tenant_id))
