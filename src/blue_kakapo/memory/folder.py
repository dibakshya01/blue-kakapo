"""Folder-backed memory — an embedded, file-based store for the UI-linked local folder.

Records live as JSON lines in ``<folder>/memory.jsonl``; search is an exact cosine scan (fine for the
single-node/localhost scale this backend targets). No server, no extra infrastructure — the user just
links a folder. For larger/shared deployments, use the pgvector or external backend.
"""

from __future__ import annotations

from pathlib import Path

from ..schema.models import MemoryRecord
from .base import ScoredRecord, cosine, matches_filters


class FolderMemoryBackend:
    name = "folder"

    def __init__(self, folder: str | Path) -> None:
        self.folder = Path(folder)
        self.folder.mkdir(parents=True, exist_ok=True)
        self.path = self.folder / "memory.jsonl"

    def _load(self) -> dict[str, MemoryRecord]:
        out: dict[str, MemoryRecord] = {}
        if not self.path.exists():
            return out
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rec = MemoryRecord.model_validate_json(line)
                out[rec.id] = rec
        return out

    def _write(self, records: dict[str, MemoryRecord]) -> None:
        tmp = self.path.with_suffix(".jsonl.tmp")
        tmp.write_text(
            "\n".join(r.model_dump_json() for r in records.values()) + ("\n" if records else ""),
            encoding="utf-8",
        )
        tmp.replace(self.path)  # atomic-ish swap

    async def upsert(self, record: MemoryRecord) -> None:
        records = self._load()
        records[record.id] = record
        self._write(records)

    async def search(
        self,
        *,
        tenant_id: str,
        embedding: list[float],
        k: int = 20,
        metadata_filters: dict[str, str] | None = None,
    ) -> list[ScoredRecord]:
        scored = [
            ScoredRecord(r, cosine(embedding, r.embedding))
            for r in self._load().values()
            if r.tenant_id == tenant_id and matches_filters(r, metadata_filters)
        ]
        scored.sort(key=lambda s: s.score, reverse=True)
        return scored[:k]

    async def get(self, tenant_id: str, record_id: str) -> MemoryRecord | None:
        rec = self._load().get(record_id)
        return rec if rec and rec.tenant_id == tenant_id else None

    async def all(self, tenant_id: str) -> list[MemoryRecord]:
        return [r for r in self._load().values() if r.tenant_id == tenant_id]

    async def count(self, tenant_id: str) -> int:
        return len(await self.all(tenant_id))

    async def delete_by_case(self, tenant_id: str, case_id: str) -> int:
        records = self._load()
        doomed = [
            rid for rid, r in records.items() if r.tenant_id == tenant_id and r.case_id == case_id
        ]
        for rid in doomed:
            del records[rid]
        if doomed:
            self._write(records)
        return len(doomed)
