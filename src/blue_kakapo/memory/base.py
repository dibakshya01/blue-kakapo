"""Memory backend contract + shared scoring helpers.

A backend handles storage and dense (vector) candidate retrieval; the service layer applies the
poisoning defenses (quarantine, trust-tier/decay weighting), the lexical blend, and reranking — so
those live in one place regardless of backend (folder, pgvector, external).
"""

from __future__ import annotations

import math
import re
from typing import Protocol, runtime_checkable

from ..schema.models import MemoryRecord

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def lexical_overlap(query: str, text: str) -> float:
    q = set(_TOKEN_RE.findall(query.lower()))
    d = set(_TOKEN_RE.findall(text.lower()))
    if not q or not d:
        return 0.0
    return len(q & d) / len(q | d)


class ScoredRecord:
    __slots__ = ("record", "score")

    def __init__(self, record: MemoryRecord, score: float) -> None:
        self.record = record
        self.score = score


@runtime_checkable
class MemoryBackend(Protocol):
    name: str

    async def upsert(self, record: MemoryRecord) -> None: ...

    async def search(
        self,
        *,
        tenant_id: str,
        embedding: list[float],
        k: int = 20,
        metadata_filters: dict[str, str] | None = None,
    ) -> list[ScoredRecord]: ...

    async def get(self, tenant_id: str, record_id: str) -> MemoryRecord | None: ...

    async def all(self, tenant_id: str) -> list[MemoryRecord]: ...

    async def count(self, tenant_id: str) -> int: ...


def matches_filters(record: MemoryRecord, filters: dict[str, str] | None) -> bool:
    if not filters:
        return True
    return all(str(record.metadata.get(key)) == str(value) for key, value in filters.items())
