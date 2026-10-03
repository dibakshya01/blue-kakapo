"""blue-kakapo memory subsystem — opt-in case recall with poisoning defenses.

Backends: ``folder`` (embedded, user-linked folder) and ``pgvector`` (DB-backed; Postgres in prod,
SQLite in dev). The ``external`` backend (Qdrant) is a later stage.
"""

from __future__ import annotations

from pathlib import Path

from ..config import MemoryBackend as MemoryBackendKind
from ..config import Settings
from ..core.store import Store
from .base import MemoryBackend, ScoredRecord, cosine, lexical_overlap
from .folder import FolderMemoryBackend
from .service import MemoryService, case_query_text, compact_case
from .sql import SqlMemoryBackend

__all__ = [
    "MemoryBackend",
    "MemoryService",
    "FolderMemoryBackend",
    "SqlMemoryBackend",
    "ScoredRecord",
    "cosine",
    "lexical_overlap",
    "compact_case",
    "case_query_text",
    "build_memory_backend",
]


def build_memory_backend(settings: Settings, store: Store) -> MemoryBackend:
    """Construct the configured memory backend."""
    kind = settings.memory_backend
    if kind == MemoryBackendKind.FOLDER:
        folder = settings.memory_folder or (settings.data_dir / "case-memory")
        return FolderMemoryBackend(Path(folder))
    if kind == MemoryBackendKind.PGVECTOR:
        return SqlMemoryBackend(store)
    raise NotImplementedError(
        f"memory backend {kind!r} is not available yet (external/Qdrant is a later stage)"
    )
