# Case memory

**Opt-in per case.** blue-kakapo can remember resolved cases and recall similar ones — but only when
you enable it, and with defenses against memory poisoning.

## Backends
- **folder** (default local) — an embedded, file-based store in a system folder you link from the UI
  (`POST /api/memory/link`). No server.
- **pgvector** (DB-backed) — Postgres in production, SQLite in dev; the non-local option.
- **external** (Qdrant) — a later stage, behind the same interface.

## How recall works
Dense similarity + a lexical blend, weighted by **trust tier** and **decay**, filtered by tenant +
metadata (ATT&CK technique, severity, outcome).

## Poisoning defenses (ASI06)
- Agent-authored memories are **quarantined** — excluded from decisioning until a human **promotes**
  them to `reviewed`/`authoritative`.
- Low-trust and aged records are **down-weighted** (decay); every record carries **provenance**.
- Changing the embedding model is **detected**; stale vectors are excluded until `reembed` migrates
  them (mixing models' vectors is meaningless).

Status: `GET /api/memory/status`.
