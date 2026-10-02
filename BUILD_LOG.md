# Build Log — blue-kakapo

One entry per build iteration: what shipped, how it was verified, result. Newest last.

---

## S0 — Foundations ✅ (2026-10-03)

**Shipped:** monorepo scaffold (src-layout, hatchling/uv), Apache-2.0 LICENSE + NOTICE, README,
CONTRIBUTING / CODE_OF_CONDUCT / SECURITY, `.gitignore`, `.env.example`; config system
(`pydantic-settings`, `BK_` env, offline-by-default); structured logging (`structlog`) + optional
OpenTelemetry; the full **tenant-aware data model** (OCSF `Event`/`Observable`; `Alert`, `Entity`,
`Evidence`, `Verdict` [verdict-class vs routing], `Case`, `CostAccounting`, `RegulatoryClock`,
`AssetRecord`, `MemoryRecord`, `AgBOM`; `Action`/`Disposition`; `LedgerEntry`/`ModelRef`/`PiiToken`);
the **model-agnostic provider gateway** (offline / Anthropic / OpenAI-compatible / Ollama) with
generation + embeddings + reranking, runtime switching, structured-JSON helper, per-call cost
accounting, and an Ollama `/api/pull` bootstrap; FastAPI control plane (health/ready/version/provider)
+ `bk` CLI (`version`/`info`/`serve`); Dockerfile + docker-compose (api + pgvector + optional ollama);
GitHub Actions CI (ruff + ruff-format + mypy + pytest on py3.11/3.12 + CLI smoke).

**Verified:**
- `uv run pytest` → **17 passed** (schema invariants incl. tenant_id required; offline provider
  determinism + normalized embeddings + rerank ordering; gateway switch + embed fallback; API
  health/ready/provider).
- `uv run ruff check` → clean. `uv run mypy` → **no issues in 27 files**.
- Ran the server for real (`bk serve`, offline mode) and hit `/healthz`, `/readyz`, `/api/provider`
  → correct JSON, no key, no external calls.

**Notes:** uv's editable install mishandles a directory path containing a space ("OpenSource
Projects"); added a root `conftest.py` so `uv run pytest` works regardless, and documented a
space-free clone path for contributors. CI and normal clones are unaffected.

**Exit check (S0):** `uv run` stack healthy; offline mode works with no key; `tenant_id` present in
all core models. ✅
