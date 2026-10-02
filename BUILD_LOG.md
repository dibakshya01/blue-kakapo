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

---

## S1 — Kernel + Ledger ✅ (2026-10-03)

**Shipped:** the deterministic orchestration spine.
- `core/store.py` — one SQLAlchemy Core schema (SQLite dev / Postgres prod) with document-style
  tables for cases, ledger (unique tenant+seq), checkpoints, and the crypto keystore/blobs; `Store`
  facade with `in_memory()` (StaticPool, thread-shared) for tests.
- `core/crypto.py` — `CryptoShredder`: per-record **AES-256-GCM** encryption (token as AAD), reveal,
  and erase-by-key-destruction (GDPR crypto-shred).
- `core/ledger.py` — hash-chained append-only `Ledger`: `append` (auto seq + prev_hash + sha256 over
  canonical content), `verify` (full-chain recompute), `replay` (ordered path per case/run).
- `core/bus.py` — in-process async pub/sub `EventBus` (drops on backpressure, tenant-filtered).
- `core/kernel.py` (322 LOC) — typed state machine: `Node`/`NodeResult` (Goto/Suspend/Done/Fail),
  `Graph`, `RunContext[S]`, `Engine.run`/`Engine.resume` (checkpoint after every node; **suspend/resume
  re-enters the exact node with restored typed state**; per-node timeout+retry; max-steps guard;
  ledger+bus hook on every node), `run_parallel`.

**Kernel budget decision:** core total **852 LOC** (kernel 322 + ledger 115 + store 283 + crypto 75 +
bus 57) — **well under the ≤1,500 budget → keep the purpose-built kernel; no LangGraph fallback.**

**Verified:** `uv run pytest` → **31 passed** (14 new). Highlights: ledger chains + `verify` true;
tamper → `verify` false; per-tenant independent chains; crypto-shred roundtrip + erase→None +
**erasure leaves the chain verifiable**; kernel run→DONE with ledgered path; **suspend→resume
re-enters exact node, state restored, approval payload applied**; bad resume token rejected; node
exception + explicit Fail captured; retry-then-succeed; max-steps guard; parallel children. ruff +
format + mypy (32 files) clean.

**Fix during build:** in-memory SQLite needs `StaticPool` so the kernel's worker-thread ledger writes
share the DB; added a 30s busy timeout for file SQLite.

**Exit check (S1):** graph runs/persists/resumes into the exact node; ledger hash-chain verifies;
replay reconstructs the path; crypto-shred erases a record without breaking the chain. ✅
