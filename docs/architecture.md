# Architecture

```
Alert sources ─▶ Connectors ─▶ Ingestion/Normalize (OCSF) ─▶ Case store (Postgres+pgvector / SQLite)
 (SIEM/EDR/           (SDK)                │
  webhook/syslog/MCP)                      ▼
                             Orchestrator / Superagent  ── deterministic, checkpointed state machine
                                           │   routes to agents; HITL suspend/resume; via the Guardian
                        ┌──────────────────┼───────────────────┐
                     intake ─▶ L1 ─▶ (auto_close | investigate: INTEL+L2+FUSION) ─▶ route
                                           │
                            bounded LLM · deterministic-first enrichment · typed, evidence-cited outputs
                                           │
                 Provider Gateway       Memory (folder/pgvector)      Guardian (ACS) ──▶ Connectors.act
                (offline/anthropic/        opt-in, poisoning-          allow/deny/modify/ask/defer
                 openai/ollama)            defended                     (RESP, human-approved)
                                           │
                     Case Ledger (append-only, hash-chained, crypto-shredded, replayable) ◀── everything
                                           │
                     Control plane (FastAPI + WebSocket) ◀──▶ Coworker dashboard (React)
  Cross-cutting: AuthN/Z (OIDC/SCIM/RBAC, tenant-scoped) · Secrets (OpenBao) · OpenTelemetry
```

## Principles
1. **Trust is the product** — evidence-cited, replayable verdicts; ship the eval harness, not a number.
2. **Deterministic spine, bounded intelligence** — a typed checkpointed kernel drives flow; LLMs do
   scoped reasoning after deterministic enrichment.
3. **Human-in-the-loop by default; least privilege always** — Guardian-gated, blast-radius-limited,
   reversible, audited.
4. **In-network & model-agnostic** — localhost/air-gap; any provider; opt-in memory.
5. **Integration-first, standards-anchored** — OCSF, STIX/TAXII, Sigma/ATT&CK, MCP.

## Components
- **Kernel** (`core/kernel.py`) — `Node`/`Goto|Suspend|Done|Fail`, `Graph`, `Engine.run/resume`
  (re-enters the exact node), checkpoints after every node, per-node timeout/retry, ledger hook.
- **Ledger** (`core/ledger.py`) — append-only, SHA-256 hash-chained; `verify` + `replay`; per-tenant
  serialized writes.
- **Crypto-shred** (`core/crypto.py`) — per-record AES-256-GCM; destroy key to erase (GDPR).
- **Guardian** (`guardian/`) — ACS policy engine + GuardedExecutor + maker-checker approvals.
- **Provider gateway** (`providers/`) — one interface (generation/embeddings/rerank) over all backends.
- **Memory** (`memory/`) — folder + SQL/pgvector backends; hybrid recall; quarantine/decay.
- **Connectors** (`connectors/`) — capability-declaring SDK + reference connectors + MCP client.
- **Agents** (`agents/`) — SDK + the 14-agent roster.
- **Security** (`security/`) — authn (open/local/OIDC), RBAC, secrets, SCIM.

## Storage
One SQLAlchemy layer: **SQLite** for dev/localhost (no Docker), **Postgres + pgvector** for production.
Tables: cases, ledger, checkpoints, crypto keystore/blobs, assets, approvals, memory, users.

See [build-plan.md](../build-plan.md) for the full specification and the staged build order.
