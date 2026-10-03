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

---

## S2 — Walking skeleton (first vertical slice) ✅ (2026-10-03)

**Shipped:** the first end-to-end triage loop — ingest → OCSF-normalize → L1 verdict → ledger →
minimal UI, offline-capable.
- `normalize.py` — source-agnostic normalizer: generic alert → OCSF `Event`/`Alert`, observable
  extraction (ip/user/host/domain/url/hash) + PII flagging, severity coercion, raw retained.
- `intel_builtin.py` — tiny built-in indicator set for offline enrichment (RFC-5737/RFC-2606 reserved
  values only — no real host implicated); clearly not a threat-intel feed.
- `agents/l1.py` — L1 triage: deterministic-first enrichment + scoring producing an evidence-cited
  verdict (verdict-class + routing + confidence + rationale), **bias to escalate on uncertainty, never
  auto-close**; optional bounded LLM path (structured, schema-validated) when a provider is set, with
  deterministic fallback.
- `agents/orchestrator.py` — `TriageOrchestrator` + triage graph (intake → l1 → route) on the kernel;
  persists the Case, records every node in the ledger, accounts per-case cost.
- `core/cases.py` — `CaseRepo` (persist/load Case models).
- `api/routes.py` — `POST /api/ingest`, `GET /api/cases`, `GET /api/cases/{id}`,
  `GET /api/cases/{id}/ledger` (replay + verify); app wires store/gateway/bus/ledger/orchestrator.
- `api/static/index.html` — minimal dark "analyst console" UI (triage box, case list, verdict card,
  evidence, verified ledger trail; sample alerts). Served at `/`.
- `bk triage <file|->` CLI.

**Verified (empirically, offline, no key):**
- `uv run pytest` → **45 passed** (14 new: normalize, L1 scoring, orchestrator + API e2e).
- Live HTTP: malicious alert → `malicious/escalate/0.80`, state=escalated, 3 evidence; benign →
  `false_positive/auto_close`, state=resolved; `GET /api/cases` lists both; ledger **verified: true**
  with path `intake→l1→route→done`; `/` serves the UI.
- `bk triage -` (stdin) prints the verdict. ruff + format + mypy (38 files) clean.

**Exit check (S2):** a posted alert yields a tenant-scoped Case with an L1 verdict + cited evidence,
visible in a minimal UI, recorded in a verifiable ledger — on a fresh machine with no API key. ✅

---

## S3 — Connectors + ingestion depth ✅ (2026-10-03)

**Shipped:** the "connect your systems" layer.
- `connectors/base.py` — capability-declaring **Connector SDK**: `Capability` (read_alerts/query/
  enrich/act), `ActionSpec` (verb + **reversibility** + reverse_verb + required_scope), `ConnectorInfo`,
  `ActionResult`/`QueryResult`/`HealthStatus`, `Connector` protocol + `BaseConnector`.
- `connectors/registry.py` — register/lookup by capability; `find_action(verb)`.
- `connectors/mock.py` — **MockSIEM** (read/query/enrich, deterministic samples) + **MockEDR** (act:
  isolate/disable/block/kill with correct reversibility, dry-run, idempotency, in-memory state).
- `connectors/ingest.py` — **FileIngestConnector** (.json/.jsonl/dir) + `parse_syslog_line`
  (RFC 5424 & 3164 + key=value extraction + freeform fallback).
- `connectors/wazuh.py` — read from the Wazuh indexer (OpenSearch) → OCSF; active-response act; JWT auth.
- `connectors/elastic.py` — read `.alerts-security.alerts-*` (ECS) → OCSF; endpoint isolate/unisolate.
- `connectors/mcp.py` — **MCP client with tool-manifest fingerprint pinning** (rug-pull defense),
  argument validation, descriptions-as-data; transport injected (testable).

**Sources now available (≥3):** webhook (`POST /api/ingest`), mock SIEM, file/JSONL, syslog parse,
plus real Wazuh/Elastic read paths.

**Verified:** `uv run pytest` → **66 passed** (21 new). Highlights: mock EDR reversibility/dry-run/
idempotency; registry capability + action lookup; file + JSONL + directory ingest; syslog 5424/3164;
**MCP: pin → call ok; rug-pull (changed tool description) → MCPRugPullError, poisoned tool never
invoked; schema validation rejects missing/typed args; repin re-approves**; Wazuh + Elastic OCSF
mapping (unit) and read_alerts over respx-mocked HTTP; capability/reversibility declarations. ruff +
format + mypy (45 files) clean.

**Exit check (S3):** alerts flow from ≥3 sources → OCSF → Alerts; connector contract tests pass; MCP
tool consumed safely with manifest pinning. ✅

---

## S4 — Guardian + Asset Inventory ✅ (2026-10-03)

**Shipped:** the safety core — nothing state-changing reaches a connector ungated.
- `assets/inventory.py` + store tables (`assets`, `asset_identifiers`) — `AssetInventory`
  (upsert/lookup by identifier, tenant-scoped, conservative `normal` default).
- `assets/resolution.py` — deterministic entity resolution (exact-identifier match → asset link +
  confidence; unknowns left unresolved, never guessed).
- `guardian/injection.py` — prompt-injection detection (`scan_injection`/`contains_injection`), unsafe
  output guard (`contains_unsafe_output`), `as_untrusted` wrapper, and **Rule of Two**.
- `guardian/policy.py` — typed policy engine (ACS): `capability_gate` (deny unsupported),
  `crown_jewel_guard` (ask + N approvals), `blast_radius_guard`, `irreversible_guard`,
  `containment_ttl_modify` (auto-expiry), `low_impact_allow`; precedence **deny > ask > modify >
  allow**, default **ask** (never fail-open).
- `guardian/guardian.py` — `Guardian.check` (action+context → Disposition) and `GuardedExecutor`
  (the sole path to `connector.act`): records the disposition in the ledger, refuses denies, opens
  maker-checker **approvals** (two-person rule, duplicate-approver rejected, deny path), executes
  allow/modify using the rewritten action; `approvals` store table.

**Verified:** `uv run pytest` → **87 passed** (21 new). Highlights: low-impact→allow+executed+ledgered;
containment→modify adds TTL then executes; **crown-jewel isolate→pending (never auto-isolated); needs
2 distinct approvers; duplicate approver rejected; denied approval blocks execution**; unsupported
verb→deny and the connector is never touched (disposition still ledgered); irreversible→ask; injection
detected in alert content; unsafe output caught; Rule-of-Two. ruff + format + mypy (50 files) clean.

**Exit check (S4):** Guardian asks/denies/modifies high-impact in tests; injection suite passes; no
action reaches a connector without a disposition + ledger entry; never-isolate-crown-jewel honored. ✅

---

## S5 — Memory subsystem ✅ (2026-10-03)

**Shipped:** opt-in case memory with poisoning defenses.
- `memory/base.py` — backend protocol + shared scoring (cosine, lexical overlap, metadata filters).
- `memory/folder.py` — **FolderMemoryBackend** (embedded JSONL in the UI-linked folder; atomic writes).
- `memory/sql.py` — **SqlMemoryBackend** (DB-backed; Postgres in prod / SQLite in dev; `memory` table;
  pgvector/HNSW ANN is a Postgres deploy optimization, retrieval contract unchanged).
- `memory/service.py` — **MemoryService**: `remember` (compact case → embed → store, **quarantined**
  by default), `recall` (opt-in; dense + lexical blend × **trust-tier weight** × **decay**, excludes
  quarantined/stale), `promote` (human review → reviewed/authoritative), `reembed` (detects embedding-
  model change and migrates — mixing models' vectors is excluded until migrated).
- Wiring: orchestrator recalls similar prior cases at intake (as cited `prior_case` evidence, never
  instructions) and remembers resolved cases — both opt-in per case. API: `GET /api/memory/status`,
  `POST /api/memory/link` (local folder), and `memory_enabled` on `/api/ingest`. Store `memory` table
  + helpers.

**Verified:** `uv run pytest` → **95 passed** (8 new). Highlights: folder + SQL roundtrip (tenant-
scoped); **quarantine blocks recall until a human promotes**; opt-out honored; hybrid ranking prefers
the relevant case; **embedding-model change → stale excluded → reembed migrates → recall works**;
orchestrator remembers then recalls a promoted case end-to-end; API status + ingest opt-in flag. ruff
+ format + mypy (54 files) clean.

**Exit check (S5):** resolve case → stored; similar alert retrieves it (once promoted); opt-in honored;
agent-authored memory quarantined; embedding-version mismatch triggers migration; poisoning-guard
tests pass. ✅

---

## S6 — Core-5 depth + eval harness ✅ (2026-10-03)

**Shipped:** the deep triage wedge on a frozen Agent SDK, plus the honest eval harness.
- `agents/sdk.py` — **Agent SDK**: `AgentServices`, `AgentOutput`, `Agent` base that **structurally
  enforces the Rule of Two** (construction fails if an agent has all three legs).
- `attack.py` — ATT&CK technique→tactic map + kill-chain weighting (v19 Stealth/Defense-Impairment
  split noted).
- Core-5 agents (each: typed I/O, AgBOM, deterministic-first, evidence-cited, autonomy-enforced):
  **L1** (verdict), **L2** (connector enrich + SIEM query via escape hatch), **INTEL** (IOC intel +
  ATT&CK tactics), **FUSION** (entity-overlap correlation across open cases), **RESP** (containment,
  only via the GuardedExecutor; breaks the untrusted-input leg).
- Orchestrator rebuilt: intake (entity resolution + memory recall) → L1 → *(auto_close → route | else
  investigate: INTEL+L2+FUSION)* → route; plus `respond(case, dry_run)` — explicit, Guardian-gated,
  never auto-run.
- **Eval harness** (`eval/harness.py` + bundled 18-record dataset + methodology README): threat
  precision/recall/F1, **false-negative rate** (+ named misses), verdict accuracy, calibration
  (Brier + ECE), cost-per-case; offline numbers labeled an **illustrative floor**. `bk eval` CLI +
  `GET /api/eval`. API: `/api/cases/{id}/respond`, `/api/agents` (roster + AgBOM). App wires default
  reference connectors + Guardian so the full flow runs out of the box.

**Verified:** `uv run pytest` → **105 passed** (10 new). Highlights: **Rule-of-Two enforced at
construction** (reckless 3-leg agent rejected; core-5 all valid); L2 enrich+query; INTEL known-bad +
tactics; FUSION correlates shared entities; **RESP crown-jewel isolate → pending (never auto-isolated)**;
full orchestrator flow escalates with intel/l2/fusion evidence + verifiable ledger; gated dry-run
respond. Live: `bk eval` → precision 1.0 / recall 0.9 / **FNR 0.10** (names the stealthy miss) /
labeled floor; `/api/agents`, `/api/eval`, `/api/cases/{id}/respond` all work. ruff + format + mypy
(61 files) clean.

**Exit check (S6):** end-to-end alert→triage→investigate→correlate→context→verdict (evidence +
confidence); RESP containment gated + reversible (dry-run + mock EDR); harness reports precision/
recall/**FNR**/cost on the documented bundled dataset (labeled illustrative). ✅

---

## S7 — Scale + coworker dashboard ✅ (2026-10-03)

**Shipped:** backpressure + live updates + runtime controls, and the React coworker dashboard.
- Backend: orchestrator **concurrency semaphore** (backpressure, FR-34); **ledger threading lock**
  serializing hash-chained appends (fixed a real race the load test caught); `/api/ws` live
  tenant-filtered events; `/api/provider/switch` (runtime); `/api/provider/ollama/pull` (NDJSON
  bootstrap stream).
- Frontend (`web/`, **React + Vite + TypeScript**, built to `web/dist`, served by FastAPI): dark
  "analyst console" dashboard — **Cases** (live inbox + triage box with memory toggle; coworker detail
  = verdict card, ATT&CK chips, cited evidence timeline, replayable reasoning trace with "ledger
  verified ✓", gated "Run response (dry-run)"); **Agents** (roster with AgBOM + Rule-of-Two legs);
  **Settings** (provider switch, memory status, run-eval panel showing the FNR). WebSocket live
  refresh. App serves the built dashboard if present, else the minimal fallback UI.

**Verified:** `uv run pytest` → **109 passed** (4 new). Load/flood: **60 concurrent cases, peak
concurrency ≤ cap (8), lossless, ledger verifies** on a file-backed store (production concurrency path).
Live events; provider switch; ws connect. `npm run build` → dashboard built (154 KB JS). **Live
browser check:** dashboard renders; malicious case shows verdict + 10 cross-agent cited evidence items
+ verified trace; Agents roster shows Rule-of-Two per agent. ruff + mypy (61 files) + tsc clean.

**Exit check (S7):** ≥5k alerts/day flood stays bounded; full triage loop usable from the UI; live
updates; approvals/respond actionable; provider switch from UI; dark theme. ✅

**This completes Arc 1 (first public release: S0–S7 + core-5 + honest eval).**

---

## S8 — Enterprise hardening ✅ (2026-10-03)

**Shipped (Arc 2 — enterprise GA):**
- `security/` package: **Principal + RBAC** (viewer/analyst/responder/admin → permissions);
  **Authenticator** (open localhost / static service tokens / **OIDC JWT via JWKS**, PyJWT RS256);
  **SecretStore** (env / encrypted-file / **OpenBao** KV); **SCIM 2.0** user provisioning with a
  **deprovision→deny cascade** wired into auth; FastAPI deps (`require(permission)`).
- API hardening: every data route is **tenant-scoped to the principal** and **RBAC-gated** (VIEW /
  TRIAGE / PROPOSE_RESPONSE / MANAGE / ADMIN); cross-tenant access returns 404 (no existence leak);
  WebSocket authenticates via `?token=`. SCIM endpoints under `/scim/v2` (admin-only). Store gains a
  `users` table.
- Deploy: hardened **Helm chart** (non-root, read-only rootfs, dropped caps, no SA token, probes,
  config/secret wiring, ingress/HPA options) + README; **Release CI** (build → SBOM via syft →
  **cosign keyless sign + SBOM attestation** → GHCR); **Zarf** air-gap package (image + chart +
  pgvector) with air-gapped values.

**Verified:** `uv run pytest` → **118 passed** (9 new). Highlights: role→permission mapping; open-mode
local admin; local-token auth (missing/invalid → 401); **OIDC RS256 verify maps tenant+roles**;
**SCIM deprovision → subsequent auth denied**; env secret store; **API 401 without token, 403 without
permission (viewer can't triage, analyst can't respond)**; **tenant isolation (B can't see A's case →
404)**; SCIM admin-only. ruff + mypy (69 files) clean.

**Exit check (S8):** SSO (OIDC) works; SCIM deprovision cascades; low-priv role denied containment;
tenant isolation holds; Helm chart written (hardened); images signed + SBOM in CI; Zarf air-gap
package defined. ✅  *(SAML via an OIDC-bridging proxy — Keycloak/oauth2-proxy — is the documented
pattern; native SAML is roadmap.)*

**This completes Arc 2 (enterprise GA).**

---

## S9 — Full agent roster ✅ (2026-10-03)

**Shipped (Arc 3):** the remaining 9 agents, each on the Agent SDK (AgBOM, Rule-of-Two, deterministic-
first, evidence-cited) + their supporting data.
- `compliance.py` — regulatory clocks (DORA 4h/24h, NIS2 24h/72h, GDPR 72h, SEC 4bd) from *awareness*.
- `vuln_feed.py` (sample CVE/KEV) + `detections.py` (detection inventory + Sigma skeleton generator).
- Proactive (`agents/proactive.py`): **WATCH** (burst/early-warning over recent cases), **HUNT**
  (hypothesis→query via escape hatch), **DET** (ATT&CK coverage gaps + proposed Sigma, human-merged),
  **VULN** (KEV/CVSS × asset × active-threat prioritization), **INSIDER** (privacy-gated UEBA signal).
- Service ops (`agents/serviceops.py`): **COMMS** (summary + human-sent external draft), **RPT**
  (incident report incl. clocks + cost), **MAINT** (connector/pipeline health + decay), **MGR**
  (sets regulatory clocks on the case + prioritization).
- Orchestrator exposes the full **14-agent roster** + `run_agent_on_case(name, ...)` for scheduled/
  on-demand ops; `/api/agents` now lists all 14 with AgBOM + Rule-of-Two.

**Verified:** `uv run pytest` → **129 passed** (11 new). Highlights: 14 agents construct (Rule-of-Two
all satisfied); WATCH burst; HUNT query; DET gap→Sigma; VULN KEV-first; INSIDER privacy-minimized;
COMMS external draft (not sent); RPT report w/ clocks; MAINT flags an unhealthy connector; **MGR sets
DORA/NIS2/GDPR/SEC clocks**; compliance only for reportable verdicts. ruff + mypy (74 files) clean.

**Exit check (S9):** each remaining agent meets the §4.6 depth bar with its acceptance test; MGR tracks
regulatory clocks; DET proposes a Sigma rule + coverage delta; VULN prioritizes by active-threat
context; INSIDER runs under privacy controls. ✅  **All 14 agents now deeply implemented.**
