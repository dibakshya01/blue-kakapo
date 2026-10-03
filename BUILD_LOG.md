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

---

## S10 — Eval, docs, security self-review ✅ (2026-10-03)

**Shipped:**
- `tests/test_attack_suite.py` — the consolidated **adversarial suite** (9 integrated scenarios):
  indirect prompt injection contained, excessive-agency blocked on crown jewels, MCP rug-pull refused,
  memory poisoning quarantined, unsafe output caught, ledger tamper detected, GDPR erasure preserves
  the chain, cross-tenant access denied, connector reversibility declared.
- `docs/` (13 pages): index, getting-started, architecture, agents, connectors, providers, memory,
  guardian, eval (+ dataset methodology), **security-model (OWASP LLM/ASI/MCP + NIST + AISVS 1.0
  self-assessment)**, **what-it-can-and-cannot-do**, threat-model, **gdpr-erasure**.

**Verified:** `uv run pytest` → **138 passed** (9 new). README-promise CLI smoke reproduces:
`bk version`, `bk eval` (precision 1.0 / **FNR 0.10** / illustrative-floor label), `bk triage`
(malicious→escalate). ruff + format + mypy (74 files) + tsc clean.

---

## ✅ First-cut Definition of Done (build-plan §9)

- [x] All first-cut MUST FRs; **core-5 deep + Agent SDK**; all 14 agents deep (S9).
- [x] `bk serve` runs on a fresh machine; **offline mode triages end-to-end with no key**; walking
      skeleton works from S2 on.
- [x] Self-checks clean: ruff + ruff-format + mypy (74) + tsc; **138 tests** green.
- [x] **Adversarial suite passes** (injection, excessive-agency+modify, rug-pull, memory-poisoning,
      output-handling, ledger-tamper, erasure, tenancy).
- [x] **Eval harness** reproducible; reports precision/recall/**FNR**/cost; offline labeled illustrative.
- [x] **Ledger** tamper-evident + replayable; **crypto-shred erasure** keeps the chain verifiable.
- [x] Enterprise: OIDC SSO, SCIM, RBAC/ABAC, secrets (OpenBao), multi-tenant isolation; **Helm** chart;
      **cosign-sign + SBOM** in CI; Zarf air-gap package.
- [x] Docs incl. **"what it can & cannot do"**, dataset methodology, GDPR/erasure, **AISVS
      self-assessment**; README quickstart reproduces.
- [x] `BUILD_LOG.md` + `HANDOFF.md` current; **no unaudited accuracy numbers** anywhere.

**Phase 3 build complete (Arcs 1–3).** Next: Phase 4 (site + deck), Phase 5 (≥3 adversarial hardening
rounds), Phase 6 (handoff).

---

## Phase 4 — Website + deck + assets ✅ (2026-10-03)

**Design system ("Night Watch", via master-designer):** deep-night canvas, one concept-driven
signal-green/teal accent (`#35e0a1`) + blue-team cyan (`#4aa8ff`) + verdict status colors; Space
Grotesk / Inter / JetBrains Mono; a shield-with-watchful-gaze kākāpō mark; Swiss-modern dark + glow.

**Shipped:**
- **5-page GitHub Pages site** in `docs/` (shared `site.css` + `site.js` + `.nojekyll`): Home
  (dark hero, one-command install + copy, proof chips, why/how/trust sections, live verdict mock),
  **Plain-English** (ELI5 for leaders), **Docs** (quickstart, CLI/API/module map), **Architecture**
  (inline SVG data-flow diagram + principles), **Contact** (community + responsible use).
- **Logo mark** (`docs/assets/kakapo-mark.svg`) — monochrome-safe.
- **Social card** 2:1 (`docs/assets/social-card.jpg`, 35 KB) + README artistic header, badge row,
  product screenshot, and a six-line pitch deck.

**Verified (empirically in-browser):** desktop + mobile (375px) renders; **no horizontal overflow**
(`scrollWidth == innerWidth`); nav collapses to a toggle on mobile; fonts load; strong contrast; the
architecture SVG renders. Screenshots captured for Home (desktop + mobile), the social card, and the
dashboard.

**This completes the first cut (build + site).** Handoff item added: upload the social card to the
repo's Settings → Social preview, and enable GitHub Pages (Settings → Pages → `main`/`docs`).

---

## Phase 5 — Adversarial hardening

### Round 1 ✅ (2026-10-03) — fresh memory-free `adversarial-code-review` subagent

Verdict: *"Genuinely impressive architecture and unusually honest docs, but three headline
safety/privacy promises were falsified in the running code."* Suite was green (138 tests) but the
reviewer earned its keep. Findings triaged and **all fixed**, each with a fail-before/pass-after
attack-test. Suite now **145 tests**, `ruff`/`ruff format`/`mypy` (75 files) clean, `tsc`+`vite` clean.

**🔴 Criticals (pure misses — fixed):**
1. **GDPR crypto-shred was never wired.** `CryptoShredder` existed but ingest never called it, so raw
   alert payloads (SSNs, free-text notes, emails) were persisted verbatim in `cases.data`. Fixed:
   new `core/pii.py` tokenizes every raw payload at ingest (`protect_case_pii`, called in
   `TriageOrchestrator.triage_alert` before the first persist) → the case at rest holds a
   `{_pii_ref: token}`, plaintext lives only as AES-GCM ciphertext. Added `erase_case` +
   `POST /api/cases/{id}/erase` (admin) that crypto-shreds raw blobs **and** redacts PII-flagged
   observables/entities; ledger stays PII-free and verifies. Docs corrected to be precise about what
   is tokenized vs. redacted. Test: `test_raw_pii_is_tokenized_at_rest_and_erasable`.
2. **High-impact containment auto-executed on normal/unknown assets.** The old `containment_ttl_modify`
   returned `MODIFY`, which `GuardedExecutor` ran immediately — so `isolate_host`/`firewall_drop` on a
   `normal` (or unknown→normal) asset fired with no human. Fixed: replaced crown-jewel + ttl-modify
   policies with a single `high_impact_guard` → **ASK with two approvers on every asset**; the TTL is
   carried as the *effective* action the approvers run (modify composes with ask, never replaces it).
   Tests: `test_containment_on_normal_asset_requires_two_humans_never_auto_executes`,
   `test_all_high_impact_verbs_require_two_humans_on_normal_assets`,
   `test_containment_on_unknown_asset_never_auto_executes`.
3. **Maker-checker loop was unreachable.** `approve()/deny()` existed but no route/UI called them.
   Fixed: `GET /api/approvals`, `POST /api/approvals/{id}/approve|deny` (gated by `approve_response`),
   plus an **Approvals** inbox tab in the dashboard (approve/deny, live count badge). Tests:
   `test_maker_checker_approval_flow_via_api`, `test_maker_checker_blocks_self_approval_and_single_approver`.

**🟡 Moderates (fixed):** proposer may no longer approve its own action (maker≠checker) + **all**
high-impact actions require **two** distinct approvers; injection/`as_untrusted`/unsafe-output guards
wired into L1 (untrusted content wrapped as data; injection markers force escalate-not-auto-close;
unsafe model output withheld); OIDC now **fails closed** when `oidc_audience` is unset
(confused-deputy); `memory/link` folder confinement via `BK_MEMORY_ROOT` + documented that the
provider/memory backends are process-global today (per-tenant on the roadmap); `bk serve` **refuses a
non-loopback bind while auth is disabled** (`--insecure`/`BK_ALLOW_INSECURE_BIND` to override);
README/plan/site "immutable" → **"tamper-evident"**. Tests: `test_oidc_without_audience_fails_closed`,
`test_serve_refuses_non_loopback_bind_without_auth`.

**⚪ Minors (fixed):** `/api/provider` now requires `view`; CORS drops `allow_credentials` under a
`*` origin; `FileSecretStore` key wired from `BK_SECRET_FILE_KEY`; real in-flight-action counter feeds
the blast-radius guard; `contains_unsafe_output` is now live (was dead code).

**Not changed (accepted/roadmap):** WS token in query string (browsers can't set WS headers; tenant
still enforced); per-tenant provider/memory backends (documented as process-global); MCP fingerprint
field coverage. Carried into round 2.

### Round 2 ✅ (2026-10-03) — fresh memory-free adversarial reviewer

Reviewer reproduced everything empirically (forged RS256 JWTs, concurrency harness). Confirmed
round-1 fixes #2 (two-person gate on every asset) and #3 (maker-checker, proposer≠checker) **hold
under adversarial testing**, the Guardian is genuinely the sole connector path, tenant isolation
returns 404 (no oracle), ledger verifies after erase, eval harness is honest, injection regexes are
ReDoS-safe, CI has no injection surface. But it found round-1 fix #1 was **half-done** plus moderates.
All fixed with fail-before/pass-after tests. **150 tests**, `ruff`/`format`/`mypy` (75 files) clean.

**🔴 C1 — crypto-shred was incomplete (ship-blocker, fixed).** `normalize_alert` promotes raw text
into cleartext `title`/`message`/`rule_name` + USER/EMAIL observables; round-1 only tokenized `.raw`,
so PII in an alert's title/description was stored plaintext **and survived `erase`**. My own regression
test used a *clean* title, masking it. Fixed: `erase_case_pii` now scrubs emails/SSNs + the case's own
PII values out of **every** free-text field (title, alert titles, rule_name, event messages, evidence
summaries, verdict rationale) in addition to shredding raw blobs and redacting observables/entities;
added `redact_pii_text`. Docs reworded to the honest split (raw never stored in clear; free-text
readable while live, fully scrubbed on erasure). Test:
`test_pii_tokenized_at_ingest_and_fully_scrubbed_on_erase` now plants PII in title+message+user.

**🟡 M1 — erasure ignored derived memory.** `compact_case` stores `case.title`+rationale in the memory
store; `erase_case` never touched it. Fixed: added `MemoryBackend.delete_by_case` (folder + sql),
`MemoryService.forget_case`, and `erase_case` now purges the case's memory records. Test:
`test_erasure_purges_derived_memory`.

**🟡 M2 — `set_oidc` bypassed the audience fail-closed.** The guard lived only in `Authenticator.__init__`;
an audience-less verifier injected via `set_oidc` accepted a token minted for another relying party.
Fixed: `OIDCVerifier.__init__` refuses `audience=None` unless an explicit `insecure_skip_aud=True`.
Tests: `test_oidc_verifier_refuses_audienceless_construction`, `test_oidc_rejects_wrong_audience_even_via_set_oidc`.

**🟡 M3 — SCIM deprovision didn't cascade for typical IdPs.** `_check_active` keyed on `display_name`,
which OIDC sets from the `name` claim (Entra/Okta/Google default) → deprovisioned users still
authenticated. Fixed: resolve by **stable ids** — OIDC `sub`↔SCIM `external_id` first, then
`preferred_username`↔`userName`, never display name; added `Principal.username` +
`store.get_user_by_external_id`. Test: `test_scim_deprovision_cascades_with_name_claim`.

**🟡 M4 — benign-keyword stuffing could force `auto_close`.** Padding threat text with "false positive /
known good" at low severity hit the benign branch. Fixed: a strong-threat veto — a known-bad
indicator, suspicious keywords, or injection markers now force ESCALATE over any AUTO_CLOSE, on both
the deterministic and LLM paths. Test: `test_benign_keyword_stuffing_cannot_force_auto_close`.

**⚪ Minors (fixed):** local token principal id now a stable SHA-256 prefix (was `token[:6]`, which
collided → false duplicate-approver rejection); ingest body size cap (413); erase requires
`?confirm=true`; README test count; documented responder-role separation + multi-process approval
row-locking (guardian.md + a code comment). Dead-code `reveal`/replay left as the erasure-verification
mechanism (not overclaimed).

### Round 3 ✅ (2026-10-03) — fresh memory-free adversarial reviewer

Reviewer re-stressed rounds 1–2 (maker-checker races, OIDC confused-deputy, SSRF, deep-nesting DoS,
idempotent/chain-safe crypto-shred) and confirmed they **hold**. But it found the round-2 C1 erasure
was *still* incomplete on connector-wired, RESP-run cases — and that my round-2 C1 test under-tested
(no registry/guardian → L2 skipped; no `respond` → no approval), so it never touched the leaking
fields. All fixed with a properly-wired regression test. **152 tests**, ruff/format/mypy clean.

**🔴 F1 — PII survived erasure in two API-readable places (ship-blocker, fixed):**
- `Evidence.query` (L2/proactive write `user=<email> last 24h`) was not scrubbed — only `ev.summary`
  was. Fixed: `erase_case_pii` now scrubs `ev.query` too.
- The **approvals table** was never touched by erase — `disable_user`'s `action.target` (a username/
  email) persisted and was readable via `GET /api/approvals`. Fixed: `erase_case` now redacts
  `action.target`/`args`/reason of the case's approval rows (`_redact_case_approvals`), using the
  case's own PII values gathered *before* scrubbing (`collect_case_pii_values`).
- New honest regression `test_erasure_scrubs_evidence_query_and_approvals` wires MockSIEM/EDR +
  Guardian and runs RESP, asserting no PII in `GET /api/cases/{id}` (incl. evidence.query) or in the
  approvals table after erase; the original under-testing test is kept for the title/message vector.

**🟡 F3 — redact coverage vs. "every field" overclaim (fixed):** added a ReDoS-safe phone pattern and
**reworded the docs + orchestrator docstring** to the honest, precise claim — erasure removes *known
PII patterns (emails/SSNs/phones) plus the case's own identified PII values*, not "all personal data"
by magic. Documented that operators can extend patterns; we don't guess-redact generic digit runs
(would clobber ports/hashes/IPs).

**🟡 F4 — strong-threat veto evaded by homoglyphs (fixed):** added `fold_confusables` (NFKC +
Cyrillic/Greek→Latin map + zero-width strip) applied before the keyword and injection scanners, and
**tightened offline auto_close to require a positive benign *indicator*** (allowlist hit), not a
benign *keyword* — so keyword-stuffing (obfuscated or not) can't force a close. Test:
`test_homoglyph_threat_cannot_force_auto_close`. (All bundled benign eval rows carry a real benign
indicator, so FNR/precision are unaffected.)

**⚪ Minors (fixed):** `/api/approvals` gated to `approve_response` (targets can be PII); a real
Content-Length body-size middleware (not just the post-parse 413 cap); on approve the stored action is
**re-evaluated through the Guardian** and refused if it now DENYs (tamper/policy-drift defense);
`case.assignee` scrubbed on erase; erase is idempotent (no duplicate `case.erased` ledger entry);
documented one-credential-per-approver (two local tokens = two ids).

### Round 4 ✅ (2026-10-03) — fresh memory-free adversarial reviewer

Reviewer confirmed rounds 1–3 hold (crypto-shred survives even the leak; approvals redaction covers
non-pending rows; memory purge real; no PII on the WS bus or in logs — two surfaces it explicitly
checked). But the GDPR-completeness theme recurred a fourth time, and it caught two round-3 tests that
didn't prove their names. All fixed. **152 tests**, ruff/format/mypy clean.

**🔴 F1 — `checkpoints` table kept a full cleartext case snapshot after erase (fixed).** The kernel
checkpoints each node with `state_json = full Case`; `erase_case` never touched the `checkpoints`
table (no delete method existed), so every normalized PII value — incl. the structured PII the
case-level scrub removes — survived in cleartext forever. Fixed: added
`store.delete_checkpoints_by_case` and `erase_case` now deletes the case's checkpoints (an erased case
is not resumable). Verified live: a checkpoint held the email+SSN pre-erase, is gone post-erase.

**🟡 F2 — non-observable free-text PII (e.g. a plain display name) survives; "every field" overclaimed
(fixed by honest wording).** The scrub is pattern- + value-based, not NER, so a name like "Jane
Roberts" that is neither a recognized pattern nor an extracted observable isn't detected. Reworded
`docs/gdpr-erasure.md` + the `erase_case`/`erase_case_pii` docstrings to state the honest scope
(known-pattern PII + the case's identified observables/entities) and to point at hard-delete for the
stronger guarantee. (No fake NER; no silent overclaim.)

**🟡 F3 — `fold_confusables` missed uppercase homoglyphs (fixed).** The map was lowercase-only and
folded before lowercasing, so `Ѕystem prompt` / `Іgnore all previous…` slipped past the scanners.
Fixed: `casefold()` before the translate, so uppercase Cyrillic/Greek folds to its lowercase form and
then to ASCII.

**🟡 F4 / F5 — two round-3 tests didn't prove their names (fixed).** The homoglyph test passed even
with folding disabled (the auto_close branch was unreachable for its fixture); rewrote it with a
benign-allowlist-indicator + low-severity baseline that *does* auto_close, so the fold is now the thing
that flips it to escalate. The "fully scrubbed" test only checked the case document; extended it to
also assert the `checkpoints` table is PII-free (it now fails without the F1 fix).

**⚪ F6 — body-size middleware is Content-Length-only** (a chunked request without the header isn't
caught by the global cap; the per-route 413 and uvicorn limits remain). Left as documented
defense-in-depth; a streaming byte cap is the follow-up if a hard bound is required.

### Round 5 ✅ (2026-10-03) — fresh memory-free adversarial reviewer (FINAL / protocol cap)

Verdict: **essentially clean.** The reviewer built a worst-case PII-everywhere case, fully wired
(SIEM+EDR+Guardian+inventory+SQL-memory), triaged + responded + memory-enabled, erased, then dumped
**all 10 tables** and grepped every PII value. Result matrix: `cases` (incl. the `title` *column*),
`ledger`, `checkpoints`, `crypto_keys`, `crypto_blobs` (ciphertext unrecoverable), `assets`,
`asset_identifiers`, `memory`, `users` — all clean/handled. Round-4 fixes all hold (checkpoint delete
is tenant+case scoped, non-resumable-after-erase is clean, homoglyph fold is load-bearing and
casefolds uppercase, no false-escalation storm, no ReDoS). Invariants (Guardian sole path, two-person,
tenant 404, OIDC fail-closed, ledger-verifies-after-erase, SCIM stable-id) all re-confirmed. Docs
judged "honest to a fault" — the non-NER caveat precisely predicts the one acknowledged residue.

One genuine completeness bug on the recurring theme, now fixed:
**🟡-1 — approval redaction was capped at the recent 200 rows.** `_redact_case_approvals` used
`list_approvals(status=None)` (ordered desc, limit 200), so in a busy tenant (>200 approvals) an older
erased case's `disable_user` target (a user email) survived in the API-readable `approvals` table —
and erasures usually target older cases. Fixed: added `store.list_approvals_by_case` (queries the
indexed `case_id` column, unbounded) and `_redact_case_approvals` now uses it. Regression:
`test_erasure_redacts_approvals_beyond_recent_window` floods 250 newer approvals, asserts the case's
approval is outside the recent-200 window, then asserts erasure still redacts it.
**⚪-1 (parallel, fixed):** `SqlMemoryBackend.delete_by_case` was bounded at 1000 (`query_memory`
default); now passes `limit=None` (unbounded) so a >1000-record tenant can't retain an erased case's
memory. (The default folder backend was already complete.)
**⚪-2 (acknowledged, no change):** non-NER free-text residue (a plain display name) — exactly the
documented scope; hard-delete is the stronger guarantee.

**Phase 5 complete — 5 adversarial rounds (≥3 required; continued while rounds surfaced material
findings; round 5 came back essentially clean).** Final: **153 tests**, `ruff` + `ruff format` +
`mypy` (75 files) + `tsc`/`vite` all clean. Every round's findings + fixes are logged above; every fix
carries a fail-before/pass-after attack-test.
