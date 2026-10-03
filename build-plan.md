# Build Plan — blue-kakapo

*An open-source, self-hostable, agentic SOC platform for trustworthy Tier-1 triage — a transparent coworker for L2/L3 analysts.*

> This is the contract for the build. Nothing is implemented that isn't specified here. When reality forces a change, this file is edited first, then the code. Derived from [finding.md](finding.md). Revised after ExpertSpecReviewer cycle 1 (see §11 Open concerns for the audit trail).

---

## 0. Thesis & principles

**Thesis:** The AI-SOC category is real and valuable but entirely closed, cloud-bound, and trust-challenged. blue-kakapo is the open-source, self-hostable, in-network agent swarm that makes Tier-1 triage fast **and** trustworthy — a transparent coworker for L2/L3 analysts, not a black box that acts alone.

**Principles (these decide every trade-off):**
1. **Trust is the product.** Every verdict is backed by cited evidence and a **replayable** reasoning trace reconstructed from a **tamper-evident** (hash-chained, append-only) *case ledger*. Confidence is calibrated; the bias is to escalate, not to suppress. We ship an evaluation harness instead of marketing accuracy numbers.
2. **Deterministic spine, bounded intelligence.** A typed, checkpointed orchestration state machine drives flow; LLMs are confined to scoped reasoning tasks; deterministic enrichment runs before any model call. Controls hallucination, cost, and reproducibility-of-the-decision-path (note: LLM token output itself is *not* bit-reproducible — see §4.4).
3. **Human-in-the-loop by default; least privilege always.** Read/triage-first agents; any state-changing action is Guardian-gated (allow/deny/modify/ask/defer, default *ask/deny*), blast-radius-limited, reversible, and fully audited. Guardrails map to explicit OWASP LLM/ASI/AISVS/MCP IDs.
4. **In-network & model-agnostic.** Runs on localhost or air-gapped K8s; any LLM provider, switchable anytime; built-in Ollama bootstrap; no-key offline mode. First-class, opt-in case memory (local folder, pgvector, or external DB/VM).
5. **Tenant-aware and integration-first from day one.** A `tenant_id` boundary is carried by every core object from the first commit (default tenant on localhost). Capability-declaring connector SDK + working reference connectors; OCSF-normalized events; STIX/TAXII intel; Sigma + ATT&CK detection content; tools exposed over MCP. Easy to connect; honest about each connector's limits.

**What would make it award-winning (the bets beyond table stakes):**
- A **glass-box case ledger**: tamper-evident, replayable reasoning — the antidote to the industry's #1 complaint (opacity/trust).
- A **built-in evaluation harness that reports the false-negative rate** *and* per-case cost — honesty as a headline feature; published numbers come from a named, pinned model with a documented dataset (§6).
- **Regulatory-clock awareness** (DORA 4h/24h, NIS2 24h/72h, GDPR 72h, SEC 4 business days) tracked per case by the MGR agent.
- A **Guardian/ACS agent-safety layer with an AgBOM** (Agent Bill of Materials) — the platform secures *its own agents*, mapped to OWASP Agentic Top 10.
- **GDPR-respecting immutability**: an append-only ledger that still honors erasure via crypto-shredding (§4.3) — most append-only audit systems can't.
- A true **coworker UX** (it explains itself, cites evidence, asks for approval) — not another SOC console.

---

## 1. Goals & non-goals

**Goals**
- G1. Autonomously perform **Tier-1 triage** on alerts from heterogeneous sources: dedup, normalize (OCSF), enrich, reason, and assign a **verdict class** (`benign / false_positive / suspicious / malicious / inconclusive`) plus a **routing disposition** (`auto_close / escalate / await_approval`) **with cited evidence** and a confidence score (FR-31).
- G2. Ship a **swarm of specialized agents + an orchestrator/superagent**, built in staged milestones. The **deeply-built core-5 triage wedge** (L1, L2, INTEL, FUSION, RESP) + a documented **Agent SDK/interface** is the first-cut gate; the **remaining 9 agents** (WATCH, HUNT, DET, VULN, INSIDER, COMMS, RPT, MAINT, MGR) are built in subsequent milestones, each to the **same depth bar** (§4.6 defines "deeply implemented"). All 14 are in scope; none is a stub at release of its milestone.
- G3. Be **self-hostable and in-network**: one-command localhost, deployable to K8s/air-gap; all data stays on the user's infrastructure.
- G4. Be **model-agnostic** (Anthropic / OpenAI / Azure / local Ollama/vLLM), switchable anytime, with an Ollama bootstrap and a deterministic **offline mode** needing no key.
- G5. Make **integration easy**: a capability-declaring connector SDK + working reference connectors, MCP-native.
- G6. Provide a **first-class, opt-in memory subsystem** (local folder / pgvector / external DB/VM) of compacted past cases with metadata for fast recall.
- G7. Be **safe by construction**: Guardian-gated actions, human-in-the-loop, injection-resistant, fully audited; guardrails mapped to OWASP/NIST/AISVS.
- G8. Give L2/L3 analysts a **coworker dashboard** (not a SOC dashboard): evidence timelines, reasoning traces, verdicts, and one-click approvals, with live updates.
- G9. Ship **enterprise hardening**: SSO (OIDC + SAML), SCIM, MFA, fine-grained RBAC/ABAC, secrets management, multi-tenant isolation, signed images, SBOM.
- G10. Be **honest and measurable**: a reproducible evaluation harness with documented datasets, an explicit "what it can & cannot do" doc, and an AISVS self-assessment.

**Non-goals (deliberately out of scope)**
- N1. **Not a SIEM/EDR/log store.** We ingest from and act through them; we do not replace Wazuh/Elastic/Splunk/CrowdStrike.
- N2. **Not a SOAR playbook builder.** We orchestrate reasoning, not a drag-and-drop automation studio (we *align* to CACAO/OpenC2 conceptually and can export).
- N3. **Not fully autonomous response.** Containment is always proposed and gated; no lights-out auto-remediation of high-impact actions.
- N4. **No vendor data exfiltration / telemetry phone-home.** Ever.
- N5. **No unaudited accuracy claims.** We provide the measuring tool and the method, not a marketing number.
- N6. **Not a threat-intel platform or ticketing system of record.** We integrate with MISP/OpenCTI and ITSM; we don't reimplement them.
- N7. **Not offensive tooling.** Defensive triage only.

---

## 2. Users & jobs-to-be-done

- **Primary — L2/L3 SOC analyst / investigator.** *"Do the repetitive first-pass work for me, show me your evidence and reasoning, and let me approve anything risky."* Lives in the case-detail coworker view.
- **SOC manager / CISO (mid-size, understaffed, in-house SOC).** *"Cut alert fatigue and MTTR without adding headcount, keep data in-network, and give me defensible audit + compliance-clock reporting."* Lives in roster/metrics/reports.
- **Detection engineer / threat hunter.** *"Help me write and tune detections, measure ATT&CK coverage, and run hypothesis-driven hunts."* Uses DET/HUNT.
- **Platform / security engineer (the adopter).** *"Let me stand this up on localhost in minutes, connect my systems, run it air-gapped, and trust its guardrails."* Uses connectors, deploy, Guardian, secrets.
- **Regulated-enterprise compliance owner.** *"Prove we met the DORA/NIS2/GDPR/SEC clock and show the evidence trail — and honor an erasure request."* Uses MGR/RPT + ledger.

**Primary user in one line:** the overworked L2/L3 analyst who needs a trustworthy junior colleague, not another dashboard.

---

## 3. Functional spec (testable requirements)

Each FR is verifiable and maps to a stage (§5). Severity: **[MUST]** (first-cut), **[MUST-ENT]** (must, at the enterprise stage), **[SHOULD]**.

**Ingestion & normalization**
- FR-1 [MUST] Accept alerts via (a) HTTP webhook, (b) syslog, (c) file/dir watch, (d) connector pull. Each ingress is authenticated/validated and carries a `tenant_id`.
- FR-2 [MUST] Normalize every inbound event to the internal **OCSF-based schema** (targeting OCSF 1.9), retaining the raw original. Mapping is version-pinned and contract-tested.
- FR-3 [MUST] Deduplicate and group alerts into **Cases**; preserve provenance (source, connector, timestamps: event vs ingest).

**Orchestration kernel**
- FR-4 [MUST] A typed, deterministic, **checkpointed state machine** drives each Case through a lifecycle (`new → triaging → investigating → awaiting_approval → responding → resolved/escalated/closed`), persisting state after every node. Every object carries `tenant_id`.
- FR-5 [MUST] Support **human-in-the-loop interrupts**: a run can suspend awaiting approval/input and **resume deterministically, re-entering the exact node** with restored typed state.
- FR-6 [MUST] Every state transition, tool call, model call, agent decision, and human action writes a **hash-chained, append-only ledger entry** (who/what/when/why, correlation + trace IDs, model id+digest, prompt hash, input/output refs, per-call token+cost). PII is stored via crypto-shredding/tokenization (FR-44), not inline; **all retained hashes/digests are computed over ciphertext or tokenized refs, never over raw PII plaintext** (so surviving hashes aren't brute-forceable after a shred). The ledger is **time-partitioned** with a configurable **retention/archival** policy (hot in Postgres → cold/archived), and ledger write-volume + pruning is covered by the scale test (FR-34).
- FR-7 [MUST] A Case run is **replayable from the ledger**: the decision path and evidence are reconstructable, and ledger integrity is cryptographically verifiable. (This is replay-of-the-record, not a claim that an LLM re-run yields identical tokens.)

**LLM provider gateway**
- FR-8 [MUST] A provider gateway exposes one interface over adapters for **generation, embeddings, and reranking**: **Anthropic**, **OpenAI-compatible** (covers OpenAI/Azure/Ollama/vLLM/LM Studio/OpenRouter), **Ollama-native**, and a deterministic **mock/offline** provider. Embeddings + a reranker must have **local/offline variants** (e.g. a local embedding model + bge-reranker via Ollama/TEI) so memory retrieval works air-gapped.
- FR-9 [MUST] The active provider/model is **configurable and switchable at runtime** (config + UI) without restart; per-agent model overrides allowed.
- FR-10 [MUST] **Offline mode** runs the full triage pipeline with no external key (mock provider + deterministic enrichment), so localhost works instantly. Offline-mode verdicts are explicitly labeled non-inferential (they test the *pipeline*, not model quality).
- FR-11 [SHOULD] **Ollama bootstrap**: a CLI/UI action pulls a recommended local model and warms it; progress streamed.
- FR-12 [MUST] Every model call records model id + digest + params + token/cost for auditability and replay. Seed/temperature are pinned where the provider supports it; the platform does **not** promise bit-identical model output.

**Connectors**
- FR-13 [MUST] A **Connector SDK**: each connector declares capabilities (`read_alerts`, `query`, `enrich`, `act`) and, for actions, **reversibility + required scope**.
- FR-14 [MUST] Reference connectors shipped and tested: **ingester** (webhook/syslog/file), **mock SIEM**, **mock EDR**, **Wazuh** (API + indexer read; active-response act), **Elastic/OpenSearch** (Detections read + endpoint response-actions act).
- FR-15 [MUST] Intel-enrichment reference connectors: **MISP** and **OpenCTI** (STIX/TAXII), plus a pluggable indicator-lookup interface; offline local-feed support.
- FR-16 [MUST] **MCP client**: consume external MCP tool servers as connector tools, with tool-manifest **fingerprint pinning** (rug-pull defense) and schema validation.
- FR-17 [SHOULD] Optionally **expose blue-kakapo tools as an MCP server** (gated, authenticated).
- FR-18 [MUST] Every connector that wraps a query engine provides a **native-query escape hatch** (pass-through SPL/KQL/ES\|QL/FQL) alongside any abstracted query. (N/A for connectors with no query surface, e.g. mocks/webhook.)
- FR-19 [SHOULD] A **CVE/KEV exposure feed** connector (for VULN) and a **detection inventory** source (for DET coverage deltas) — see their agent stages.

**Guardian (safety layer)**
- FR-20 [MUST] Every state-changing action passes through the **Guardian**, which returns an **ACS disposition** (allow/deny/modify/ask/defer) via the decision schema in §4.7; default is **ask/deny**, never fail-open.
- FR-21 [MUST] Guardian enforces: capability gating, **asset allow/deny** keyed to the Asset Inventory (§4.8; e.g. never auto-isolate assets tagged `critical`/`crown_jewel`), **blast-radius caps** (max simultaneous actions / window), **maker-checker** approval for high-impact, **dry-run/simulation**, **idempotency keys**, **time-boxed/auto-expiring** containment, and **break-glass** with full audit.
- FR-22 [MUST] All tool/retrieved/alert content is treated as **untrusted data, never instructions** (prompt-injection handling); agent outputs are schema-validated before use (improper-output-handling defense).
- FR-23 [MUST] Enforce the **Rule of Two**: no single agent simultaneously (a) processes untrusted input, (b) holds sensitive access, and (c) can change external state — the Guardian breaks at least one leg.
- FR-24 [MUST] Maintain an **AgBOM** per agent (tools, models, connectors, data scopes, permissions) and surface it.

**Memory subsystem**
- FR-25 [MUST] Memory backends: **folder** (embedded, file-based, for the UI-linked local folder) and **pgvector** are first-cut; **external** (Qdrant/DB/VM) ships behind the same interface at a later stage. Configurable per tenant.
- FR-26 [MUST] On Case resolution, store a **compacted case record** (features, steps, verdict, outcome, analyst notes) + metadata (tenant, ATT&CK technique, asset, severity) + **embedding model id/version**.
- FR-27 [MUST] Retrieve similar past cases via **hybrid search (dense pgvector + lexical) + reranking** with tenant-scoped metadata filters. Lexical scoring uses a named mechanism — **ParadeDB/pg_search (true BM25)** where available, otherwise Postgres FTS `ts_rank` as a documented approximation (not called "BM25"); the reranker uses the gateway's local/offline variant (FR-8).
- FR-28 [MUST] Memory use is **opt-in per case** (toggle honored); a local folder can be created/linked **from the UI**.
- FR-29 [MUST] Memory-poisoning defenses (ASI06): every record carries **provenance + a trust tier**; agent-authored memories are **quarantined** (not retrievable for decisioning until promoted); retrieval **down-weights** low-trust/aged records (decay). A changed embedding model triggers a **re-embed migration** (version mismatch is detected, not silently mixed).

**Agents (see §4.6 for each; "deeply implemented" defined there)**
- FR-30 [MUST] Implement the **core-5** (L1, L2, INTEL, FUSION, RESP) + orchestrator deeply, plus a documented **Agent SDK** that the remaining agents implement. Each agent: defined triggers, typed inputs/outputs, declared tools, bounded LLM reasoning, deterministic-first enrichment, confidence output, explicit **autonomy level** (read-only / propose / act-on-approval), and per-agent acceptance criteria.
- FR-31 [MUST] L1 produces a **verdict class** (`benign | false_positive | suspicious | malicious | inconclusive`) — kept distinct from the **disposition/routing action** (`auto_close | escalate | await_approval`) for clean metrics — with **cited evidence** and a confidence score **whose calibration the eval harness measures** (temperature/Platt/isotonic against the eval set; we do not assert raw LLM self-confidence is calibrated). FP-closure requires evidence, is logged, and is reversible (re-openable).
- FR-32 [MUST] RESP executes containment **only** via Guardian + human approval; supports dry-run and reversal.
- FR-33 [MUST (its stage)] MGR tracks **regulatory clocks** (DORA/NIS2/GDPR/SEC) per qualifying case and flags deadlines.

**Scale & cost**
- FR-34 [MUST] Sustain the design target of **≥5,000 alerts/day** ingest with bounded concurrent-case parallelism and **backpressure** (no unbounded queue growth under flood); a load/flood test proves it.
- FR-35 [MUST] Record **per-case token and cost** in the ledger and expose **cost-per-case** in metrics and the eval harness (backs the "predictable cost" claim).

**AuthN/Z, multi-tenancy, secrets**
- FR-36 [MUST] Local admin auth for localhost (available from S7); **OIDC** SSO [MUST-ENT]; **SAML** SSO + **SCIM** provisioning/deprovisioning [MUST-ENT]; **MFA/passkeys** [SHOULD].
- FR-37 [MUST] Fine-grained **per-action, per-asset, per-tenant** authorization (RBAC/ABAC); a low-privilege role cannot approve/execute containment.
- FR-38 [MUST] **Secrets** via OpenBao/Vault (or encrypted local store for localhost); connector creds never in images/logs; injected at runtime; rotatable.
- FR-39 [MUST] **Multi-tenant isolation**: `tenant_id` is enforced across data access, authz, memory retrieval, connector-credential scoping, and ledger partitioning. (Carried from S1; hardened at the enterprise stage.)

**Dashboard (coworker UX)**
- FR-40 [MUST] Case **inbox/triage queue**; **case-detail coworker view** (alert, evidence timeline, agent reasoning trace, verdict + confidence, recommended actions with approval buttons); **agent roster/activity**; **memory browser**; **connector setup wizard**; **approvals inbox**; **settings** (provider switch, Ollama bootstrap); **reports**.
- FR-41 [MUST] **Live updates** via WebSocket; responsive; dark mode; WCAG-AA contrast.
- FR-42 [MUST] Every verdict renders an **explainable verdict card** (evidence-cited, shareable/exportable).

**Evaluation, privacy & observability**
- FR-43 [MUST] An **evaluation harness** runs the triage pipeline against labeled datasets and reports precision, recall, **false-negative rate**, calibration, and **cost-per-case**. Published numbers are produced by a **named, pinned model** and are reproducible; the **bundled synthetic dataset** has documented construction/labeling/coverage and its numbers are labeled an **illustrative floor, not a real-world claim**. CI runs the harness *mechanics* on deterministic fixtures (not to publish accuracy).
- FR-44 [MUST] **Erasure-respecting storage**: alert/case PII is stored encrypted with **per-record keys** (crypto-shredding) and/or tokenized, so a GDPR erasure request destroys the key/token mapping while the hash-chained ledger stays verifiable over hashes/ciphertext. Per-record keys live in the **secrets store (OpenBao) or a dedicated keystore**, and key destruction must be **irreversible including backups** (a key-DB backup must not silently undo an erasure — documented backup/rotation policy). An erasure API exists and is tested.
- FR-45 [MUST] **OpenTelemetry** traces/logs/metrics; structured JSON logs; health/readiness endpoints.
- FR-46 [SHOULD] **Ledger external anchoring**: optionally anchor periodic ledger checkpoints to WORM/object-lock storage so tampering by a DB admin is detectable (not just partial tampering).

**Deployment**
- FR-47 [MUST] **Docker Compose** one-command localhost (API, DB+pgvector, frontend, optional Ollama).
- FR-48 [MUST-ENT] **Helm chart** for K8s; **cosign-signed images** + **SBOM**; air-gap bundle (Zarf) documented [SHOULD].

---

## 4. Architecture

### 4.1 System overview (data flow)

```
                         ┌─────────────────────────────────────────────┐
  Alert sources          │                 blue-kakapo                  │
  (SIEM/EDR/webhook ─────┼─▶ Connectors ─▶ Ingestion/Normalize (OCSF)   │
   /syslog/MCP)          │     (SDK)            │  (+tenant_id)          │
                         │                      ▼                       │
                         │        Case store (Postgres+pgvector) ◀─ Asset Inventory
                         │                      │                       │
                         │        ┌─────────────▼──────────────┐        │
                         │        │   Orchestrator / Superagent │        │
                         │        │  (deterministic state machine,       │
                         │        │   checkpointing, HITL, routing)      │
                         │        └───┬───────────────┬─────────┘        │
                         │            │   via Guardian│ (ACS gate +       │
                         │            │               │  policy engine)  │
                         │       ┌────▼────┐     ┌────▼─────┐            │
                         │       │  Agent  │ ... │  Agent   │  (core-5 + orch,
                         │       │ subgraph│     │ subgraph │   then +9 via SDK)│
                         │       └────┬────┘     └────┬─────┘            │
                         │      tools │ (bounded LLM, deterministic      │
                         │            ▼  enrichment, typed outputs)      │
                         │   Provider Gateway        Memory subsystem    │
                         │  (Anthropic/OpenAI/        (folder/pgvector/  │
                         │   Ollama/offline)           external)         │
                         │            │                                  │
                         │            ▼                                  │
                         │   Case Ledger (hash-chained, append-only, ◀── everything writes here
                         │    crypto-shredded PII, token/cost)           │
                         │            │                                  │
                         │   Control-plane API (FastAPI + WebSocket) ◀──▶ Coworker Dashboard (React)
                         └─────────────────────────────────────────────┘
   Cross-cutting (tenant-aware from S1): AuthN/Z (OIDC/SAML/SCIM/RBAC/ABAC) · Secrets (OpenBao) · OTel · multi-tenancy
```

**Trust boundaries & where untrusted input enters:** alert/log/intel content and external MCP tool output are **untrusted** (attacker-shapeable) → sanitized, treated as data, schema-validated; the Guardian sits on the egress boundary (any action to a connector). Operator config and chat from authenticated users are trusted inputs. Model outputs are semi-trusted → validated before any side effect.

### 4.2 Repository layout (monorepo)

```
blue-kakapo/
  apps/
    api/            # FastAPI control plane + WebSocket (Python)
    web/            # React + Vite coworker dashboard (TypeScript)
  packages/
    core/           # orchestration kernel, case model, ledger, event bus, tenancy
    agents/         # orchestrator + agents (core-5 deep, then +9) + Agent SDK
    connectors/     # Connector SDK + reference connectors + MCP client/server
    providers/      # LLM provider gateway + adapters (incl. offline)
    memory/         # memory subsystem + backends (folder/pgvector/external)
    guardian/       # ACS policy engine, AgBOM, injection/output guards
    assets/         # asset inventory + entity resolution
    schema/         # OCSF-based models, STIX helpers, Sigma/ATT&CK utils
    eval/           # evaluation harness + bundled labeled datasets + methodology
  deploy/
    compose/        # docker-compose.yml + .env.example
    helm/           # Helm chart, values, signed-image + SBOM tooling
    zarf/           # air-gap bundle definition
  docs/             # docs + site source (Phase 4)
  finding.md  build-plan.md  BUILD_LOG.md  HANDOFF.md  README.md  SECURITY.md  LICENSE
```

### 4.3 Key data models (typed; Pydantic v2 / TS mirror). All carry `tenant_id`.

- **Event (OCSF)** — normalized; `raw` retained (PII-tokenized); `class_uid`, `activity_id`, `metadata`, `observables`, `time`, `source`.
- **Alert** — one or more Events + detection context (rule, source, severity, ATT&CK techniques).
- **Case** — the unit of work: `id`, `tenant_id`, `state`, `alerts[]`, `entities[]` (resolved host/user/ip), `verdict`, `confidence`, `evidence[]`, `attack_techniques[]`, `regulatory_clocks[]`, `assignee`, `cost{tokens,usd}`, timestamps.
- **Evidence** — a cited fact: `source`, `connector`, `query`, `result_ref`, `supports` (which claim), `collected_at`.
- **LedgerEntry** — `seq`, `prev_hash`, `hash`, `tenant_id`, `actor` (agent/human/system), `action`, `inputs_ref`, `outputs_ref` (refs point to crypto-shredded blobs), `model{id,digest,params,tokens,usd}`, `disposition`, `trace_id`, `ts`.
- **Disposition** — `allow|deny|modify|ask|defer`, `reason`, `policy_id`, `required_approvals`, `reversibility`, `modified_action?` (present when `modify`).
- **AssetRecord** (§4.8) — `id`, `tenant_id`, `identifiers[]` (hostname/FQDN/IP/MAC/asset-tag/UPN/SID), `criticality` (`low|normal|high|critical|crown_jewel`), `tags[]`, `owner`, `source`.
- **MemoryRecord** — `case_summary` (compacted), `features`, `metadata{tenant,technique,asset,severity}`, `embedding`, `embedding_model`, `embedding_version`, `provenance`, `trust_tier`, `created_at`, `decay`.
- **AgBOM** — per-agent: `tools[]`, `models[]`, `connectors[]`, `data_scopes[]`, `permissions[]`.
- **PiiToken** — maps a token/ref to a **per-record encryption key**; destroying the key (crypto-shred) renders the referenced blob unrecoverable without breaking the ledger hash chain.

### 4.4 The orchestration kernel (specified; time-boxed build-vs-adopt)

A small, typed, deterministic state-machine engine. **Interface (concrete):**
- **Node** = `async fn(ctx: RunContext[State]) -> NodeResult` where `NodeResult` ∈ `{Goto(node, state'), Suspend(reason, resume_token), Done(state'), Fail(err)}`. A node is either deterministic or performs **one** bounded LLM/tool call.
- **Graph** = typed nodes + typed edges; `State` is a Pydantic model serialized to JSON for checkpoints.
- **Checkpoint**: after every node, `(run_id, tenant_id, node_id, state_json, seq)` is persisted (Postgres). A crash resumes from the last checkpoint.
- **Suspend/resume**: `Suspend` persists a `resume_token`; an external event (approval, input) calls `resume(run_id, token, payload)`, which **re-enters the exact node** with the restored `State` + payload. Idempotent on duplicate resume.
- **Concurrency**: a `parallel([nodes])` combinator runs child nodes with isolated state slices and a typed join; per-node timeout + retry policy (max attempts, backoff) is declared on the edge.
- **Sub-graphs**: an agent is a graph; the orchestrator composes agent graphs as callable nodes with explicit input/output state contracts (no shared mutable global — state is passed, not ambiently mutated → auditable).
- **Ledger hook**: the kernel emits a LedgerEntry on every node entry/exit, tool call, and model call.

**Decision — build vs. adopt (time-boxed):** we start by building this focused kernel because it gives total control of the Guardian gate, the hash-chained ledger, and ledger-based replay. **Guardrail (concrete budget):** the kernel core (nodes/edges/state/checkpoint/suspend-resume/parallel/ledger-hook, excluding tests) is budgeted at **≤ ~1,500 LOC and ≤ ~1 week of build time**; **if it exceeds either during S1, we fall back to LangGraph (MIT, Apache-compatible) and wrap it with our Guardian + ledger + tenancy**, since LangGraph already provides graph + Postgres checkpointing + HITL interrupts. The decision is recorded in `BUILD_LOG.md`. The license/control argument is a *preference*, not a hard requirement — we will not reinvent a mature framework at the cost of the timeline. **Pydantic-AI (MIT)** is used inside nodes for typed, model-agnostic structured outputs / tool calls regardless of which kernel path we take. *(Reproducibility: the decision path is replayable from the ledger; we do not claim bit-identical LLM output — hosted and batched-local inference are not deterministic even at temp=0.)*

### 4.5 Tech choices + rationale

| Area | Choice | Rationale | Rejected |
|------|--------|-----------|----------|
| Backend language | **Python 3.11+** | Security + LLM/agent/MCP ecosystem; async | Go (less LLM ecosystem) |
| API | **FastAPI + Uvicorn** | Async, typed (Pydantic), native WebSocket | Flask/Django (heavier/sync) |
| Typed models | **Pydantic v2** | One schema for API, LLM I/O, DB mapping | dataclasses (no validation) |
| Agent LLM calls | **Pydantic-AI** (lib) + our provider gateway | Typed structured outputs, model-agnostic, MIT | LangGraph/CrewAI as core (lock-in) |
| Orchestration | **Purpose-built kernel, time-boxed; LangGraph fallback** | Control of Guardian/ledger/replay; adopt if it balloons | hard dependency either way |
| Primary store | **PostgreSQL 16 + pgvector 0.8.x** | Cases + events + ledger + vectors in one txn store → RBAC/tenancy | separate vector DB by default |
| Local memory | **embedded file store** (sqlite-vec / LanceDB) in the linked folder | Matches "link a folder" UX; no server | forcing Postgres for pure-local |
| Event bus/queue | **in-process + Postgres-backed** default; pluggable Redis/NATS | Zero extra infra on localhost; scales later (see FR-34) | mandatory Kafka |
| LLM providers | gateway adapters: **Anthropic, OpenAI-compatible, Ollama, offline-mock** | Covers cloud + local + air-gap + instant demo | single-provider lock-in; litellm (heavy dep) |
| Frontend | **React + Vite + TypeScript** | Fast, typed, ecosystem; dark analyst-console UI | SSR framework (unneeded) |
| Styling | **Tailwind + minimal component layer** | Fast, consistent dark theme, a11y control | heavy UI kit |
| Secrets | **OpenBao** (+ encrypted local for dev) | LF/MPL-2.0, Vault-compatible, truly OSS | Vault (BUSL) as default |
| Authz policy | built-in RBAC/ABAC; **OPA/OpenFGA** optional | Works out-of-box; scales to fine-grained | mandatory external PDP |
| SSO | **OIDC + SAML + SCIM** (Authlib/python3-saml); Keycloak/Dex friendly | Enterprise table stakes | OIDC-only |
| Observability | **OpenTelemetry** + structured logs | Standard, SIEM-exportable audit | bespoke logging |
| Tests | **pytest** (+ hypothesis), **vitest** + **Playwright** | Unit/property/e2e | — |
| CI | **GitHub Actions** | Lint (ruff), type (mypy/pyright, tsc), test, Sigma-CI, image sign + SBOM | — |
| Deploy | **Docker Compose** + **Helm 3** + **Zarf** | Localhost → K8s → air-gap | — |

**Dependency discipline:** every runtime dependency is justified; the ledger, Guardian, connector SDK, asset inventory, and (unless we invoke the LangGraph fallback) the kernel are first-party. No telemetry/phone-home dependency is permitted.

### 4.6 The agent roster (orchestrator + 14, staged by depth)

**Agent SDK (frozen interface the 9 staged agents build against):** an agent is `class Agent` declaring `name`, `autonomy_level`, an `AgBOM`, and `input_schema`/`output_schema` (Pydantic), implemented as a kernel sub-graph with `async def run(ctx: RunContext[AgentState]) -> AgentOutput`; it declares its **tools** (connector capabilities + MCP tools) and may call `ctx.memory.recall(...)` (opt-in), `ctx.llm(...)` (gateway, bounded), and `ctx.guardian.check(action)` before any state-changing call. Outputs are schema-validated and evidence-cited. This contract is frozen at S6 so S9 agents build against a stable surface.

**"Deeply implemented" acceptance bar (applies to every agent at its milestone):** (1) a typed input/output contract and an AgBOM; (2) deterministic-first enrichment before any LLM call; (3) bounded, scoped LLM steps (no open-ended autonomy); (4) evidence-cited, schema-validated outputs with a calibrated confidence; (5) declared autonomy level enforced by the Guardian; (6) ≥1 happy-path + ≥2 adversarial tests (incl. an injection case) and an entry in the eval harness or a dedicated functional check; (7) documented limits.

Each agent: **role · trigger · inputs · tools · bounded-LLM reasoning · typed output · autonomy · key guardrails (OWASP IDs) · dependencies.** All are read/propose-only except RESP; all write to the ledger; all can consult memory if opted-in.

**Orchestrator / Superagent (the conductor)** — owns the Case state machine, routes to agents, enforces sequencing, applies the Guardian, manages HITL/checkpointing, balances concurrency + backpressure. Autonomy: system. Guards: ASI07 (inter-agent comms integrity), ASI08 (cascading-failure circuit breakers), ASI10 (rogue-agent containment).

#### Core-5 (deeply built in the first cut — the Tier-1 triage wedge)
1. **L1 — Triage & intake.** Trigger: new alert/case. Deterministic dedup/normalize/scoring first, then a bounded reasoning step for an initial verdict (benign/FP/suspicious/escalate) with cited evidence + confidence. Autonomy: propose (auto-close FPs only above a confidence threshold, reversible, logged). Guards: LLM01, LLM07, conservative escalation bias.
2. **L2 — Investigation.** Trigger: escalation from L1. Multi-step pivots across connectors; builds the incident narrative; deepens evidence. Autonomy: propose. Guards: Rule-of-Two, query scoping, injection handling.
3. **INTEL — Adversary context.** Trigger: entities/IOCs present. Enriches via MISP/OpenCTI/STIX; maps to ATT&CK techniques, actors, campaigns. Autonomy: propose (read-only external intel). Guards: untrusted intel content, source provenance.
4. **FUSION — Links signals & campaigns.** Trigger: new/updated cases. Correlates/clusters related alerts/cases into incidents/campaigns via **entity resolution** (§4.8); entity-graph building. Autonomy: propose. Guards: ASI06.
5. **RESP — Containment.** Trigger: approved response plan. Executes isolate-host / disable-user / block-IOC / kill-process **only** through Guardian + human approval; dry-run first; reversible; time-boxed. Autonomy: **act-on-approval only**. Guards: LLM06/ASI02/ASI03, blast-radius, maker-checker, break-glass, full audit. Deps: Asset Inventory.

#### Staged roster (subsequent milestones, each to the same depth bar)
6. **WATCH — Early warning.** Continuous stream scan: bursts/anomalies/emerging patterns → proactive cases. Autonomy: propose. Guards: unbounded-consumption limits, rate control. Deps: ingest stream + backpressure (FR-34).
7. **HUNT — Proactive hunting.** Hypothesis/scheduled/analyst-initiated; generates + runs hunt queries (native-query escape hatch) → cases. Autonomy: propose (read/query only). Guards: query cost caps.
8. **DET — Detection engineering.** Proposes/tunes **Sigma** rules, measures ATT&CK coverage deltas, reduces FPs. Autonomy: propose (human-merge, no auto-deploy). Guards: detection-as-code review. Deps: a **detection inventory** source (FR-19).
9. **VULN — Exposure management.** Correlates exposure with assets + active threats; prioritizes. Autonomy: propose. Guards: data minimization. Deps: **Asset Inventory + CVE/KEV feed** (FR-19).
10. **INSIDER — Insider risk.** UEBA-style anomaly reasoning; **privacy-gated** (minimization, purpose limitation, access controls). Autonomy: propose. Guards: **OWASP GenAI Data-Security controls** (data governance/PII handling), strict RBAC.
11. **COMMS — Keeps you informed.** In-app notifications + case summaries; drafts external messages — **external send requires human approval**. Autonomy: propose/act (internal only). Guards: LLM02 redaction.
12. **RPT — Reporting & insight.** Incident, compliance (DORA/NIS2/SEC/GDPR), and metrics (MTTD/MTTR, FP rate, cost-per-case) reports from the ledger. Autonomy: propose. Guards: evidence-cited, no fabrication.
13. **MAINT — Keeps the SOC seeing.** Monitors connector/detection/pipeline health; flags **detection decay** and data-source gaps. Autonomy: propose. Guards: least privilege.
14. **MGR — Runs the shift.** Workload balancing, prioritization, escalation routing, SLA + **regulatory-clock tracking** (FR-33). Autonomy: propose/orchestrate (no external actions). Guards: fairness/consistency, audit.

### 4.7 The Guardian policy model

- **Policy language:** a built-in, typed **policy DSL** (declarative rules over a typed decision input) as the default, with an **OPA/Rego** adapter for teams that want external policy-as-code. Policies are versioned and carry a `policy_id`.
- **Decision input schema:** `{ tenant_id, actor (agent/human + roles), action (verb + target + args), asset (from Asset Inventory incl. criticality/tags), context (case, confidence, blast_radius_estimate, time), connector_capabilities }`.
- **Decision output:** a `Disposition` (§4.3). **`modify` contract:** the Guardian returns a `modified_action` (a fully-formed, re-validated action, e.g. downgrade "isolate host" → "isolate host for 1h with auto-expiry" or narrow an IOC block scope); the caller must execute the modified action or nothing, never the original. `ask`/`defer` create an approval task; `deny` blocks with reason; `allow` proceeds. Default on policy gap or error = **ask** (never fail-open).
- **Where asset criticality comes from:** the Asset Inventory (§4.8), populated via connectors/CMDB import or manual tagging; unknown assets default to a conservative criticality.

### 4.8 Asset inventory & entity resolution

- **Asset Inventory:** an `AssetRecord` store (§4.3) populated from connector data (EDR/SIEM host lists), optional CMDB import, and manual tagging. Drives Guardian blast-radius rules and VULN prioritization.
- **Entity resolution (for FUSION/Case entities):** a **deterministic first pass** — normalize and match on strong identifiers (exact IP-in-window, FQDN↔hostname, MAC, UPN↔email, SID), with configurable rules and an explicit confidence on each merge. Ambiguous merges are surfaced, not silently assumed. (Probabilistic/ML stitching is a documented non-goal for v1.)

---

## 5. Milestones / stages (the build order)

Sequenced so a **real end-to-end triage slice exists at S2**, then layers grow horizontally onto a working loop. `tenant_id` is threaded from S1. Each stage ends with a committed, tested increment and a `BUILD_LOG.md` note.

| Stage | Ships | Satisfies | Acceptance check (exit) |
|------|-------|-----------|-------------------------|
| **S0 Foundations** | Monorepo, Apache-2.0, CI (lint/type/test), Docker Compose skeleton, Postgres+pgvector, config, provider gateway (incl. offline), tenant-aware base data models, OTel/logging | FR-8/10/12/45/47 | `docker compose up` → API+DB+web shell healthy; provider gateway + offline mode unit-tested; `tenant_id` present in base models |
| **S1 Kernel + Ledger** | Deterministic checkpointed state machine (per §4.4 interface), case lifecycle, event bus, hash-chained append-only ledger with crypto-shredded PII + token/cost fields, replay, HITL suspend/resume. **Kernel time-box decision point** (build vs LangGraph fallback). | FR-4/5/6/7/44 | Graph runs, persists, resumes into the exact node after interrupt; ledger hash-chain verifies; replay reconstructs the path; crypto-shred erases a record without breaking the chain |
| **S2 Walking skeleton (first vertical slice)** | **One ingest source → OCSF normalize → L1 bounded-LLM verdict → ledger → minimal verdict view.** End-to-end, offline-mode capable. | FR-1/2/3/31 + a thin slice of FR-40/42 | A posted alert yields a tenant-scoped Case with an L1 verdict + cited evidence, visible in a minimal UI, recorded in the ledger — on a fresh machine, no API key |
| **S3 Connectors + ingestion depth** | Connector SDK, ingester (webhook/syslog/file), mock SIEM/EDR, full OCSF normalization, Wazuh + Elastic/OpenSearch, MCP client w/ fingerprint pinning | FR-13/14/15/16/18 | Alerts flow from ≥3 sources → OCSF → Cases; connector contract tests pass; MCP tool consumed safely with manifest pinning |
| **S4 Guardian + Asset Inventory** | ACS policy engine (DSL + OPA adapter), decision schema, `modify` contract, asset inventory, capability gating, asset allow/deny, blast-radius, maker-checker, dry-run, idempotency, time-box, break-glass, injection/output guards, Rule-of-Two, AgBOM | FR-19(assets)/20/21/22/23/24 + §4.7/4.8 | Guardian asks/denies/ modifies high-impact actions in tests; indirect-prompt-injection suite passes; no action reaches a connector without a disposition + ledger entry; never-isolate-crown-jewel honored |
| **S5 Memory** | folder + pgvector backends, compacted case records (+embedding version), hybrid retrieval + rerank + tenant-scoped filters, UI folder-link flow, opt-in per case, poisoning defenses (provenance/trust-tier/quarantine/decay), re-embed migration | FR-25/26/27/28/29 | Resolve case → stored; similar alert retrieves it; opt-in honored; agent-authored memory quarantined; embedding-version mismatch triggers migration; poisoning-guard test passes |
| **S6 Core-5 depth + eval harness** | **L1, L2, INTEL, FUSION, RESP** to the depth bar + **Agent SDK**; entity resolution; confidence calibration; ATT&CK mapping; evaluation harness v1 (datasets + methodology + cost-per-case) | FR-30/31/32/43/35 + G1 | End-to-end alert→triage→investigate→correlate→context→verdict (evidence+confidence); RESP containment gated + reversible (dry-run + mock EDR); harness reports precision/recall/**FNR**/cost on the documented bundled dataset (labeled illustrative) |
| **S7 Scale + coworker dashboard** | Backpressure + load/flood handling; full React UI: inbox, case-detail coworker view (evidence timeline + reasoning trace + verdict card + approvals), roster/activity, memory browser, connector wizard, approvals inbox, settings (provider switch + Ollama bootstrap), reports; WebSocket live | FR-11/34/40/41/42 | ≥5,000 alerts/day flood test stays bounded; full triage loop usable from UI; live updates; approvals actionable; provider switch + Ollama bootstrap from UI; a11y AA + dark mode verified |
| **S8 Enterprise hardening** | Local admin → **OIDC**, then **SAML + SCIM**, MFA/passkeys; RBAC/ABAC per action/asset/tenant; OpenBao secrets; multi-tenant isolation hardening; Helm chart + signed images + SBOM; Zarf air-gap; ledger external anchoring | FR-36/37/38/39/46/48 | SSO (OIDC+SAML) login works; SCIM deprovision cascades; low-priv role denied containment; tenant isolation test passes; Helm installs on kind/k3d; images cosign-verified; SBOM emitted |
| **S9 Staged roster — proactive & service agents** | **WATCH, HUNT, DET, VULN, INSIDER, COMMS, RPT, MGR, MAINT** to the depth bar; CVE/KEV + detection-inventory connectors; regulatory clocks | FR-19/30/33 (+ each agent's criteria) | Each agent meets the §4.6 depth bar with its acceptance test; MGR tracks DORA/NIS2/GDPR/SEC clocks; DET proposes a Sigma rule + coverage delta; VULN prioritizes by active-threat context; INSIDER runs under privacy controls |
| **S10 Eval, docs, security self-review** | Harness maturity (BYO datasets, reproducible, named-model numbers), red-team/attack test suite, "can & cannot do" doc, full docs, **AISVS self-assessment (L1/L2)**, threat model, SECURITY.md | FR-43 + G10 | DoD (§9) met; AISVS checklist mapped; attack suite green |

Phases 4 (site + deck) and 5 (≥3 adversarial hardening rounds) run after S10 per the skill pipeline.

**Loop discipline:** each stage is a bounded iterative loop — build → test → run/verify → commit. Hard cap of 3 corrective iterations per stage; if two consecutive iterations make no net progress, stop and escalate.

---

## 6. Test strategy

- **Unit** (pytest + hypothesis; vitest): schema mappings (OCSF), provider adapters (incl. offline determinism), ledger hash-chain + crypto-shred, kernel transitions + resume-into-exact-node, Guardian dispositions incl. `modify`, entity resolution, memory retrieval + quarantine, each agent's deterministic steps.
- **Integration**: ingest→normalize→case (tenant-scoped); connector contract tests (mock + Wazuh/Elastic against disposable containers); end-to-end triage pipeline; HITL suspend/resume; approval→RESP→reversal in dry-run.
- **Scale**: a **flood/load test** at ≥5,000 alerts/day equivalent proving bounded queue growth + backpressure (FR-34) and recording cost-per-case.
- **Adversarial / security** (prove the safety claims):
  - **Indirect prompt injection** in alert/log/intel/MCP-tool content → agent must not follow it; Guardian must still gate.
  - **Excessive agency**: un-approved/out-of-policy containment → denied/asked; crown-jewel allow-list honored; `modify` downgrades correctly.
  - **Rug-pull**: changed MCP tool manifest → pinned fingerprint mismatch blocks it.
  - **Memory poisoning**: malicious "past case" → quarantine/trust-tier/decay prevents it steering a verdict.
  - **Output handling**: model emits markup/command-like output → sanitized, never executed/rendered unsafely.
  - **Ledger tamper**: altered entry → chain verification fails; (with anchoring) wholesale recompute is detectable.
  - **Erasure**: GDPR erasure request → PII unrecoverable, ledger chain still verifies.
  - **Tenancy**: cross-tenant read/action attempt → denied.
- **Evaluation harness (claim-proving + honest about itself)**: runs triage on labeled datasets; reports precision, recall, **false-negative rate**, calibration, **cost-per-case**. Published numbers come from a **named, pinned model**, reproduced via a documented command. The **bundled synthetic dataset** ships with its construction/labeling/coverage methodology and its numbers are labeled an **illustrative floor**. CI runs the harness *mechanics* on deterministic fixtures to prove it works, not to publish accuracy.
- **"Self-checks clean"** = ruff + mypy/pyright + tsc clean; all unit/integration/scale/adversarial tests green; `docker compose up` healthy; README quickstart reproduces end-to-end on a fresh machine; AISVS L1 checklist has no undetected-violation gaps mislabeled as "proven".

---

## 7. Docs, site & deck plan

- **README**: one-paragraph pitch, the gap, a 60-second quickstart (`docker compose up` + offline mode), an architecture diagram, the agent roster, the "trust" story (ledger + eval harness), honest limits link, security policy link.
- **Docs** (`docs/`): Install (localhost / K8s / air-gap), Connect-your-systems (connector SDK + each reference connector), Configure LLM providers (incl. Ollama bootstrap + offline), Memory setup (folder/pgvector/external), Guardian & policies, Asset inventory, Agents reference, **Evaluation harness + dataset methodology**, Security model + AISVS self-assessment, GDPR/erasure, **"What it can & cannot do"**.
- **ELI5 page** (non-technical): what a SOC is, why alerts overwhelm people, how blue-kakapo helps like a careful junior colleague that always shows its work and asks before doing anything risky.
- **Site** (Phase 4, GitHub Pages): Home, ELI5, Docs, Architecture, Contact — modern dark "analyst console" aesthetic via `master-designer`.
- **Deck** (README/pitch): problem (sourced stats), the gap, the approach (deterministic spine + glass-box trust), the roster, differentiators, honest limits, roadmap.

---

## 8. Honest limits (written before building)

- **Not a detector of unknown-unknowns.** Triage quality depends on the telemetry and detections feeding it; blue-kakapo reasons over signals, it doesn't replace good detection engineering. *Alert reduction ≠ better detection.*
- **Local-model quality gap.** Small local models reason less well on hard cases than frontier hosted models; offline mode is deterministic/assistive, not frontier-grade. Per-model guidance is provided; no parity is claimed.
- **False negatives remain possible.** No triage system is perfect; our bias is to escalate, and the harness measures the miss rate — but a mis-triage can still happen. Humans stay in the loop on anything consequential.
- **Eval numbers are illustrative unless you run your own.** Bundled-dataset metrics are a floor on synthetic data; real-world performance must be measured in the user's environment with the harness.
- **Guardrails reduce, not eliminate, prompt-injection risk.** We design for blast-radius, not perfect prevention.
- **Ledger tamper-evidence has limits.** Hash-chaining in Postgres detects partial tampering; defense against a wholesale chain recompute by a privileged DB admin requires the optional external anchoring (FR-46).
- **LLM output is not bit-reproducible.** The *decision path* is replayable from the ledger; re-running a model may differ.
- **Connectors cover a subset at launch.** Reference connectors + SDK are shipped; full vendor adapters (Splunk, Sentinel, CrowdStrike, etc.) are a roadmap, community-extensible.
- **Compliance features assist, not certify.** Regulatory-clock tracking and reports are aids, not legal advice or a compliance guarantee.
- **Self-hosting shifts operational + security burden to the operator.** We document hardening; the operator owns their deployment.

---

## 9. Definition of Done

> **Release arcs (de-risking scope).** **Arc 1 — "first public release" (≈ S0–S7 + core-5 + eval honesty):** a self-hostable, offline-capable, Guardian-gated Tier-1 triage product with the coworker UI, local-admin auth, and the honest eval harness — enough to be genuinely useful and launchable. **Arc 2 — "enterprise GA" (S8):** full SSO (OIDC+SAML)+SCIM+MFA, multi-tenant isolation hardening, Helm/signed-images/SBOM/Zarf. **Arc 3 — "full roster" (S9–S10):** the remaining 9 agents + maturity. The DoD below is the complete first-build target; Arc boundaries let us ship/validate earlier without changing the end state.

**First-cut DoD (ends the first build arc; = S0–S8 + core-5 + eval honesty):**
- [ ] All first-cut **[MUST]** FRs implemented; **core-5 agents + orchestrator** deeply implemented (per §4.6 bar) with a documented **Agent SDK**.
- [ ] `docker compose up` runs the full stack on a fresh machine; **offline mode** triages an alert end-to-end with no API key; the **walking-skeleton loop works from S2 onward**.
- [ ] Self-checks clean (lint, types, all unit/integration/scale/adversarial tests green).
- [ ] The **adversarial/security suite** passes (injection, excessive-agency incl. `modify`, rug-pull, memory-poisoning, output-handling, ledger-tamper, **erasure**, **tenancy**).
- [ ] The **evaluation harness** runs reproducibly and reports precision/recall/FNR/cost on the documented bundled dataset, with published numbers from a named pinned model (labeled illustrative).
- [ ] **Ledger** is tamper-evident, a case is **replayable**, and **crypto-shred erasure** works without breaking the chain.
- [ ] Enterprise: SSO (OIDC+SAML), SCIM, RBAC/ABAC, secrets, **multi-tenant isolation** functional; **Helm** installs; images **signed**; **SBOM** emitted.
- [ ] Docs complete incl. **"what it can & cannot do"**, dataset methodology, GDPR/erasure, and **AISVS self-assessment**; README quickstart reproduces.
- [ ] `BUILD_LOG.md` and `HANDOFF.md` current; no unaudited accuracy numbers anywhere.

**Full-roster milestone (S9–S10):** the remaining 9 agents each meet the §4.6 depth bar with their acceptance tests; regulatory clocks, CVE/KEV + detection-inventory connectors shipped; harness matured; AISVS mapped. *(This is the "all 14 deeply implemented" goal, delivered as staged milestones rather than a single big-bang gate — reconciling G2's ambition with buildability.)*

---

## 10. Standards anchor (pinned at spec time; re-verify at implementation)

OCSF **1.9.0** · STIX/TAXII **2.1** · Sigma **v2.1.0** · MITRE ATT&CK **v19.2** (mind the Defense-Evasion→Stealth/Defense-Impairment split) · D3FEND **1.0.0** · OpenC2 LS **v1.0 (Committee Spec)** / CACAO **v2.0 (Committee Spec)** — adopt as interchange, build the governance layer ourselves · pgvector **0.8.x** · OWASP LLM Top 10 (2025/26), Agentic ASI01–10 (2026), AISVS **1.0**, MCP Top 10 · NIST SP 800-53r5 (AU), 800-61 · OpenBao (MPL-2.0) · OIDC Core 1.0 / SAML 2.0 / SCIM 2.0.

---

## 11. Open concerns (audit trail of the spec review)

**ExpertSpecReviewer cycle 1 → REVISE.** All 7 blocking issues addressed in this revision:
1. Roster big-bang → **staged**: core-5 deep + Agent SDK as first-cut gate; remaining 9 as later milestones to the same depth bar (§4.6, G2, §9). *(Preserves the user's "all 14 deep" intent by sequencing, not cutting.)*
2. Late first slice → **S2 walking skeleton** inserted (§5).
3. Kernel under-specified + false reproducibility claim → **kernel interface specified + time-boxed with LangGraph fallback; "replayable from the ledger"** (§4.4, FR-7/12, principle 2).
4. Guardian/asset model → **§4.7 policy model + §4.8 asset inventory & entity resolution** added.
5. GDPR vs append-only ledger → **crypto-shredding/tokenization** (FR-44, §4.3 PiiToken).
6. Multi-tenancy retrofit → **`tenant_id` threaded from S1** (principle 5, FR-39, data models).
7. Eval honesty → **named pinned model for published numbers + documented dataset + illustrative-floor labeling** (FR-43, §6).

Non-blocking items folded in: throughput/flood test (FR-34/§6), per-case cost accounting (FR-35), memory down to folder+pgvector-first with concrete poisoning defenses + embedding versioning (FR-25/29), entity resolution (§4.8), honest ledger tamper model + optional anchoring (FR-46, §8), per-agent "deeply implemented" bar (§4.6), dependency fixes (CVE/KEV + detection inventory FR-19; DSGAI → OWASP GenAI Data-Security; FR-18 "where applicable"), trimmed v1 auth surface (OIDC MUST-ENT, SAML/SCIM MUST-ENT, passkeys SHOULD).

**ExpertSpecReviewer cycle 2 → APPROVE** (no blocking issues; all 7 prior blockers verified genuinely resolved). Its 11 non-blocking refinements folded in: ledger retention/partitioning + hash-over-ciphertext (FR-6); crypto-shred key management incl. backups (FR-44); embeddings+reranker in the gateway with offline variants (FR-8); named BM25 mechanism + reranker air-gap (FR-27); calibration method stated / "calibration the harness measures" (FR-31, G1); concrete kernel LOC/time budget (§4.4); Agent SDK frozen interface (§4.6); verdict-class vs disposition split (G1/FR-31); release arcs to de-risk scope (§9); editorial S7 fix (FR-36). Remaining minor items (e.g. exact archival tiering) are implementation details for the build log.
