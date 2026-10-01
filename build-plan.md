# Build Plan — blue-kakapo

*An open-source, self-hostable, agentic SOC platform for trustworthy Tier-1 triage — a transparent coworker for L2/L3 analysts.*

> This is the contract for the build. Nothing is implemented that isn't specified here. When reality forces a change, this file is edited first, then the code. Derived from [finding.md](finding.md).

---

## 0. Thesis & principles

**Thesis:** The AI-SOC category is real and valuable but entirely closed, cloud-bound, and trust-challenged. blue-kakapo is the open-source, self-hostable, in-network agent swarm that makes Tier-1 triage fast **and** trustworthy — a transparent coworker for L2/L3 analysts, not a black box that acts alone.

**Principles (these decide every trade-off):**
1. **Trust is the product.** Every verdict is backed by cited evidence and a replayable reasoning trace (the immutable *case ledger*). Confidence is calibrated; the bias is to escalate, not to suppress. We ship an evaluation harness instead of marketing accuracy numbers.
2. **Deterministic spine, bounded intelligence.** A typed, checkpointed orchestration state machine drives flow; LLMs are confined to scoped reasoning tasks; deterministic enrichment runs before any model call. Controls hallucination, cost, and reproducibility.
3. **Human-in-the-loop by default; least privilege always.** Read/triage-first agents; any state-changing action is Guardian-gated (allow/deny/modify/ask/defer, default *ask/deny*), blast-radius-limited, reversible, and fully audited. Guardrails map to explicit OWASP LLM/ASI/AISVS/MCP IDs.
4. **In-network & model-agnostic.** Runs on localhost or air-gapped K8s; any LLM provider, switchable anytime; built-in Ollama bootstrap; no-key offline mode. First-class, opt-in case memory (local folder or DB/VM-backed).
5. **Integration-first & standards-anchored.** Capability-declaring connector SDK + working reference connectors; OCSF-normalized events; STIX/TAXII intel; Sigma + ATT&CK detection content; tools exposed over MCP. Easy to connect; honest about each connector's limits.

**What would make it award-winning (the bets beyond table stakes):**
- A **glass-box case ledger**: tamper-evident, replayable reasoning — the antidote to the industry's #1 complaint (opacity/trust).
- A **built-in evaluation harness that reports the false-negative rate** — honesty as a headline feature; nobody open-sources this.
- **Regulatory-clock awareness** (DORA 4h/24h, NIS2 24h/72h, GDPR 72h, SEC 4 business days) tracked per case by the MGR agent — a killer enterprise capability no OSS tool offers.
- A **Guardian/ACS agent-safety layer with an AgBOM** (Agent Bill of Materials) — the platform secures *its own agents*, mapped to OWASP Agentic Top 10.
- **Reproducibility**: pinned model digests + seeds + full replay — scientific rigor in a field of unaudited claims.
- A true **coworker UX** (it explains itself, cites evidence, asks for approval) — not another SOC console.

---

## 1. Goals & non-goals

**Goals**
- G1. Autonomously perform **Tier-1 triage** on alerts from heterogeneous sources: dedup, normalize (OCSF), enrich, reason, assign a calibrated verdict (benign / false-positive / suspicious / escalate) **with cited evidence**.
- G2. Run a **swarm of 14 specialized agents + an orchestrator/superagent** across triage, investigation, proactive, and service-ops functions, each deeply implemented with guardrails.
- G3. Be **self-hostable and in-network**: one-command localhost, deployable to K8s/air-gap; all data stays on the user's infrastructure.
- G4. Be **model-agnostic** (Anthropic / OpenAI / Azure / local Ollama/vLLM), switchable anytime, with an Ollama bootstrap and a deterministic **offline mode** needing no key.
- G5. Make **integration easy**: a capability-declaring connector SDK + working reference connectors (ingester, mock SIEM/EDR, Wazuh, Elastic/OpenSearch), MCP-native.
- G6. Provide a **first-class, opt-in memory subsystem** (local folder / pgvector / external DB) of compacted past cases with metadata for fast recall.
- G7. Be **safe by construction**: Guardian-gated actions, human-in-the-loop, injection-resistant, fully audited; guardrails mapped to OWASP/NIST/AISVS.
- G8. Give L2/L3 analysts a **coworker dashboard** (not a SOC dashboard): evidence timelines, reasoning traces, verdicts, and one-click approvals, with live updates.
- G9. Ship **enterprise hardening**: OIDC/SAML/SCIM/MFA, fine-grained RBAC/ABAC, secrets management, multi-tenancy, signed images, SBOM.
- G10. Be **honest and measurable**: a reproducible evaluation harness, an explicit "what it can & cannot do" doc, and an AISVS self-assessment.

**Non-goals (deliberately out of scope)**
- N1. **Not a SIEM/EDR/log store.** We ingest from and act through them; we do not replace Wazuh/Elastic/Splunk/CrowdStrike.
- N2. **Not a SOAR playbook builder.** We orchestrate reasoning, not a drag-and-drop automation studio (we *align* to CACAO/OpenC2 conceptually and can export).
- N3. **Not fully autonomous response.** Containment is always proposed and gated; we do not pursue lights-out auto-remediation of high-impact actions.
- N4. **No vendor data exfiltration / telemetry phone-home.** Ever.
- N5. **No unaudited accuracy claims.** We provide the measuring tool, not the marketing number.
- N6. **Not a threat-intel platform or ticketing system of record.** We integrate with MISP/OpenCTI and ITSM; we don't reimplement them.
- N7. **Not offensive tooling.** Defensive triage only.

---

## 2. Users & jobs-to-be-done

- **Primary — L2/L3 SOC analyst / investigator.** *"Do the repetitive first-pass work for me, show me your evidence and reasoning, and let me approve anything risky."* Lives in the case-detail coworker view.
- **SOC manager / CISO (mid-size, understaffed, in-house SOC).** *"Cut alert fatigue and MTTR without adding headcount, keep data in-network, and give me defensible audit + compliance-clock reporting."* Lives in roster/metrics/reports.
- **Detection engineer / threat hunter.** *"Help me write and tune detections, measure ATT&CK coverage, and run hypothesis-driven hunts."* Uses DET/HUNT.
- **Platform / security engineer (the adopter).** *"Let me stand this up on localhost in minutes, connect my systems, run it air-gapped, and trust its guardrails."* Uses connectors, deploy, Guardian, secrets.
- **Regulated-enterprise compliance owner.** *"Prove we met the DORA/NIS2/GDPR/SEC clock and show the evidence trail."* Uses MGR/RPT + ledger.

**Primary user in one line:** the overworked L2/L3 analyst who needs a trustworthy junior colleague, not another dashboard.

---

## 3. Functional spec (testable requirements)

Each FR is verifiable and maps to a stage (§5). Severity: **[MUST]**, **[SHOULD]**.

**Ingestion & normalization**
- FR-1 [MUST] Accept alerts via (a) HTTP webhook, (b) syslog, (c) file/dir watch, (d) connector pull. Each ingress is authenticated/validated.
- FR-2 [MUST] Normalize every inbound event to the internal **OCSF-based schema**, retaining the raw original. Mapping is version-pinned and contract-tested.
- FR-3 [MUST] Deduplicate and group alerts into **Cases**; preserve provenance (source, connector, timestamps: event vs ingest).

**Orchestration kernel**
- FR-4 [MUST] A typed, deterministic, **checkpointed state machine** drives each Case through a lifecycle (`new → triaging → investigating → awaiting_approval → responding → resolved/escalated/closed`), persisting state transitions.
- FR-5 [MUST] Support **human-in-the-loop interrupts**: a run can suspend awaiting approval/input and **resume** deterministically.
- FR-6 [MUST] Every state transition, tool call, model call, agent decision, and human action writes a **hash-chained, append-only ledger entry** (who/what/when/why, correlation + trace IDs, model id+digest, prompt hash, inputs/outputs).
- FR-7 [MUST] A Case run is **replayable**: given the ledger, reconstruct the decision path; ledger integrity is cryptographically verifiable.

**LLM provider gateway**
- FR-8 [MUST] A provider gateway exposes one interface over adapters: **Anthropic**, **OpenAI-compatible** (covers OpenAI/Azure/Ollama/vLLM/LM Studio/OpenRouter), **Ollama-native**, and a deterministic **mock/offline** provider.
- FR-9 [MUST] The active provider/model is **configurable and switchable at runtime** (config + UI) without restart; per-agent model overrides allowed.
- FR-10 [MUST] **Offline mode** runs the full triage pipeline with no external key (mock provider + deterministic enrichment), so localhost works instantly.
- FR-11 [SHOULD] **Ollama bootstrap**: a CLI/UI action pulls a recommended local model and warms it; progress streamed.
- FR-12 [MUST] Every model call is recorded with model id + digest + params for reproducibility; temperature/seed pinned where supported.

**Connectors**
- FR-13 [MUST] A **Connector SDK**: each connector declares capabilities (`read_alerts`, `query`, `enrich`, `act`) and, for actions, **reversibility + required scope**.
- FR-14 [MUST] Reference connectors shipped and tested: **ingester** (webhook/syslog/file), **mock SIEM**, **mock EDR**, **Wazuh** (API + indexer read; active-response act), **Elastic/OpenSearch** (Detections read + endpoint response-actions act).
- FR-15 [MUST] Intel-enrichment reference connectors: **MISP** and **OpenCTI** (STIX/TAXII), plus a pluggable indicator-lookup interface; offline local-feed support.
- FR-16 [MUST] **MCP client**: consume external MCP tool servers as connector tools, with tool-manifest **fingerprint pinning** (rug-pull defense) and schema validation.
- FR-17 [SHOULD] Optionally **expose blue-kakapo tools as an MCP server** (gated, authenticated).
- FR-18 [MUST] Every connector provides a **native-query escape hatch** (pass-through SPL/KQL/ES|QL/FQL) alongside any abstracted query.

**Guardian (safety layer)**
- FR-19 [MUST] Every state-changing action passes through the **Guardian**, which returns an **ACS disposition** (allow/deny/modify/ask/defer); default is **ask/deny**, never fail-open.
- FR-20 [MUST] Guardian enforces: capability gating, **asset allow/deny** (e.g., never auto-isolate tagged critical assets), **blast-radius caps** (max simultaneous actions), **maker-checker** approval for high-impact, **dry-run/simulation**, **idempotency keys**, **time-boxed/auto-expiring** containment, and **break-glass** with full audit.
- FR-21 [MUST] All tool/retrieved/alert content is treated as **untrusted data, never instructions** (prompt-injection handling); agent outputs are schema-validated before use (improper-output-handling defense).
- FR-22 [MUST] Enforce the **Rule of Two**: no single agent simultaneously (a) processes untrusted input, (b) holds sensitive access, and (c) can change external state — the Guardian breaks at least one leg.
- FR-23 [MUST] Maintain an **AgBOM** per agent (tools, models, connectors, data scopes, permissions) and surface it.

**Memory subsystem**
- FR-24 [MUST] Pluggable memory backends: **folder** (embedded, file-based, for the UI-linked local folder), **postgres** (pgvector), **external** (Qdrant/DB). Configurable.
- FR-25 [MUST] On Case resolution, store a **compacted case record** (features, steps, verdict, outcome, analyst notes) + metadata (tenant, ATT&CK technique, asset, severity).
- FR-26 [MUST] Retrieve similar past cases via **hybrid search (dense + BM25) + reranking** with metadata filters.
- FR-27 [MUST] Memory use is **opt-in per case** (toggle honored); a local folder can be created/linked **from the UI**.
- FR-28 [MUST] Memory-poisoning defenses: provenance on every record, review-before-write for agent-authored memories, and decay/aging; mapped to ASI06.

**Agents (see §4.6 for each)**
- FR-29 [MUST] Implement all 14 agents + orchestrator, each as an auditable sub-graph with: defined triggers, typed inputs/outputs, declared tools, bounded LLM reasoning steps, deterministic-first enrichment, confidence output, and an explicit **autonomy level** (read-only / propose / act-on-approval).
- FR-30 [MUST] L1 produces a triage verdict with **cited evidence** and a confidence score; FP-closure requires evidence and is logged and reversible (re-openable).
- FR-31 [MUST] RESP executes containment **only** via Guardian + human approval; supports dry-run and reversal.
- FR-32 [MUST] MGR tracks **regulatory clocks** (DORA/NIS2/GDPR/SEC) per qualifying case and flags deadlines.

**AuthN/Z, multi-tenancy, secrets**
- FR-33 [MUST] **OIDC** and **SAML** SSO; **SCIM** provisioning/deprovisioning; **MFA/passkeys**. Local admin login for localhost.
- FR-34 [MUST] Fine-grained **per-action, per-asset, per-tenant** authorization (RBAC/ABAC); a low-privilege role cannot approve/execute containment.
- FR-35 [MUST] **Secrets** via OpenBao/Vault (or encrypted local store for localhost); connector creds never in images/logs; injected at runtime; rotatable.
- FR-36 [MUST] **Multi-tenancy** isolation across data, authz, and memory.

**Dashboard (coworker UX)**
- FR-37 [MUST] Case **inbox/triage queue**; **case-detail coworker view** (alert, evidence timeline, agent reasoning trace, verdict + confidence, recommended actions with approval buttons); **agent roster/activity**; **memory browser**; **connector setup wizard**; **approvals inbox**; **settings** (provider switch, Ollama bootstrap); **reports**.
- FR-38 [MUST] **Live updates** via WebSocket; responsive; dark mode; WCAG-AA contrast.
- FR-39 [MUST] Every verdict renders an **explainable verdict card** (evidence-cited, shareable/exportable).

**Evaluation & observability**
- FR-40 [MUST] An **evaluation harness** runs the triage pipeline against labeled datasets (bundled synthetic + bring-your-own) and reports precision, recall, and **false-negative rate**, reproducibly.
- FR-41 [MUST] **OpenTelemetry** traces/logs/metrics; structured JSON logs; health/readiness endpoints.

**Deployment**
- FR-42 [MUST] **Docker Compose** one-command localhost (API, DB+pgvector, frontend, optional Ollama). 
- FR-43 [MUST] **Helm chart** for K8s; **cosign-signed images** + **SBOM**; air-gap bundle (Zarf) documented.

---

## 4. Architecture

### 4.1 System overview (data flow)

```
                         ┌─────────────────────────────────────────────┐
  Alert sources          │                 blue-kakapo                  │
  (SIEM/EDR/webhook ─────┼─▶ Connectors ─▶ Ingestion/Normalize (OCSF)   │
   /syslog/MCP)          │     (SDK)            │                       │
                         │                      ▼                       │
                         │               Case store (Postgres+pgvector) │
                         │                      │                       │
                         │        ┌─────────────▼──────────────┐        │
                         │        │   Orchestrator / Superagent │        │
                         │        │  (deterministic state machine,       │
                         │        │   checkpointing, HITL, routing)      │
                         │        └───┬───────────────┬─────────┘        │
                         │            │   via Guardian│ (ACS gate)       │
                         │       ┌────▼────┐     ┌────▼─────┐            │
                         │       │  Agent  │ ... │  Agent   │  (14 + orch)│
                         │       │ subgraph│     │ subgraph │            │
                         │       └────┬────┘     └────┬─────┘            │
                         │      tools │ (bounded LLM, deterministic      │
                         │            ▼  enrichment, typed outputs)      │
                         │   Provider Gateway        Memory subsystem    │
                         │  (Anthropic/OpenAI/        (folder/pgvector/  │
                         │   Ollama/offline)           external)         │
                         │            │                                  │
                         │            ▼                                  │
                         │   Case Ledger (hash-chained, append-only) ◀── everything writes here
                         │            │                                  │
                         │   Control-plane API (FastAPI + WebSocket) ◀──▶ Coworker Dashboard (React)
                         └─────────────────────────────────────────────┘
   Cross-cutting: AuthN/Z (OIDC/SAML/SCIM/RBAC/ABAC) · Secrets (OpenBao) · OTel observability · Multi-tenancy
```

**Trust boundaries & where untrusted input enters:** alert/log/intel content and external MCP tool output are **untrusted** (attacker-shapeable) → sanitized, treated as data, schema-validated; the Guardian sits on the egress boundary (any action to a connector). Operator config and chat from authenticated users are trusted inputs. Model outputs are semi-trusted → validated before any side effect.

### 4.2 Repository layout (monorepo)

```
blue-kakapo/
  apps/
    api/            # FastAPI control plane + WebSocket (Python)
    web/            # React + Vite coworker dashboard (TypeScript)
  packages/
    core/           # orchestration kernel, case model, ledger, event bus
    agents/         # the 14 agents + orchestrator, each a subgraph
    connectors/     # Connector SDK + reference connectors + MCP client/server
    providers/      # LLM provider gateway + adapters (incl. offline)
    memory/         # memory subsystem + backends (folder/pgvector/external)
    guardian/       # ACS policy engine, AgBOM, injection/output guards
    schema/         # OCSF-based models, STIX helpers, Sigma/ATT&CK utils
    eval/           # evaluation harness + bundled labeled datasets
  deploy/
    compose/        # docker-compose.yml + .env.example
    helm/           # Helm chart, values, signed-image + SBOM tooling
    zarf/           # air-gap bundle definition
  docs/             # docs + site source (Phase 4)
  finding.md  build-plan.md  BUILD_LOG.md  HANDOFF.md  README.md  SECURITY.md  LICENSE
```

### 4.3 Key data models (typed; Pydantic v2 / TS mirror)

- **Event (OCSF)** — normalized; `raw` retained; `class_uid`, `activity_id`, `metadata`, `observables`, `time`, `source`.
- **Alert** — one or more Events + detection context (rule, source, severity, ATT&CK techniques).
- **Case** — the unit of work: `id`, `tenant`, `state`, `alerts[]`, `entities[]` (host/user/ip), `verdict`, `confidence`, `evidence[]`, `attack_techniques[]`, `regulatory_clocks[]`, `assignee`, timestamps.
- **Evidence** — a cited fact: `source`, `connector`, `query`, `result_ref`, `supports` (which claim), `collected_at`.
- **LedgerEntry** — `seq`, `prev_hash`, `hash`, `actor` (agent/human/system), `action`, `inputs_ref`, `outputs_ref`, `model{id,digest,params}`, `disposition`, `trace_id`, `ts`.
- **Disposition** — `allow|deny|modify|ask|defer`, `reason`, `policy_id`, `required_approvals`, `reversibility`.
- **MemoryRecord** — `case_summary` (compacted), `features`, `metadata{tenant,technique,asset,severity}`, `embedding`, `provenance`, `created_at`, `decay`.
- **AgBOM** — per-agent: `tools[]`, `models[]`, `connectors[]`, `data_scopes[]`, `permissions[]`.

### 4.4 The orchestration kernel (why purpose-built)

A small, typed, deterministic state-machine engine: nodes are pure-ish steps (deterministic or a single bounded LLM call), edges are typed transitions, state is checkpointed to Postgres after each node, HITL is a first-class suspend/resume, and **every node emits a ledger entry**. Agents are composed as sub-graphs.

**Decision — build vs. adopt:** we build a focused kernel (~hundreds of LOC) rather than adopt **LangGraph** or **Microsoft Agent Framework** as a hard dependency, because (a) we need total control of the Guardian gate, the hash-chained ledger, and byte-level reproducibility; (b) we avoid a large framework's churn and transitive deps; (c) Apache-2.0 cleanliness. We adopt their *patterns* (graph + checkpointing + HITL interrupts) and document them as prior art. **Pydantic-AI (MIT)** is used inside nodes for typed, model-agnostic structured outputs / tool calls — a library, not an orchestration framework. *(This is a key judgment call flagged for the spec reviewer.)*

### 4.5 Tech choices + rationale

| Area | Choice | Rationale | Rejected |
|------|--------|-----------|----------|
| Backend language | **Python 3.11+** | Security + LLM/agent/MCP ecosystem; async | Go (less LLM ecosystem) |
| API | **FastAPI + Uvicorn** | Async, typed (Pydantic), native WebSocket | Flask/Django (heavier/sync) |
| Typed models | **Pydantic v2** | One schema for API, LLM I/O, DB mapping | dataclasses (no validation) |
| Agent LLM calls | **Pydantic-AI** (lib) + our provider gateway | Typed structured outputs, model-agnostic, MIT | LangGraph/CrewAI as core (lock-in, AGPL-adjacent tooling) |
| Orchestration | **Purpose-built kernel** | Control of Guardian/ledger/replay; few deps | LangGraph (dep weight/churn) |
| Primary store | **PostgreSQL 16 + pgvector** | Cases + events + ledger + vectors in one txn store → RBAC/multi-tenancy | separate vector DB by default (ops overhead) |
| Local memory | **embedded file store** (sqlite-vec / LanceDB) in the linked folder | Matches "link a folder" UX; no server | forcing Postgres for pure-local |
| Event bus/queue | **in-process + Postgres-backed** default; pluggable Redis/NATS | Zero extra infra on localhost; scales later | mandatory Kafka (too heavy) |
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

**Dependency discipline:** every runtime dependency is justified above; the orchestration core, ledger, Guardian, and connector SDK are first-party. No telemetry/phone-home dependency is permitted.

### 4.6 The agent roster (14 + orchestrator)

Each agent: **role · trigger · inputs · tools · bounded-LLM reasoning · typed output · autonomy · key guardrails (OWASP IDs)**. All are read/propose-only except RESP; all write to the ledger; all can consult memory if opted-in.

**Orchestrator / Superagent (the conductor)** — not a chat agent. Owns the Case state machine, routes to agents, enforces sequencing, applies the Guardian, manages HITL and checkpointing, balances concurrency. Autonomy: system. Guards: ASI07 (inter-agent comms integrity), ASI08 (cascading-failure circuit breakers), ASI10 (rogue-agent containment).

*Front line*
1. **L1 — Triage & intake.** Trigger: new alert/case. Deterministic dedup/normalize/scoring first, then a bounded reasoning step for an initial verdict (benign/FP/suspicious/escalate) with cited evidence + confidence. Autonomy: propose (auto-close FPs only above a confidence threshold, reversible, logged). Guards: LLM01 (alert content untrusted), LLM07/Misinformation (evidence-grounded), conservative escalation bias.
2. **WATCH — Early warning.** Trigger: continuous stream scan. Detects bursts/anomalies/emerging patterns across signals; raises proactive cases. Autonomy: propose. Guards: unbounded-consumption limits, rate control.

*Investigate*
3. **L2 — Investigation.** Trigger: escalation from L1/WATCH. Multi-step pivots across connectors; builds the incident narrative; deepens evidence. Autonomy: propose. Guards: Rule-of-Two, query scoping, injection handling.
4. **FUSION — Links signals & campaigns.** Trigger: new/updated cases. Correlates/clusters related alerts/cases into incidents/campaigns; entity-graph building. Autonomy: propose. Guards: ASI06 (memory/context poisoning on correlation inputs).
5. **INTEL — Adversary context.** Trigger: entities/IOCs present. Enriches via MISP/OpenCTI/STIX; maps to ATT&CK techniques, actors, campaigns. Autonomy: propose (read-only external intel). Guards: untrusted intel content, source provenance.

*Proactive*
6. **HUNT — Proactive hunting.** Trigger: scheduled/hypothesis/analyst-initiated. Generates + runs hunt queries (native-query escape hatch), triages findings into cases. Autonomy: propose (read/query only). Guards: query cost caps, scoping.
7. **DET — Detection engineering.** Trigger: FP patterns, coverage gaps, new TTPs. Proposes/tunes **Sigma** rules, measures ATT&CK coverage deltas, reduces FPs. Autonomy: propose (rules are reviewed/merged by humans). Guards: detection-as-code review, no auto-deploy without approval.
8. **VULN — Exposure management.** Trigger: vuln feed/asset context. Correlates exposure with assets + active threats; prioritizes. Autonomy: propose. Guards: data minimization.
9. **INSIDER — Insider risk.** Trigger: behavioral signals. UEBA-style anomaly reasoning for insider threats. Autonomy: propose, **privacy-gated** (minimization, purpose limitation, access controls). Guards: DSGAI data-governance IDs, strict RBAC, PII handling.

*On approval*
10. **RESP — Containment.** Trigger: approved response plan. Executes isolate-host / disable-user / block-IOC / kill-process **only** through Guardian + human approval; dry-run first; reversible; time-boxed. Autonomy: **act-on-approval only**. Guards: LLM06/ASI02/ASI03 excessive-agency, blast-radius, maker-checker, break-glass, full audit.

*Service ops*
11. **COMMS — Keeps you informed.** Trigger: case events/SLA. In-app notifications + case summaries; drafts external messages (Slack/Teams/email) — **external send requires human approval**. Autonomy: propose/act (internal notifications only). Guards: sensitive-info-disclosure (LLM02) redaction.
12. **RPT — Reporting & insight.** Trigger: scheduled/on-demand. Generates incident, compliance (DORA/NIS2/SEC/GDPR), and metrics (MTTD/MTTR, FP rate) reports from the ledger. Autonomy: propose. Guards: evidence-cited, no fabrication.
13. **MAINT — Keeps the SOC seeing.** Trigger: continuous health checks. Monitors connector/detection/pipeline health; flags **detection decay** and data-source gaps. Autonomy: propose. Guards: least privilege on health probes.
14. **MGR — Runs the shift.** Trigger: continuous. Workload balancing, prioritization, escalation routing, SLA + **regulatory-clock tracking** (DORA 4h/24h, NIS2 24h/72h, GDPR 72h, SEC 4 business days). Autonomy: propose/orchestrate (no external actions). Guards: fairness/consistency, audit.

---

## 5. Milestones / stages (the build order)

Sequenced so something runnable exists early and each stage is independently verifiable. Each stage ends with a committed, tested increment and a `BUILD_LOG.md` note. (Deep, no-shortcut builds — stages are large by design.)

| Stage | Ships | Satisfies | Acceptance check (exit) |
|------|-------|-----------|-------------------------|
| **S0 Foundations** | Monorepo, Apache-2.0, CI (lint/type/test), Docker Compose skeleton, Postgres+pgvector, config, provider gateway (incl. offline), base data models, OTel/logging | FR-8/10/12/41/42 | `docker compose up` → API+DB+web shell healthy; provider gateway + offline mode unit-tested green |
| **S1 Kernel + Ledger** | Deterministic checkpointed state machine, case lifecycle, event bus, hash-chained append-only ledger, replay, HITL suspend/resume | FR-4/5/6/7 | Trivial graph runs, persists, resumes after interrupt; ledger hash-chain verifies; replay reproduces state |
| **S2 Connectors + Ingestion** | Connector SDK, ingester (webhook/syslog/file), mock SIEM/EDR, OCSF normalization, Wazuh + Elastic/OpenSearch, MCP client w/ fingerprint pinning | FR-1/2/3/13/14/15/16/18 | Alerts flow from ≥3 sources → OCSF → Cases; connector contract tests pass; MCP tool consumed safely |
| **S3 Guardian** | ACS policy engine, dispositions, capability gating, asset allow/deny, blast-radius, maker-checker, dry-run, idempotency, time-box, break-glass, injection/output guards, Rule-of-Two, AgBOM | FR-19/20/21/22/23/31(partial) | Guardian asks/denies on high-impact in tests; indirect-prompt-injection suite passes; no action reaches a connector without a disposition + ledger entry |
| **S4 Memory** | Pluggable backends (folder/pgvector/external), compacted case records, hybrid retrieval + rerank + metadata filters, UI folder-link flow, opt-in per case, poisoning/decay/provenance guards | FR-24/25/26/27/28 | Resolve case → stored; similar alert retrieves it; opt-in honored; poisoning-guard test passes |
| **S5 Core triage agents** | **L1, WATCH, L2, FUSION, INTEL** (deep), confidence calibration, ATT&CK mapping, correlation, intel enrichment; evaluation harness v1 | FR-29/30/40 + G1 | End-to-end alert→triage→investigate→correlate→context→verdict (evidence+confidence); harness reports precision/recall + **false-negative rate** on bundled dataset |
| **S6 Response + service agents** | **RESP** (Guardian-gated), **COMMS, RPT, MAINT, MGR** (incl. regulatory clocks) | FR-29/31/32 | Approval-gated containment works (dry-run + mock EDR + reversal); compliance report w/ clocks generates; MAINT flags broken connector; MGR routes by SLA |
| **S7 Proactive agents** | **HUNT, DET, VULN, INSIDER** (privacy-gated) | FR-29 | HUNT runs a hunt→case; DET proposes a Sigma rule + coverage delta (human-merge); VULN prioritizes by active-threat context; INSIDER surfaces a signal under privacy controls |
| **S8 Coworker dashboard** | Full React UI: inbox, case-detail coworker view (evidence timeline + reasoning trace + verdict card + approvals), roster/activity, memory browser, connector wizard, approvals inbox, settings (provider switch + Ollama bootstrap), reports; WebSocket live | FR-11/37/38/39 | Full triage loop usable from UI; live updates; approvals actionable; provider switch + Ollama bootstrap from UI; a11y AA + dark mode verified |
| **S9 Enterprise hardening** | OIDC/SAML/SCIM/MFA, RBAC/ABAC per action/asset/tenant, OpenBao secrets, multi-tenancy, Helm chart + signed images + SBOM, Zarf air-gap | FR-33/34/35/36/43 | SSO login works; low-priv role denied containment; Helm installs on kind/k3d; images cosign-verified; SBOM emitted |
| **S10 Eval, docs, security self-review** | Harness maturity (BYO datasets, reproducible), red-team/attack test suite, "can & cannot do" doc, full docs, **AISVS self-assessment (L1/L2)**, threat model, SECURITY.md | FR-40 + G10 | DoD (§9) met; AISVS checklist mapped; attack suite green |

Phases 4 (site + deck) and 5 (≥3 adversarial hardening rounds) run after S10 per the skill pipeline.

**Loop discipline:** each stage is a bounded iterative loop — build → test → run/verify → commit. Hard cap of 3 corrective iterations per stage; if two consecutive iterations make no net progress, stop and escalate.

---

## 6. Test strategy

- **Unit** (pytest + hypothesis; vitest): schema mappings (OCSF), provider adapters (incl. offline determinism), ledger hash-chain, kernel transitions, Guardian dispositions, memory retrieval, each agent's deterministic steps.
- **Integration**: ingest→normalize→case; connector contract tests (mock + Wazuh/Elastic against disposable containers); end-to-end triage pipeline; HITL suspend/resume; approval→RESP→reversal in dry-run.
- **Adversarial / security** (the ones that prove the safety claims):
  - **Indirect prompt injection** embedded in alert/log/intel/MCP-tool content → agent must not follow it; Guardian must still gate.
  - **Excessive agency**: attempt an un-approved or out-of-policy containment → must be denied/asked; asset allow-list honored.
  - **Rug-pull**: changed MCP tool manifest → pinned fingerprint mismatch blocks it.
  - **Memory poisoning**: malicious "past case" → provenance/review/decay prevents it from steering a verdict.
  - **Output handling**: model emits markup/command-like output → sanitized, never executed/rendered unsafely.
  - **Ledger tamper**: altered entry → chain verification fails.
- **Evaluation harness (claim-proving)**: runs triage on labeled datasets; reports precision, recall, **false-negative rate**, calibration; reproducible with pinned models/seeds. This *is* the proof for any accuracy statement — we publish the method, not a number.
- **"Self-checks clean"** = ruff + mypy/pyright + tsc clean; all unit/integration/adversarial tests green; `docker compose up` healthy; README quickstart reproduces end-to-end on a fresh machine; AISVS L1 checklist has no undetected-violation gaps mislabeled as "proven".

---

## 7. Docs, site & deck plan

- **README**: one-paragraph pitch, the gap, a 60-second quickstart (`docker compose up` + offline mode), an architecture diagram, the agent roster, the "trust" story (ledger + eval harness), honest limits link, security policy link.
- **Docs** (`docs/`): Install (localhost / K8s / air-gap), Connect-your-systems (connector SDK + each reference connector), Configure LLM providers (incl. Ollama bootstrap + offline), Memory setup (folder/DB), Guardian & policies, Agents reference, Evaluation harness how-to, Security model + AISVS self-assessment, **"What it can & cannot do"**.
- **ELI5 page** (non-technical): what a SOC is, why alerts overwhelm people, how blue-kakapo helps like a careful junior colleague that always shows its work and asks before doing anything risky.
- **Site** (Phase 4, GitHub Pages): Home, ELI5, Docs, Architecture, Contact — modern dark "analyst console" aesthetic via `master-designer`.
- **Deck** (README/pitch): problem (sourced stats), the gap, the approach (deterministic spine + glass-box trust), the roster, differentiators, honest limits, roadmap.

---

## 8. Honest limits (written before building)

- **Not a detector of unknown-unknowns.** Triage quality depends on the telemetry and detections feeding it; blue-kakapo reasons over signals, it doesn't replace good detection engineering.
- **Local-model quality gap.** Small local models reason less well on hard cases than frontier hosted models; offline mode is deterministic/assistive, not frontier-grade. We state per-model guidance and never claim parity.
- **False negatives remain possible.** No triage system is perfect; our bias is to escalate, and the harness measures the miss rate — but a mis-triage can still happen. Humans stay in the loop on anything consequential.
- **Guardrails reduce, not eliminate, prompt-injection risk.** We design for blast-radius, not for perfect prevention.
- **Connectors cover a subset at launch.** Reference connectors + SDK are shipped; full vendor adapters (Splunk, Sentinel, CrowdStrike, etc.) are a roadmap, community-extensible.
- **Compliance features assist, not certify.** Regulatory-clock tracking and reports are aids; they are not legal advice or a compliance guarantee.
- **Self-hosting shifts operational + security burden to the operator.** We document hardening; the operator owns their deployment.

---

## 9. Definition of Done (ends the build phase)

- [ ] All **[MUST]** FRs implemented; all 14 agents + orchestrator deeply implemented with guardrails.
- [ ] `docker compose up` runs the full stack on a fresh machine; **offline mode** triages an alert end-to-end with no API key.
- [ ] Self-checks clean (lint, types, all unit/integration/adversarial tests green).
- [ ] The **adversarial/security suite** passes (injection, excessive-agency, rug-pull, memory-poisoning, output-handling, ledger-tamper).
- [ ] The **evaluation harness** runs reproducibly and reports precision/recall/false-negative-rate on the bundled dataset.
- [ ] **Ledger** is tamper-evident and a case is fully **replayable**.
- [ ] Enterprise: SSO (OIDC+SAML), SCIM, RBAC/ABAC, secrets, multi-tenancy functional; **Helm** installs; images **signed**; **SBOM** emitted.
- [ ] Docs complete incl. **"what it can & cannot do"** and **AISVS self-assessment**; README quickstart reproduces.
- [ ] `BUILD_LOG.md` and `HANDOFF.md` current.
- [ ] Every README/doc claim is reproducible; no unaudited accuracy numbers anywhere.

---

## Open concerns (to be filled by the spec review loop, if any remain)
*(populated after ExpertSpecReviewer cycles)*
