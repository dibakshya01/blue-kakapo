# Findings — blue-kakapo

*An open-source, self-hostable, agentic SOC platform for Tier-1 alert triage — a coworker for L2/L3 analysts.*

Research date: **2026-10-02**. Every non-obvious claim is sourced below. Vendor performance figures (accuracy %, false-positive reduction) are **self-reported marketing metrics unless stated otherwise** and are treated as claims, not facts.

---

## 1. Problem

Security Operations Centers are drowning in alerts, and the humans in them are burning out while the cost of being slow keeps rising.

- **Alert volume is crushing and mostly unexamined.** Independent and vendor-commissioned surveys converge on **~3,000–4,500 alerts per day** for an average organization, with **40–63% never investigated at all** and **~42–46% false positives** ([SANS 2024 Detection & Response Survey](https://www.sans.org/white-papers/sans-2024-soc-survey-facing-top-challenges-security-operations/); [Vectra AI, 2026](https://www.vectra.ai/topics/alert-fatigue); [2026 State of SecOps / Crogl, via Techspective](https://techspective.net/2026/03/18/your-soc-is-investigating-less-than-half-its-alerts-every-day/)). Analysts lose **~25% of their time chasing false positives** — estimated at ~$1.3M/yr for a large enterprise ([Ponemon/Exabeam, via Bitdefender](https://www.bitdefender.com/en-us/blog/businessinsights/every-hour-socs-run-15-minutes-are-wasted-on-false-positives)).
- **The people are leaving.** **~71% of SOC analysts report burnout and ~64% expect to quit within a year** ([Tines Voice of the SOC 2022](https://www.tines.com/reports/voice-of-the-soc-analyst/)); **73% of orgs report burnout + staffing shortages, 76% cite alert fatigue** ([Gurucul 2025 Pulse of the AI SOC](https://www.cybersecurity-insiders.com/wp-content/uploads/2025-Gurucul-Pulse-AI-SOC-Report-by-CSI.pdf)). The global cybersecurity workforce gap was last officially put at **~4.8M unfilled roles** with workforce growth essentially flat ([ISC2 2024 Workforce Study](https://www.isc2.org/Insights/2024/09/Employers-Must-Act-Cybersecurity-Workforce-Growth-Stalls-as-Skills-Gaps-Widen); [ISC2 2025](https://www.isc2.org/Insights/2025/12/2025-ISC2-Cybersecurity-Workforce-Study) dropped the single number, with 59% reporting critical skills gaps).
- **Slow triage is expensive and now a legal liability.** Median attacker dwell time is **~11 days** ([Mandiant M-Trends 2025](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2025/)); breaches contained in under 200 days cost **~$1.9M less** ([IBM Cost of a Data Breach 2025](https://www.ibm.com/reports/data-breach)), while the global average breach cost hit a record **~$4.99M** (IBM 2026). Regulators now start the disclosure clock at *awareness*: **DORA ~4h/24h**, **NIS2 24h/72h**, **GDPR 72h**, **SEC 4 business days** ([SOC Prime](https://socprime.com/blog/regulatory-detection-obligations-dora-nis2-pci-dss-4-0-sec/); [Legiscope](https://www.legiscope.com/blog/incident-reporting-dora-nis2-gdpr.html)). A single incident at an EU financial firm can trip all four simultaneously.
- **Tier-1 is the agreed wedge.** **66% of analysts believe half-to-all of their tasks could be automated today**; every major report names Tier-1 triage as the first automation target, explicitly advising teams to *"Focus on Tier 1 work first, build trust in early gains, and scale gradually — with visibility, context, and human judgment built in"* (Gurucul 2025; [Devo SOC Performance Report](https://www.globenewswire.com/en/news-release/2022/10/11/2531943/0/en/Devo-s-Annual-SOC-Performance-Report-Reveals-71-of-Security-Professionals-are-Likely-to-Quit-Due-to-a-Combination-of-Challenges-in-the-SOC.html)).

**Who feels it most:** (1) **Tier-1/junior analysts** — they absorb the raw flood, do the most repetitive work, and churn fastest. (2) **SOC managers / CISOs at mid-sized, understaffed, in-house SOCs** (the most common SOC is 2–10 people) — they own retention, the skills gap, and budget justification. (3) **Regulated enterprises** (DORA/NIS2/SEC/GDPR) — for whom slow triage is quantifiable legal and financial exposure.

---

## 2. Prior art & the gap

| Tool | What it does | Strengths | Gaps | Open/License |
|------|--------------|-----------|------|--------------|
| **Microsoft Security Copilot** | GenAI assistant + embedded agents across Defender/Sentinel/Entra | Deepest Microsoft-stack integration; E5 inclusion | Reasons only over the Microsoft part of a mixed stack; SCU consumption cost surprises; surveys report weak value | Closed SaaS |
| **CrowdStrike Charlotte AI** | Agentic triage/response, agentic SOAR; 7-agent "workforce" | Tight Falcon integration; shipped to prod; claims ~98% triage accuracy | Falcon lock-in; credit meter costlier the deeper you investigate | Closed SaaS |
| **Google SecOps / Sec-Gemini** | GA Gemini alert-triage & investigation agent; Mandiant intel | Scale (5M+ alerts); unmatched threat intel | Chronicle lock-in; Sec-Gemini is limited research access, not open-weight | Closed SaaS |
| **Dropzone AI** | Autonomous analyst, no-playbook collect→comprehend→conclude | Transparent analyst-style write-ups; 80+ integrations | Triage-focused (human executes response); pulled public pricing | Closed SaaS |
| **Prophet / Simbian / 7AI / Qevlar / Exaforce / Conifers / Intezer / Torq HyperSOC / AirMDR** (and Radiant, acquired by Cribl Aug 2026) | Agentic "AI SOC analyst" triage/investigation, some with multi-agent swarms | Well-funded; multi-agent; several emphasize bounded/deterministic reasoning (Qevlar, Intezer, Exaforce) | All closed SaaS; most are cloud-only; metrics unaudited; opaque consumption pricing (e.g. Prophet ~$10/investigation, Microsoft SCUs ~$4/hr) | Closed SaaS |
| **Shuffle / Tracecat / Admyral / StackStorm** | OSS SOAR / workflow automation, adding AI/MCP nodes | Self-hostable plumbing; large app libraries | **Plumbing, not autonomous reasoning**; AGPL (Shuffle/Tracecat) limits embedding | AGPL / Apache |
| **TheHive + Cortex** | IR case management + observable analysis | Best-in-class IR case mgmt | TheHive 5 is now source-available/commercial; limited AI | Source-available / AGPL |
| **Elastic Security (Attack Discovery)** | LLM alert correlation/triage inside Elastic | Closest thing to OSS LLM triage | Elastic-License (source-available, not OSI); Elastic-locked; needs paid tiers | Source-available |
| **MISP / OpenCTI / Intel Owl** | Threat-intel platforms & enrichment | Mature, standardized (STIX/TAXII) | Enrichment/intel only; no triage/agent layer; best AI gated to Enterprise | AGPL / Apache+EE |
| **Wazuh / Velociraptor / Suricata / Zeek** | XDR/SIEM, DFIR, NIDS, NSM | Excellent, commodity telemetry & detection | Sensors/detection, not a triage/reasoning layer | GPL / AGPL / BSD |
| **AiSOC (beenuar)** | Nascent OSS agentic SOC, LangGraph, MCP, local LLM, "decision ledger" | The most complete OSS entrant; proves self-hosted + local-LLM is feasible | **~5 months old** (created 2026-05), single-maintainer, vendor-adjacent, enterprise hardening/feature claims unverified | MIT |
| **FunnyWolf/agentic-soc-platform** | Agent-centric OSS SOC (alert→case, AI investigation, playbooks) | Demonstrates the pattern | **Ships with no LICENSE file → legally all-rights-reserved**; effectively a 1–2 person project | None (unlicensed) |
| **LangGraph / CrewAI / OpenAI Agents SDK / Pydantic-AI** | Agent orchestration frameworks | Permissive, production-capable | Generic, not security-native | MIT / Apache |

**The gap we fill:** Every serious AI-SOC product is **closed, proprietary, cloud-only SaaS** that ships customer security telemetry to a vendor cloud on opaque consumption pricing. The only genuinely open, self-hosted options are nascent single-maintainer projects: **AiSOC** is the most complete but is ~5 months old, vendor-adjacent, and unproven at enterprise scale; **FunnyWolf's** ships with no license at all. The OSS ecosystem has excellent *telemetry* (Wazuh, Suricata, Zeek, Elastic), *intel* (MISP, OpenCTI), *DFIR* (Velociraptor), and *plumbing* (Shuffle, Tracecat) — but **no OSI-licensed, enterprise-grade agentic reasoning layer** that sits on top and performs trustworthy Tier-1 triage. (Note: the "open" SOC stack has itself drifted to source-available/commercial at its most valuable layers — TheHive 5 private-source, Elastic Security/Security Onion under ELv2, n8n fair-code, Filigran EE-gated AI — making a cleanly Apache-2.0, vendor-neutral entrant a sharper differentiator still.) blue-kakapo fills exactly that slot: a **security-native, model-agnostic, in-network, auditable, human-in-the-loop agent swarm** that enriches alerts, gathers context, reasons over them, correlates into incidents, produces an analyst-grade verdict *with evidence*, and either closes false positives or escalates — with containment gated behind human approval. Apache-2.0 is itself a wedge against the AGPL / source-available / commercial incumbents.

---

## 3. Technical landscape

**What "good" looks like, synthesized from the current standards and the credible end of the vendor field.**

- **Normalize to a common schema.** Map heterogeneous telemetry to **OCSF 1.9.0** (Open Cybersecurity Schema Framework; joined the Linux Foundation Nov 2024; Apache-2.0; [schema.ocsf.io](https://schema.ocsf.io)) as the internal event schema, retaining raw. (OCSF 1.9 even adds `ai_agent`/`iam_role`/`attestation` objects + a `record_integrity` profile — handy for logging our *own* agents.) Model threat intel in **STIX 2.1** over **TAXII 2.1** (OASIS Standards, 2021). Track the **ECS (9.5.0) → OpenTelemetry Semantic Conventions** convergence (directional/ongoing). Keep a *native-query escape hatch* because true query abstraction across SPL/KQL/ES\|QL/FQL is lossy.
- **Detection-as-code.** Author detections in **Sigma v2.1.0** (SigmaHQ; pySigma/sigma-cli; now with a correlation spec), use **YARA-X (~1.15)** for files and **Suricata 8 / Snort 3** for network, and **map every alert to MITRE ATT&CK v19.2** for triage, prioritization, and coverage — *noting v19 split Defense Evasion into "Stealth" + "Defense Impairment"*, which breaks older mappings — paired with **D3FEND 1.0.0** for countermeasures.
- **Explicit, auditable orchestration — not a free-roaming swarm.** The credible design pattern (Qevlar's deterministic graph orchestrator with bounded LLMs; Intezer's deterministic-first; Exaforce's multi-model) is a **typed, checkpointed state machine** (LangGraph-style) where the LLM is confined to scoped reasoning tasks and **never takes irreversible action without approval + risk/blast-radius guardrails**. Align the response layer conceptually to **CACAO v2.0** playbooks and **OpenC2** commands. Expose tools/connectors over **MCP**, and consider **A2A** for inter-agent messaging.
- **Case memory done safely.** Episodic ("past cases"), semantic (runbooks/intel/policy), and procedural memory, retrieved by **hybrid search (dense + BM25) + reranking** with metadata filters (tenant, ATT&CK technique, asset, severity). **pgvector** (same Postgres as app data → transactional RBAC/multi-tenancy) is the best default; Qdrant when it outgrows that. Guard against **memory poisoning** with provenance, review, and decay.
- **Model-agnostic, local-first serving.** **Ollama** for dev/single-node (REST on :11434, `/api/pull` bootstrap, OpenAI-compatible `/v1`); **vLLM / SGLang** for concurrent multi-agent serving in production. Strong open-weight picks for reasoning + tool use: **gpt-oss-20b/120b** (Apache-2.0), **Qwen3** family (Apache-2.0), **Mistral Small 3.x**, **Llama 4 Scout**, **DeepSeek-R1/distills**. Cloud providers (Anthropic/OpenAI/Azure) remain first-class, switchable options.
- **Enterprise table stakes.** **OpenBao** (LF, MPL-2.0 Vault fork) for secrets; **tamper-evident, append-only audit** (hash-chaining / WORM) of every agent action and human decision, anchored to **NIST SP 800-53 AU family / SOC 2 / ISO 27001**; **OIDC + SAML + SCIM + MFA/passkeys**; fine-grained per-action/per-asset authorization via **OPA/Rego** or **OpenFGA** (Zanzibar-style); **Helm** for K8s with **cosign-signed images + SBOMs** and **Zarf** for air-gapped installs.

**The hard parts** (why no one has filled the OSS gap yet): matching proprietary model quality on self-hostable/local LLMs; building and maintaining the long tail of SIEM/EDR/cloud/identity connectors; solving the trust problem with bounded reasoning + auditability rather than "wrap an LLM"; and shipping true enterprise hardening (RBAC, audit, multi-tenancy, HA, air-gap).

---

## 4. Standards & references

Each security control in blue-kakapo will map to a specific ID and cite it. Anchors:

- **OWASP Top 10 for LLM Applications** — 2025/2026 line. Esp. **LLM01 Prompt Injection**, **LLM02 Sensitive Info Disclosure**, **LLM06 Excessive Agency**, **LLM10 Improper Output Handling**. ([genai.owasp.org](https://genai.owasp.org/llm-top-10/))
- **OWASP Top 10 for Agentic Applications 2026** (ASI01–ASI10; pub. Dec 2025) — esp. **ASI01 Goal Hijack, ASI02 Tool Misuse, ASI03 Identity/Privilege Abuse, ASI06 Memory & Context Poisoning, ASI07 Insecure Inter-Agent Comms, ASI08 Cascading Failures, ASI10 Rogue Agents**. ([cycode summary](https://cycode.com/blog/owasp-top-10-agentic-applications/))
- **OWASP AISVS 1.0** (June 2026; 191 requirements, 12 chapters, L1/L2/L3) — our verification checklist. ([owasp.github.io/AISVS](https://owasp.github.io/www-project-artificial-intelligence-security-verification-standard-aisvs-docs/))
- **OWASP MCP Top 10** (incl. MCP01 Token Mismanagement, MCP03 Tool Poisoning) + **NSA MCP guidance** (May 2026). ([OWASP MCP Top 10](https://owasp.github.io/www-project-mcp-top-10/))
- **Agent Control Standard (ACS)** — a Guardian between agent and action returning allow/deny/modify/ask/defer, defaulting to deny/ask; paired with an **AgBOM**. Plus **Meta "Rule of Two" / lethal trifecta** (an agent should not simultaneously handle untrusted input, hold sensitive access, and change state/communicate externally — break one leg).
- **NIST**: SP 800-53 Rev 5 (AU audit family), SP 800-61 (incident handling), AI 100-2 (adversarial ML).
- **Domain standards**: OCSF, STIX/TAXII 2.1, Sigma, YARA/YARA-X, Suricata/Snort, MITRE ATT&CK & D3FEND, OASIS CACAO v2.0 & OpenC2, OpenTelemetry.

---

## 5. Risks & unknowns

- **Trust & false negatives (the defining risk).** Independent testing pegs real-world AI-SOC false-positive rates at **68–72%**, and in one test an AI SOC scored ~71% accuracy but **missed the single real incident among 348 false positives** ([UnderDefense 2026](https://underdefense.com/blog/ai-soc-real-incidents/); [Help Net Security 2026](https://helpnetsecurity.com/2026/03/26/future-ai-soc-vendor-claims)). *Alert reduction can mask risk.* Mitigation: deterministic-first enrichment, evidence-grounded verdicts, calibrated confidence, conservative escalation bias, a built-in evaluation harness, and human-in-the-loop by default. **We will never market unaudited accuracy numbers.**
- **Prompt/indirect injection via alert and log content (LLM01/ASI01/ASI06).** Alerts and enrichment data are *untrusted input* an attacker can shape. Mitigation: treat all tool/retrieved content as data, strict output handling, the Guardian/ACS gate, least privilege, and blast-radius limits — design for injection succeeding, not for preventing it.
- **Excessive agency / rogue actions (LLM06/ASI02/ASI10).** An agent isolating a domain controller is its own outage. Mitigation: capability-gated connectors, asset allow/deny guardrails, maker-checker approvals, dry-run/simulation, reversibility metadata, idempotency, time-boxed containment, break-glass + full audit.
- **Local model quality gap.** Open-weight models trail frontier hosted models on hard triage reasoning. Mitigation: model-agnostic design, deterministic enrichment to reduce reliance on the LLM, and honest per-model guidance.
- **Connector maintenance burden.** Vendor APIs churn (Microsoft Graph consolidation, CrowdStrike Alerts v2). Mitigation: capability-declaring connector SDK, version-pinned adapters, contract tests, and a strong reference-connector tier so the project is useful before every vendor adapter exists.
- **Adoption friction.** Self-hosting shifts operational/security burden to the user; real AI-SOC adoption is only ~1–5% ("pilot purgatory"). Mitigation: one-command localhost start, Ollama bootstrap, a deterministic offline/demo mode needing no key, and a credible "what it can & cannot do" doc.
- **Legal/naming.** Apache-2.0 avoids copyleft friction; name/brand must not trace to any inspiration source (verified: "blue-kakapo" is distinct). Third-party content fetched by agents is untrusted data, never instructions.

---

## 6. Synthesized direction

**Thesis:** *The AI-SOC category is real and valuable but entirely closed, cloud-bound, and trust-challenged. blue-kakapo is the open-source, self-hostable, in-network agent swarm that makes Tier-1 triage fast **and** trustworthy — a transparent coworker for L2/L3 analysts, not a black box that acts alone.*

**The wedge:** autonomous, evidence-first **Tier-1 triage** that keeps all data in-network, shows its reasoning, and escalates to humans instead of acting irreversibly — the three loudest unmet objections (data sovereignty, transparency, predictable cost) answered at once.

**Guiding principles for the build:**
1. **Trust is the product.** Every verdict is backed by cited evidence and a replayable reasoning trace (a tamper-evident, hash-chained "case ledger"); confidence is calibrated; the bias is to escalate, not to suppress. No unaudited accuracy claims, ever.
2. **Deterministic spine, bounded intelligence.** A typed, checkpointed orchestration state machine drives the flow; LLMs are confined to scoped reasoning tasks; deterministic enrichment does as much as possible before any model call. This is what the credible vendors do, and it controls hallucination, cost, and reproducibility.
3. **Human-in-the-loop by default; least privilege always.** Read/triage-first agents; any containment is Guardian-gated (allow/deny/modify/ask/defer, default ask), blast-radius-limited, reversible, and fully audited. Security guardrails map explicitly to OWASP LLM/ASI/AISVS/MCP IDs.
4. **In-network and model-agnostic.** Runs on localhost or air-gapped K8s; any LLM provider (Anthropic/OpenAI/Azure/local), switchable anytime, with a built-in Ollama bootstrap and a no-key offline mode. First-class, opt-in **case memory** (local folder or DB/VM-backed).
5. **Integration-first, standards-anchored.** A capability-declaring connector SDK + working reference connectors; OCSF-normalized events; STIX/TAXII intel; Sigma + ATT&CK detection content; tools exposed over MCP. Easy to connect; honest about what each connector can do.

**Positive differentiators to lead with:** open-source & Apache-2.0 (no lock-in, no copyleft friction) · self-hosted & in-network (data sovereignty, air-gap capable) · transparent, replayable, evidence-backed reasoning (the auditable case ledger) · human-in-the-loop & Guardian-gated by design · model-agnostic with local-first bootstrap · predictable cost (no per-SCU/credit meter) · standards-anchored guardrails (OWASP LLM/ASI/AISVS/MCP, NIST, CACAO/OpenC2) · a genuine coworker UX for L2/L3, not another SOC console.

---

## Sources

Competitive, problem-space, and technical sources are linked inline above. Primary anchors, dated where version/price-sensitive:
- SANS 2024 Detection & Response Survey (2024) · Gurucul 2025 Pulse of the AI SOC · Tines Voice of the SOC 2022 · ISC2 Workforce Study 2024 & 2025 · IBM Cost of a Data Breach 2025 & 2026 · Mandiant M-Trends 2025 · Torq 2026 AI SOC Leadership Report · Help Net Security (2026-03-26) · UnderDefense AI SOC real incidents (2026).
- OWASP GenAI Security Project (LLM Top 10 2025/2026; Agentic Top 10 2026; AISVS 1.0, 2026-06; MCP Top 10) · NSA MCP guidance (2026-05) · NIST SP 800-53r5, SP 800-61, AI 100-2.
- OCSF (schema.ocsf.io) · OASIS STIX/TAXII 2.1 · SigmaHQ · YARA-X · Suricata/Snort · MITRE ATT&CK/D3FEND · OASIS CACAO v2.0 / OpenC2 · OpenTelemetry.
- Vendor API docs: Splunk REST, Elastic Detections/response-actions, Microsoft Graph Security, CrowdStrike FalconPy, Wazuh API.
- Agents/memory/serving: Anthropic *Building Effective Agents*, LangGraph, OpenAI Agents SDK, MCP, A2A, pgvector, Qdrant, Ollama, vLLM, SGLang; open models gpt-oss / Qwen3 / Mistral / Llama 4 / DeepSeek.
- Enterprise: OpenBao, External Secrets Operator, Helm, Zarf, OPA, OpenFGA, Keycloak/Dex, OIDC Core 1.0, SCIM 2.0, WebAuthn.

> **Honesty note:** All vendor efficacy/accuracy/pricing figures are self-reported and unaudited. Some fast-moving version numbers (OCSF, ATT&CK, YARA-X, Ollama/vLLM, newest model releases) should be reconfirmed on official pages at implementation time; a few were flagged by research as unverifiable this session.
