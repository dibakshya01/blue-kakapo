# Security model & standards self-assessment

blue-kakapo is a defensive tool that treats **its own agents** as part of the attack surface. Controls
map to recognized standards; this page is the self-assessment. "Mitigated" means a control is present
and tested, **not** that the risk is eliminated.

## OWASP Top 10 for LLM Applications (2025/26)

| ID | Risk | How blue-kakapo addresses it |
|----|------|------------------------------|
| LLM01 | Prompt Injection | All alert/log/intel/tool content is treated as untrusted **data**, never instructions; injection detector flags it; blast-radius limited by the Guardian. |
| LLM02 | Sensitive Info Disclosure | PII tokenized/crypto-shredded; COMMS redaction; secrets via OpenBao, never logged. |
| LLM06 | Excessive Agency | Read/triage-first agents; RESP acts **only** via the Guardian with human approval; asset allow/deny + blast-radius caps. |
| LLM07 | System-Prompt Leakage | No secrets in prompts; provider keys via env/secret store. |
| LLM10 | Improper Output Handling | Agent outputs are schema-validated; unsafe-output guard catches markup/command patterns. |

## OWASP Top 10 for Agentic Applications (ASI01–ASI10, 2026)

| ID | Risk | Control |
|----|------|---------|
| ASI01 | Goal Hijack | Deterministic orchestration spine; LLMs confined to scoped tasks; injection handling. |
| ASI02 | Tool Misuse | Capability-declaring connectors; Guardian gates every action; least-privilege scopes. |
| ASI03 | Identity/Privilege Abuse | RBAC per action; maker-checker for high-impact; per-tenant isolation. |
| ASI04 | Agentic Supply Chain | MCP manifest **fingerprint pinning** (rug-pull defense); signed images + SBOM. |
| ASI06 | Memory/Context Poisoning | Agent-authored memory **quarantined** until reviewed; trust-tier weighting + decay; provenance. |
| ASI07 | Insecure Inter-Agent Comms | Agents exchange typed, validated outputs through the kernel; everything ledgered. |
| ASI08 | Cascading Failures | Per-node timeout/retry; max-steps guard; backpressure; circuit-break on repeated failure. |
| ASI09 | Human-Agent Trust Exploitation | Evidence-cited verdicts + replayable ledger; no unaudited accuracy claims; FNR surfaced. |
| ASI10 | Rogue Agents | **Rule of Two** enforced at agent construction; AgBOM per agent; Guardian on egress. |

## OWASP MCP Top 10
- **MCP03 Tool Poisoning / rug-pull** — tool-manifest fingerprint pinning; descriptions treated as
  data; arguments schema-validated. **MCP01 Token mismanagement** — no token passthrough; scoped auth.

## Agent Control Standard (ACS) & Rule of Two
- The **Guardian** returns one of `allow / deny / modify / ask / defer` for every action, defaulting to
  **ask** (never fail-open), paired with an **AgBOM** per agent.
- **Rule of Two**: no agent simultaneously (a) processes untrusted input, (b) holds sensitive access,
  and (c) can change external state. Enforced at construction (`AgentConfigError`).

## NIST / audit
- **SP 800-53 AU family**: append-only, hash-chained ledger (AU-9 protect, AU-10 non-repudiation);
  OpenTelemetry + structured logs; optional WORM anchoring.
- **SP 800-61**: incident lifecycle reflected in the case state machine + RESP gating.

## OWASP AISVS 1.0 — self-assessment (indicative)

| Area | Level targeted | Status |
|------|----------------|--------|
| C1 Data governance / PII | L2 | Tokenization + crypto-shred erasure; data minimization (INSIDER). |
| C3 Prompt/IO handling | L2 | Untrusted-input handling, output validation, injection detection — tested. |
| C6 Orchestration & agentic | L2 | Deterministic kernel, Guardian/ACS, Rule of Two, AgBOM — tested. |
| C10 MCP security | L2 | Fingerprint pinning + schema validation — tested. |
| C11 Supply chain | L1→L2 | Signed images + SBOM (CI); pinned deps. |
| C12 Monitoring/audit | L2 | Tamper-evident ledger + OTel — tested. |

> A clean automated check means "no violation **detected**", not "control **proven** present". We label
> accordingly and welcome adversarial review (see [SECURITY.md](../SECURITY.md)).
