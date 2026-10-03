# What blue-kakapo can & cannot do

Written honestly, before and during the build — not marketing. If something here stops being true,
it's a bug in this doc.

## What it can do

- **Triage Tier-1 alerts end-to-end**, offline with no API key: ingest → OCSF-normalize → enrich
  (deterministic-first) → reason (bounded LLM when configured) → verdict **with cited evidence** →
  auto-close false positives or escalate with a narrative.
- **Show its work.** Every verdict is backed by cited evidence and a **replayable, hash-chained case
  ledger** you can verify.
- **Investigate & correlate**: pull connector enrichment + SIEM queries (L2), map ATT&CK context
  (INTEL), cluster related cases by shared entities (FUSION).
- **Gate response**: propose containment (RESP) that is **always** Guardian-checked. Every
  high-impact action (isolate/disable/kill/quarantine/firewall) needs **two distinct human
  approvers** on *any* asset — a proposer can't approve its own action — so nothing is ever
  auto-isolated, crown jewel or not.
- **Run proactive & service work**: early warning, hypothesis hunts, detection-coverage gaps + Sigma
  drafts, exposure (KEV/CVSS) prioritization, privacy-gated insider signals, summaries, incident &
  compliance reports, pipeline-health checks, and **regulatory-clock tracking** (DORA/NIS2/GDPR/SEC).
- **Stay in your network**: localhost, Docker, or air-gapped Kubernetes; any LLM (cloud or local),
  switchable anytime; opt-in memory (local folder or DB).
- **Meet enterprise table stakes**: OIDC SSO, RBAC, SCIM deprovisioning, multi-tenant isolation,
  secrets via OpenBao, signed images + SBOM.
- **Measure itself honestly**: an evaluation harness that reports precision/recall, calibration, cost,
  and the **false-negative rate**.

## What it cannot do (and won't claim)

- **It is not a detector.** Triage quality depends on the telemetry and detections you feed it. It
  reasons over signals; it does not replace good detection engineering. **Alert reduction is not the
  same as better detection** — suppressing noise can hide a real threat.
- **It can miss real threats.** No triage system is perfect. Our bias is to escalate on uncertainty,
  and the harness measures the miss rate, but **false negatives are possible** — which is why humans
  stay in the loop on anything consequential.
- **Local models trail frontier models** on hard reasoning. Offline mode is deterministic and
  assistive, explicitly non-inferential — not a substitute for a capable model.
- **Guardrails reduce, not eliminate, prompt-injection risk.** We design for blast-radius containment,
  not perfect prevention; assume injection can succeed and limit what it can reach.
- **No unaudited accuracy numbers.** The bundled dataset gives an *illustrative floor*, not a
  real-world figure. Run the harness on your own labeled data for numbers that mean anything.
- **Ledger tamper-evidence has limits.** Hash-chaining detects partial tampering; defending against a
  privileged DB admin recomputing the whole chain requires the optional external anchoring.
- **Connectors cover a subset at launch.** Reference connectors + the SDK ship now; full vendor
  adapters (Splunk, Sentinel, CrowdStrike, …) are a community-extensible roadmap.
- **Native SAML isn't built-in.** Use an OIDC-bridging proxy (Keycloak / oauth2-proxy). OIDC + SCIM
  are first-class.
- **Compliance features assist, they don't certify.** Regulatory-clock tracking and reports are aids,
  not legal advice or a guarantee of compliance.
- **Self-hosting shifts operational & security burden to you.** We document hardening; you own your
  deployment.
