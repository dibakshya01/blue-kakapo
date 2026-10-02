# Security Policy

blue-kakapo is a defensive security tool. We hold it to the standard we ask of the systems it
protects: least privilege, defense in depth, auditable decisions, and honesty about limits.

> **Status:** alpha. Do not point an early build at production response actions without review. Any
> containment capability is Guardian-gated and human-in-the-loop by design — keep it that way.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Use **GitHub Security Advisories** → the repository's **"Report a vulnerability"** button
(Security tab) to open a private report. Include: affected version/commit, a description, reproduction
steps, and impact. We aim to acknowledge within a few business days.

If you cannot use GitHub advisories, open a minimal public issue asking for a private contact channel
(no details) and we will follow up.

## Scope & our own threat model

blue-kakapo is an agentic system acting on untrusted security telemetry, so it treats its **own**
agents as part of the attack surface. Design controls (see `build-plan.md` §4.6–4.8 and §6) map to:

- **OWASP Top 10 for LLM Applications** (prompt injection, excessive agency, improper output handling,
  sensitive-info disclosure).
- **OWASP Top 10 for Agentic Applications (ASI01–ASI10)** (goal hijack, tool misuse, memory/context
  poisoning, insecure inter-agent comms, cascading failures, rogue agents).
- **OWASP AISVS 1.0**, **OWASP MCP Top 10**, **NIST SP 800-53 (AU)**, and the **Agent Control
  Standard** disposition model (allow/deny/modify/ask/defer, default *ask* — never fail-open).

All alert/log/intel/tool content is treated as **data, never instructions**; every state-changing
action passes the Guardian; every decision is recorded in a tamper-evident, replayable ledger.

## What we will not claim

We do not publish unaudited accuracy numbers. We ship an evaluation harness and a documented dataset
so you can measure results — including the false-negative rate — in your own environment.
