# blue-kakapo documentation

An open-source, self-hostable, **agentic SOC** for trustworthy Tier-1 triage — a transparent coworker
for L2/L3 analysts.

## Start here
- [Getting started](getting-started.md) — install, run, connect your systems.
- [Architecture](architecture.md) — the deterministic kernel, Guardian, ledger, memory, agents.
- [Agents](agents.md) — the 14-agent roster and what each does.

## Operate
- [Connectors](connectors.md) — the SDK + reference connectors (mock, Wazuh, Elastic, MCP).
- [LLM providers](providers.md) — offline / Anthropic / OpenAI-compatible / Ollama; switching + bootstrap.
- [Memory](memory.md) — opt-in case memory, backends, poisoning defenses.
- [Guardian & policies](guardian.md) — how containment is gated.
- [Evaluation harness](eval.md) — measure precision/recall and the **false-negative rate**.

## Trust & limits (read these)
- [What it can & cannot do](what-it-can-and-cannot-do.md) — the honest limits.
- [Security model](security-model.md) — OWASP/AISVS/NIST mapping + self-assessment.
- [Threat model](threat-model.md) — trust boundaries and how we defend them.
- [GDPR & erasure](gdpr-erasure.md) — crypto-shredding against the append-only ledger.

> blue-kakapo is **alpha**. It is designed so that the risky parts (containment) are human-approved by
> default, and so you can measure its quality in your own environment instead of trusting a number.
