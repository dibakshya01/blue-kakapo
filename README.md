<div align="center">

# 🦜 blue-kakapo

**An open-source, self-hostable, agentic SOC platform for trustworthy Tier-1 triage.**
*A transparent coworker for L2/L3 analysts — not a black box that acts alone.*

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](pyproject.toml)
[![Status: alpha](https://img.shields.io/badge/status-alpha-orange.svg)](build-plan.md)

</div>

> **Status:** early, active development. The architecture and staged plan are in
> [`build-plan.md`](build-plan.md); the research behind it is in [`finding.md`](finding.md).

---

## Why

SOC teams drown in alerts — commonly **3,000–4,500 a day**, of which **40–63% are never
investigated** and **~42–46% are false positives**. Analysts burn out (≈71%) and the cost of being
slow is real (sub-200-day breach containment saves ~$1.9M). Tier-1 triage is the agreed first thing
to automate — but every capable AI-SOC product today is **closed, cloud-only SaaS** that ships your
security telemetry to a vendor, on opaque consumption pricing, with black-box reasoning you're asked
to trust. (Sources in [`finding.md`](finding.md).)

**blue-kakapo is the open alternative:** a swarm of specialized agents coordinated by a deterministic
orchestrator that triages alerts fast **and** shows its work — runs entirely in your network, on any
LLM (cloud or local), with every decision gated by a Guardian and recorded in a replayable,
tamper-evident case ledger.

## What makes it different

- **Trust is the product.** Every verdict is evidence-cited and replayable from an immutable case
  ledger. We ship an **evaluation harness that reports the false-negative rate** instead of a
  marketing accuracy number.
- **Deterministic spine, bounded intelligence.** A typed, checkpointed state machine drives the flow;
  LLMs are confined to scoped reasoning tasks after deterministic enrichment. Controls hallucination
  and cost.
- **Human-in-the-loop by default.** Any containment action is **Guardian-gated** (allow/deny/modify/
  ask/defer, default *ask*), blast-radius-limited, reversible, and audited.
- **In-network & model-agnostic.** Localhost or air-gapped K8s. Anthropic / OpenAI / Azure / local
  **Ollama** — switchable anytime — plus a **deterministic offline mode that needs no API key**.
- **Integration-first.** A capability-declaring connector SDK + reference connectors, MCP-native,
  OCSF-normalized.

## Quickstart

> Requires Python 3.11+. The fastest path is [`uv`](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/dibakshya01/blue-kakapo.git
cd blue-kakapo
uv sync                 # install
uv run bk info          # show resolved config (offline by default — no key needed)
uv run bk serve         # start the control-plane API on http://127.0.0.1:8713
```

Open `http://127.0.0.1:8713/healthz` — you're running, in **offline mode**, with no credentials and
no data leaving your machine. Point it at a real LLM provider (or a local Ollama) when you're ready.

Full Docker Compose and Kubernetes (Helm) deployment land in later stages — see the roadmap.

## Architecture (one breath)

Connectors → OCSF normalization → a deterministic **orchestration kernel** drives each **Case** →
specialist agents reason (bounded LLM, deterministic-first) → the **Guardian** gates every
state-changing action → everything is recorded in a hash-chained, replayable **case ledger** →
surfaced in a **coworker dashboard**. Model-agnostic provider gateway; opt-in case memory. See
[`build-plan.md`](build-plan.md) §4 for the full design and the 14-agent roster.

## Honest limits

blue-kakapo reasons over the telemetry and detections you feed it — it does not replace good
detection engineering, and alert reduction is not the same as better detection. Local models trail
frontier models on hard cases. Guardrails reduce, not eliminate, prompt-injection risk. False
negatives remain possible, which is why humans stay in the loop and we ship the measuring tool rather
than a number. See [`build-plan.md`](build-plan.md) §8.

## Contributing & security

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`SECURITY.md`](SECURITY.md). Licensed under
[Apache-2.0](LICENSE).
