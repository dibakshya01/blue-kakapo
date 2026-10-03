# Threat model

## Trust boundaries
- **Untrusted (attacker-shapeable):** alert/log/intel content, external MCP tool output. Treated as
  **data, never instructions**; sanitized, schema-validated; injection-detected.
- **Semi-trusted:** LLM output — validated before any side effect.
- **Trusted:** authenticated operator config and chat; the Guardian sits on the **egress** boundary
  (any action to a connector).

## Adversaries & defenses
| Adversary goal | Defense |
|----------------|---------|
| Steer a verdict via injected alert text | content-as-data, deterministic-first signals, Guardian gate |
| Make the agent take a harmful action | Guardian ACS gate, asset allow/deny, maker-checker, blast-radius, reversibility |
| Poison memory to mislead future triage | quarantine of agent-authored memory, trust tiers, decay, provenance |
| Swap a trusted MCP tool for a malicious one | manifest fingerprint pinning (rug-pull refusal) |
| Exfiltrate secrets | secrets via OpenBao, never in prompts/logs; token-scoped auth |
| Tamper with the audit trail | hash-chained ledger + verify; optional WORM anchoring |
| Cross-tenant data access | tenant-scoped principals; cross-tenant = 404 (no existence leak) |
| Rogue/over-privileged agent | Rule of Two enforced at construction; AgBOM; RBAC |

## Honest stance
We design for **blast-radius containment, not perfect prevention** — assume injection eventually
succeeds and limit what it can reach. Report issues via [SECURITY.md](../SECURITY.md).
