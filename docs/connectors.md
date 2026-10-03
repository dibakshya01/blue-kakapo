# Connectors

A capability-declaring SDK: each connector advertises which of `read_alerts / query / enrich / act` it
supports and, for each action, its **reversibility** and **required scope** — so the orchestrator and
Guardian know what is possible before anything runs.

## Reference connectors
- **ingester** — webhook (`POST /api/ingest`), file/dir (`.json`/`.jsonl`), syslog (RFC 5424/3164).
- **mock SIEM / mock EDR** — deterministic; power offline mode, demos, and tests.
- **Wazuh** — reads alerts from the indexer (OpenSearch) → OCSF; active-response containment.
- **Elastic Security** — reads `.alerts-security.alerts-*` (ECS) → OCSF; endpoint isolate/unisolate.
- **MCP client** — consume external MCP tool servers with **tool-manifest fingerprint pinning**
  (rug-pull defense) and argument validation.

Real vendor adapters (Splunk, Sentinel, CrowdStrike, …) are a community-extensible roadmap.

## Write your own
Implement the `Connector` protocol (`blue_kakapo.connectors.base`): return a `ConnectorInfo` with your
capabilities + `ActionSpec`s (verb, reversible, reverse_verb, required_scope), and implement the
methods you support. Normalize vendor events to the OCSF `Alert` shape. Ship contract tests (see
`tests/test_connectors_*`). Register it in the `ConnectorRegistry`.

Every connector that wraps a query engine must expose a **native-query escape hatch** (pass-through
SPL/KQL/ES\|QL/FQL) — true cross-vendor query abstraction is lossy.
