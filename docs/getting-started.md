# Getting started

## Localhost (no key, no Docker)

Requires Python 3.11+ and [`uv`](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/dibakshya01/blue-kakapo.git
cd blue-kakapo          # a path WITHOUT spaces avoids a uv editable-install quirk
uv sync
uv run bk serve         # http://127.0.0.1:8713  (offline mode — no API key)
```

Open the dashboard, paste an alert (or use a sample), and triage. Try the CLI too:

```bash
echo '{"title":"C2 beacon","severity":"high","dst_ip":"198.51.100.23"}' | uv run bk triage -
uv run bk eval          # prints precision/recall and the false-negative rate
```

## Docker Compose (with Postgres + optional Ollama)

```bash
docker compose -f deploy/compose/docker-compose.yml up        # api + pgvector
docker compose -f deploy/compose/docker-compose.yml --profile local-llm up   # + ollama
```

## Kubernetes (enterprise)

See [deploy/helm/README.md](../deploy/helm/README.md) — hardened chart, OIDC SSO, secrets via OpenBao,
cosign-signed images + SBOM, and a Zarf air-gap package.

## Connect a real LLM

Set a provider (switchable anytime, or from the dashboard's Settings tab):

```bash
BK_PROVIDER=anthropic BK_ANTHROPIC_API_KEY=... uv run bk serve
BK_PROVIDER=ollama   BK_MODEL=qwen3:8b        uv run bk serve   # local, in-network
```

## Connect your systems

Reference connectors ship ready: a webhook (`POST /api/ingest`), file/syslog ingest, a mock SIEM/EDR,
and real **Wazuh** and **Elastic** adapters. See [connectors](connectors.md) to configure them or add
your own via the SDK.
