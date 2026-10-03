# LLM providers

Model-agnostic by design. One gateway, four adapters, switchable at runtime — nothing leaves your
network unless you choose a cloud provider.

| Provider | Use | Notes |
|----------|-----|-------|
| `offline` | default; localhost/air-gap | deterministic, **no key**, non-inferential (labeled) |
| `anthropic` | Claude via API | `BK_ANTHROPIC_API_KEY` |
| `openai` | OpenAI-compatible | OpenAI, Azure, OpenRouter, **vLLM**, **LM Studio** — `BK_OPENAI_BASE_URL` |
| `ollama` | local models | in-network; `BK_OLLAMA_BASE_URL`; `/api/pull` bootstrap |

```bash
BK_PROVIDER=ollama BK_MODEL=qwen3:8b uv run bk serve
```

Switch anytime via `POST /api/provider/switch` or the dashboard. Bootstrap a local model via
`POST /api/provider/ollama/pull`. Embeddings + reranking use the active provider where available, else
a deterministic offline fallback (the embedding model id is tracked for memory versioning).

**Keys never appear in prompts, logs, or the UI** — they come from env or the secret store. Every model
call records model id + tokens + cost in the ledger. We do **not** claim bit-identical output; the
decision *path* is replayable from the ledger.

Strong local picks (reasoning + tool use): gpt-oss-20b/120b, Qwen3 (14–32B / 30B-A3B), Mistral Small
3.x, Llama 4 Scout, DeepSeek-R1 distills. Serve a swarm with vLLM/SGLang; Ollama for single-node/dev.
