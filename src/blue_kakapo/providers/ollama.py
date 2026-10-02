"""Native Ollama adapter + bootstrap helper.

Uses Ollama's native REST API (``/api/chat``, ``/api/embed``) and exposes ``pull_model`` for the
one-command local bootstrap (FR-11). Ollama is ideal for single-node/dev; for a concurrent agent
swarm in production, point the OpenAI-compatible adapter at vLLM/SGLang instead.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator

import httpx

from .base import ChatRequest, ChatResponse, LLMProvider, ProviderError, RerankResult
from .offline import OfflineProvider


class OllamaProvider:
    name = "ollama"
    supports_embeddings = True
    supports_rerank = False

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        default_model: str = "qwen3:8b",
        embedding_model: str = "nomic-embed-text",
        timeout: float = 120.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.default_model = default_model
        self.embedding_model = embedding_model
        self.timeout = timeout
        self._fallback: LLMProvider = OfflineProvider()

    async def chat(self, req: ChatRequest) -> ChatResponse:
        model = req.model or self.default_model
        payload: dict = {
            "model": model,
            "messages": [m.model_dump() for m in req.messages],
            "stream": False,
            "options": {"temperature": req.temperature, "num_predict": req.max_tokens},
        }
        if req.json_schema is not None:
            payload["format"] = "json"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(f"{self.base_url}/api/chat", json=payload)
                resp.raise_for_status()
                data = resp.json()
        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            raise ProviderError(f"ollama chat failed: {exc}") from exc

        text = (data.get("message") or {}).get("content", "") or ""
        tin = int(data.get("prompt_eval_count", 0))
        tout = int(data.get("eval_count", 0))
        return ChatResponse(
            text=text,
            model_id=data.get("model", model),
            tokens_in=tin,
            tokens_out=tout,
            usd=0.0,  # local model, no per-token cost
            raw=data,
        )

    async def embed(self, texts: list[str], model: str | None = None) -> list[list[float]]:
        model = model or self.embedding_model
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    f"{self.base_url}/api/embed", json={"model": model, "input": texts}
                )
                resp.raise_for_status()
                data = resp.json()
        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            raise ProviderError(f"ollama embed failed: {exc}") from exc
        return data.get("embeddings", [])

    async def rerank(
        self, query: str, documents: list[str], model: str | None = None, top_n: int | None = None
    ) -> list[RerankResult]:
        return await self._fallback.rerank(query, documents, model, top_n)

    async def pull_model(self, model: str) -> AsyncIterator[dict]:
        """Stream ``/api/pull`` progress for the local-model bootstrap (FR-11)."""
        # A model pull can run for many minutes; cap the connect but leave the read open.
        pull_timeout = httpx.Timeout(None, connect=30.0)
        try:
            async with (
                httpx.AsyncClient(timeout=pull_timeout) as client,
                client.stream("POST", f"{self.base_url}/api/pull", json={"model": model}) as resp,
            ):
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if line.strip():
                        yield json.loads(line)
        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            raise ProviderError(f"ollama pull failed: {exc}") from exc
