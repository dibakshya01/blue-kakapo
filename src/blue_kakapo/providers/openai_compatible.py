"""OpenAI-compatible adapter.

Covers OpenAI, Azure OpenAI, OpenRouter, vLLM, LM Studio, and Ollama's ``/v1`` surface — anything
that speaks the ``/v1/chat/completions`` and ``/v1/embeddings`` APIs. Uses httpx directly (no heavy
vendor SDK). Reranking falls back to lexical overlap when the endpoint has no rerank API.
"""

from __future__ import annotations

import json

import httpx

from .base import ChatRequest, ChatResponse, LLMProvider, ProviderError, RerankResult
from .offline import OfflineProvider
from .pricing import estimate_usd


class OpenAICompatibleProvider:
    name = "openai"
    supports_embeddings = True
    supports_rerank = False  # most OpenAI-compatible endpoints have no rerank API

    def __init__(
        self,
        base_url: str = "https://api.openai.com/v1",
        api_key: str | None = None,
        default_model: str = "gpt-4o-mini",
        embedding_model: str = "text-embedding-3-small",
        timeout: float = 120.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.default_model = default_model
        self.embedding_model = embedding_model
        self.timeout = timeout
        self._fallback_rerank: LLMProvider = OfflineProvider()

    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    async def chat(self, req: ChatRequest) -> ChatResponse:
        model = req.model or self.default_model
        payload: dict = {
            "model": model,
            "messages": [m.model_dump() for m in req.messages],
            "temperature": req.temperature,
            "max_tokens": req.max_tokens,
        }
        if req.seed is not None:
            payload["seed"] = req.seed
        if req.json_schema is not None:
            payload["response_format"] = {"type": "json_object"}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    f"{self.base_url}/chat/completions", headers=self._headers(), json=payload
                )
                resp.raise_for_status()
                data = resp.json()
        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            raise ProviderError(f"openai-compatible chat failed: {exc}") from exc

        choice = (data.get("choices") or [{}])[0]
        text = (choice.get("message") or {}).get("content", "") or ""
        usage = data.get("usage") or {}
        tin = int(usage.get("prompt_tokens", 0))
        tout = int(usage.get("completion_tokens", 0))
        return ChatResponse(
            text=text,
            model_id=data.get("model", model),
            tokens_in=tin,
            tokens_out=tout,
            usd=estimate_usd(model, tin, tout),
            finish_reason=choice.get("finish_reason", "stop"),
            raw=data,
        )

    async def embed(self, texts: list[str], model: str | None = None) -> list[list[float]]:
        model = model or self.embedding_model
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    f"{self.base_url}/embeddings",
                    headers=self._headers(),
                    json={"model": model, "input": texts},
                )
                resp.raise_for_status()
                data = resp.json()
        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            raise ProviderError(f"openai-compatible embed failed: {exc}") from exc
        return [item["embedding"] for item in data.get("data", [])]

    async def rerank(
        self, query: str, documents: list[str], model: str | None = None, top_n: int | None = None
    ) -> list[RerankResult]:
        # No standard rerank API; use deterministic lexical fallback.
        return await self._fallback_rerank.rerank(query, documents, model, top_n)
