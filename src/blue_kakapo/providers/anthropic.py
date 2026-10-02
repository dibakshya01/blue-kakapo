"""Anthropic Messages API adapter (httpx, no vendor SDK).

Anthropic has no first-party embeddings/rerank API, so those fall back to the deterministic offline
implementations — callers who want in-network embeddings should point the gateway's embedding model
at a local Ollama/TEI endpoint via the OpenAI-compatible adapter.
"""

from __future__ import annotations

import json

import httpx

from .base import ChatRequest, ChatResponse, LLMProvider, ProviderError, RerankResult
from .offline import OfflineProvider
from .pricing import estimate_usd

_ANTHROPIC_VERSION = "2023-06-01"


class AnthropicProvider:
    name = "anthropic"
    supports_embeddings = False
    supports_rerank = False

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = "https://api.anthropic.com/v1",
        default_model: str = "claude-sonnet-4-5",
        timeout: float = 120.0,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.default_model = default_model
        self.timeout = timeout
        self._fallback: LLMProvider = OfflineProvider()

    def _headers(self) -> dict[str, str]:
        if not self.api_key:
            raise ProviderError("anthropic provider requires an API key (BK_ANTHROPIC_API_KEY)")
        return {
            "x-api-key": self.api_key,
            "anthropic-version": _ANTHROPIC_VERSION,
            "content-type": "application/json",
        }

    async def chat(self, req: ChatRequest) -> ChatResponse:
        model = req.model or self.default_model
        system = "\n".join(m.content for m in req.messages if m.role == "system")
        turns = [
            {"role": m.role, "content": m.content}
            for m in req.messages
            if m.role in ("user", "assistant")
        ]
        payload: dict = {
            "model": model,
            "max_tokens": req.max_tokens,
            "temperature": req.temperature,
            "messages": turns,
        }
        if system:
            payload["system"] = system
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    f"{self.base_url}/messages", headers=self._headers(), json=payload
                )
                resp.raise_for_status()
                data = resp.json()
        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            raise ProviderError(f"anthropic chat failed: {exc}") from exc

        blocks = data.get("content") or []
        text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
        usage = data.get("usage") or {}
        tin = int(usage.get("input_tokens", 0))
        tout = int(usage.get("output_tokens", 0))
        return ChatResponse(
            text=text,
            model_id=data.get("model", model),
            tokens_in=tin,
            tokens_out=tout,
            usd=estimate_usd(model, tin, tout),
            finish_reason=data.get("stop_reason", "stop"),
            raw=data,
        )

    async def embed(self, texts: list[str], model: str | None = None) -> list[list[float]]:
        return await self._fallback.embed(texts, model)

    async def rerank(
        self, query: str, documents: list[str], model: str | None = None, top_n: int | None = None
    ) -> list[RerankResult]:
        return await self._fallback.rerank(query, documents, model, top_n)
