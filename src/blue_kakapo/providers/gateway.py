"""The provider gateway: one switchable entry point over every adapter.

Responsibilities:
- Pick the active adapter from config and allow **runtime switching** (FR-9) without restart.
- Allow **per-call model overrides** (per-agent models).
- Provide **embeddings + rerank** with a deterministic offline fallback when the active provider has
  no such API, so memory works out of the box (the chosen embedding model id is tracked for memory
  versioning — FR-26).
- Provide ``generate_structured`` to get schema-validated JSON out of any provider.
"""

from __future__ import annotations

import json
import re
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from ..config import ProviderKind, Settings, get_settings
from .anthropic import AnthropicProvider
from .base import ChatMessage, ChatRequest, ChatResponse, LLMProvider, ProviderError, RerankResult
from .offline import OfflineProvider
from .ollama import OllamaProvider
from .openai_compatible import OpenAICompatibleProvider

T = TypeVar("T", bound=BaseModel)

_JSON_FENCE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)
_JSON_OBJ = re.compile(r"\{.*\}", re.DOTALL)


def _extract_json(text: str) -> dict:
    """Best-effort extraction of a JSON object from an LLM response (handles code fences)."""
    m = _JSON_FENCE.search(text)
    candidate = m.group(1) if m else None
    if candidate is None:
        m2 = _JSON_OBJ.search(text)
        candidate = m2.group(0) if m2 else text
    return json.loads(candidate)


def build_provider(settings: Settings) -> LLMProvider:
    """Construct the active provider adapter from settings."""
    kind = settings.provider
    if kind == ProviderKind.OFFLINE:
        return OfflineProvider(model=settings.model)
    if kind == ProviderKind.ANTHROPIC:
        return AnthropicProvider(
            api_key=settings.anthropic_api_key,
            default_model=settings.model,
            timeout=settings.llm_timeout_seconds,
        )
    if kind == ProviderKind.OPENAI:
        return OpenAICompatibleProvider(
            base_url=settings.openai_base_url,
            api_key=settings.openai_api_key,
            default_model=settings.model,
            embedding_model=settings.embedding_model,
            timeout=settings.llm_timeout_seconds,
        )
    if kind == ProviderKind.OLLAMA:
        return OllamaProvider(
            base_url=settings.ollama_base_url,
            default_model=settings.model,
            embedding_model=settings.embedding_model,
            timeout=settings.llm_timeout_seconds,
        )
    raise ProviderError(f"unknown provider: {kind}")


class ProviderGateway:
    """Switchable facade over the active LLM provider, with an offline fallback for embed/rerank."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._provider: LLMProvider = build_provider(self.settings)
        self._offline = OfflineProvider()

    @property
    def provider_name(self) -> str:
        return self._provider.name

    @property
    def model(self) -> str:
        return self.settings.model

    def switch(self, **overrides: object) -> None:
        """Change provider/model/keys at runtime (FR-9). Pass any Settings field as a keyword."""
        data = self.settings.model_dump()
        data.update(overrides)
        self.settings = Settings(**data)
        self._provider = build_provider(self.settings)

    async def chat(self, req: ChatRequest) -> ChatResponse:
        return await self._provider.chat(req)

    async def generate_structured(
        self,
        messages: list[ChatMessage],
        schema: type[T],
        *,
        model: str | None = None,
        temperature: float = 0.0,
        max_tokens: int = 2048,
    ) -> tuple[T, ChatResponse]:
        """Ask the model for JSON matching ``schema`` and validate it. Raises ProviderError on failure."""
        req = ChatRequest(
            messages=messages,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            json_schema=schema.model_json_schema(),
        )
        resp = await self._provider.chat(req)
        try:
            return schema.model_validate(_extract_json(resp.text)), resp
        except (json.JSONDecodeError, ValidationError) as exc:
            raise ProviderError(f"structured output did not match schema: {exc}") from exc

    def embedding_model_id(self) -> str:
        """Stable identifier for the embedding model in use (for memory versioning)."""
        if getattr(self._provider, "supports_embeddings", False):
            return f"{self._provider.name}:{self.settings.embedding_model}"
        return f"offline:{self._offline.name}"

    async def embed(self, texts: list[str], model: str | None = None) -> list[list[float]]:
        if getattr(self._provider, "supports_embeddings", False):
            return await self._provider.embed(texts, model or self.settings.embedding_model)
        return await self._offline.embed(texts)

    async def rerank(
        self, query: str, documents: list[str], model: str | None = None, top_n: int | None = None
    ) -> list[RerankResult]:
        if getattr(self._provider, "supports_rerank", False):
            return await self._provider.rerank(query, documents, model, top_n)
        return await self._offline.rerank(query, documents, model, top_n)
