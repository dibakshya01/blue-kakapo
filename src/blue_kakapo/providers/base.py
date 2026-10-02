"""Provider-gateway base types and the LLMProvider protocol.

One interface over every backend for **generation, embeddings, and reranking**. Adapters implement
it for Anthropic, any OpenAI-compatible endpoint, native Ollama, and a deterministic offline mock.
Nothing here assumes a network — the offline adapter satisfies the same protocol with no key.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from pydantic import Field

from ..schema.common import BKModel


class ChatMessage(BKModel):
    role: str = Field(..., description="system | user | assistant")
    content: str


class ChatRequest(BKModel):
    messages: list[ChatMessage]
    model: str | None = None  # None -> gateway default; allows per-agent override
    temperature: float = 0.0
    max_tokens: int = 2048
    json_schema: dict[str, Any] | None = Field(
        default=None, description="If set, request structured JSON matching this schema."
    )
    seed: int | None = None


class ChatResponse(BKModel):
    text: str
    model_id: str
    tokens_in: int = 0
    tokens_out: int = 0
    usd: float = 0.0
    finish_reason: str = "stop"
    offline: bool = Field(
        default=False, description="True if produced by the offline mock (non-inferential)."
    )
    raw: dict[str, Any] = Field(default_factory=dict)


class RerankResult(BKModel):
    index: int
    score: float


@runtime_checkable
class LLMProvider(Protocol):
    """The contract every adapter satisfies."""

    name: str
    supports_embeddings: bool
    supports_rerank: bool

    async def chat(self, req: ChatRequest) -> ChatResponse: ...

    async def embed(self, texts: list[str], model: str | None = None) -> list[list[float]]: ...

    async def rerank(
        self, query: str, documents: list[str], model: str | None = None, top_n: int | None = None
    ) -> list[RerankResult]: ...


class ProviderError(RuntimeError):
    """Raised when a provider call fails (network, auth, bad response)."""
