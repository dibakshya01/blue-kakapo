"""Model-agnostic provider gateway: cloud, local, or deterministic offline — switchable at runtime."""

from __future__ import annotations

from .anthropic import AnthropicProvider
from .base import (
    ChatMessage,
    ChatRequest,
    ChatResponse,
    LLMProvider,
    ProviderError,
    RerankResult,
)
from .gateway import ProviderGateway, build_provider
from .offline import OfflineProvider, hashing_embed
from .ollama import OllamaProvider
from .openai_compatible import OpenAICompatibleProvider
from .pricing import estimate_usd

__all__ = [
    "ChatMessage",
    "ChatRequest",
    "ChatResponse",
    "RerankResult",
    "LLMProvider",
    "ProviderError",
    "ProviderGateway",
    "build_provider",
    "OfflineProvider",
    "hashing_embed",
    "AnthropicProvider",
    "OpenAICompatibleProvider",
    "OllamaProvider",
    "estimate_usd",
]
