"""The offline provider: deterministic, no network, no API key.

This is what makes ``docker compose up`` (or a bare ``bk serve``) useful instantly. Its outputs are
**deterministic and explicitly non-inferential** — chat returns a clearly-labeled offline response,
embeddings use a stable hashing vectorizer, and rerank uses lexical overlap. Agents do their *real*
offline work through deterministic enrichment/scoring, not by pretending the mock reasoned.
"""

from __future__ import annotations

import hashlib
import re

import numpy as np

from .base import ChatRequest, ChatResponse, RerankResult

_OFFLINE_DIM = 256
_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> list[str]:
    return _TOKEN_RE.findall(text.lower())


def hashing_embed(text: str, dim: int = _OFFLINE_DIM) -> list[float]:
    """A deterministic hashing vectorizer: stable, dependency-light, good enough for local recall."""
    vec = np.zeros(dim, dtype=np.float64)
    for tok in _tokens(text):
        h = hashlib.blake2b(tok.encode("utf-8"), digest_size=8).digest()
        idx = int.from_bytes(h[:4], "big") % dim
        sign = 1.0 if (h[4] & 1) else -1.0
        vec[idx] += sign
    norm = np.linalg.norm(vec)
    if norm > 0:
        vec = vec / norm
    return vec.tolist()


class OfflineProvider:
    """Satisfies the LLMProvider protocol with zero external dependencies."""

    name = "offline"
    supports_embeddings = True
    supports_rerank = True

    def __init__(self, model: str = "offline-deterministic") -> None:
        self.model = model

    async def chat(self, req: ChatRequest) -> ChatResponse:
        prompt = "\n".join(m.content for m in req.messages)
        digest = hashlib.blake2b(prompt.encode("utf-8"), digest_size=6).hexdigest()
        text = (
            "[offline mode] No LLM provider is configured, so this response is a deterministic "
            "placeholder and performs no reasoning. Configure a provider (Anthropic / OpenAI-compatible "
            f"/ Ollama) for real analysis. prompt_digest={digest}"
        )
        return ChatResponse(
            text=text,
            model_id=self.model,
            tokens_in=len(_tokens(prompt)),
            tokens_out=len(_tokens(text)),
            usd=0.0,
            offline=True,
            raw={"prompt_digest": digest},
        )

    async def embed(self, texts: list[str], model: str | None = None) -> list[list[float]]:
        return [hashing_embed(t) for t in texts]

    async def rerank(
        self, query: str, documents: list[str], model: str | None = None, top_n: int | None = None
    ) -> list[RerankResult]:
        q = set(_tokens(query))
        scored: list[RerankResult] = []
        for i, doc in enumerate(documents):
            d = set(_tokens(doc))
            overlap = len(q & d)
            union = len(q | d) or 1
            scored.append(RerankResult(index=i, score=overlap / union))
        scored.sort(key=lambda r: r.score, reverse=True)
        return scored[:top_n] if top_n else scored
