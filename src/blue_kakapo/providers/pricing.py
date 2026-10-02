"""Approximate token pricing for per-case cost accounting.

These figures are **approximate and change over time** — they power the 'predictable cost' metric
(cost-per-case), not billing. Unknown models and all local/offline models cost 0.0. Override via
``BK_`` config if you need precision. Prices are USD per 1,000,000 tokens.
"""

from __future__ import annotations

# (input_per_mtok, output_per_mtok). Matched by case-insensitive substring of the model id.
_PRICES: dict[str, tuple[float, float]] = {
    # Anthropic (approx.)
    "claude-opus": (15.0, 75.0),
    "claude-sonnet": (3.0, 15.0),
    "claude-haiku": (0.80, 4.0),
    # OpenAI (approx.)
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o": (2.50, 10.0),
    "gpt-4.1": (2.0, 8.0),
    "o4-mini": (1.10, 4.40),
    # local / open-weight served via Ollama/vLLM — self-hosted, no per-token cost
    "qwen": (0.0, 0.0),
    "llama": (0.0, 0.0),
    "mistral": (0.0, 0.0),
    "gpt-oss": (0.0, 0.0),
    "deepseek": (0.0, 0.0),
}


def estimate_usd(model_id: str, tokens_in: int, tokens_out: int) -> float:
    """Best-effort USD estimate for a single call. Returns 0.0 for unknown/local/offline models."""
    mid = (model_id or "").lower()
    for key, (pin, pout) in _PRICES.items():
        if key in mid:
            return (tokens_in / 1_000_000) * pin + (tokens_out / 1_000_000) * pout
    return 0.0
