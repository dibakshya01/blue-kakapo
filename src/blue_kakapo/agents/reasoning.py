"""Shared bounded-LLM reasoning for the whole agent roster.

Every agent computes a **deterministic finding first**, then — only when a real provider is configured
— may ask the model for a small, **schema-validated refinement** over that finding (never over raw
alert text unless explicitly wrapped as untrusted data). Offline, or on any provider error, this
returns ``(None, None)`` and the deterministic result stands, so offline mode is always fully
functional. The LLM step is bounded (temperature 0, one call), auditable, and cost-tracked via
``ModelRef`` — the same pattern L1 uses, lifted here so the rest of the roster meets the same bar.
"""

from __future__ import annotations

from typing import Any, TypeVar

from pydantic import BaseModel

from ..guardian.injection import as_untrusted, contains_unsafe_output
from ..providers import ChatMessage, ProviderError, ProviderGateway
from ..providers.pricing import estimate_usd
from ..schema.ledger import ModelRef
from ..schema.models import Evidence
from .sdk import AgentOutput

T = TypeVar("T", bound=BaseModel)


def finding_output(
    finding: BaseModel,
    evidence: list[Evidence],
    notes: str,
    cost: ModelRef | None = None,
    **meta: Any,
) -> AgentOutput:
    """Build an AgentOutput carrying a typed finding (as JSON) + evidence + optional LLM cost."""
    md: dict[str, Any] = {"finding": finding.model_dump(mode="json"), **meta}
    return AgentOutput(evidence=evidence, metadata=md, notes=notes, cost=cost)


async def bounded_reason(
    gateway: ProviderGateway,
    *,
    system: str,
    payload: str,
    schema: type[T],
    untrusted: bool = False,
    label: str = "context",
) -> tuple[T | None, ModelRef | None]:
    """Run one bounded, schema-validated LLM refinement. ``(None, None)`` offline or on error.

    When ``untrusted`` is set, ``payload`` is wrapped in an ``<untrusted>`` block so the model treats
    it as data, not instructions (LLM01). Callers pass already-summarized, deterministic findings as
    the payload wherever possible.
    """
    if gateway.provider_name == "offline":
        return None, None
    content = as_untrusted(label, payload) if untrusted else payload
    user = content + "\n\nRespond with JSON only."
    try:
        parsed, resp = await gateway.generate_structured(
            [ChatMessage(role="system", content=system), ChatMessage(role="user", content=user)],
            schema,
        )
    except ProviderError:
        return None, None
    ref = ModelRef(
        id=resp.model_id,
        params={"temperature": 0.0},
        tokens_in=resp.tokens_in,
        tokens_out=resp.tokens_out,
        usd=resp.usd or estimate_usd(resp.model_id, resp.tokens_in, resp.tokens_out),
    )
    return parsed, ref


def safe_text(text: str, fallback: str = "") -> str:
    """Drop LLM output that contains unsafe markup/command content before it is stored/shown (LLM10)."""
    if contains_unsafe_output(text):
        return fallback or "[withheld: model output contained unsafe content]"
    return text
