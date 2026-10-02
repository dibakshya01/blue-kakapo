"""S0: the offline provider is deterministic, labeled, and the gateway falls back gracefully."""

from __future__ import annotations

import math

import pytest

from blue_kakapo.config import ProviderKind, Settings
from blue_kakapo.providers import ChatMessage, ChatRequest, OfflineProvider, ProviderGateway


@pytest.fixture
def offline() -> OfflineProvider:
    return OfflineProvider()


async def test_offline_chat_is_deterministic_and_labeled(offline: OfflineProvider) -> None:
    req = ChatRequest(messages=[ChatMessage(role="user", content="triage this alert")])
    a = await offline.chat(req)
    b = await offline.chat(req)
    assert a.text == b.text  # deterministic
    assert a.offline is True
    assert "offline mode" in a.text.lower()
    assert a.usd == 0.0


async def test_offline_embeddings_are_stable_and_normalized(offline: OfflineProvider) -> None:
    v1 = (await offline.embed(["malware on host-1"]))[0]
    v2 = (await offline.embed(["malware on host-1"]))[0]
    assert v1 == v2  # stable
    norm = math.sqrt(sum(x * x for x in v1))
    assert norm == pytest.approx(1.0, abs=1e-6)  # L2-normalized
    other = (await offline.embed(["unrelated benign text"]))[0]
    assert v1 != other


async def test_offline_rerank_orders_by_overlap(offline: OfflineProvider) -> None:
    results = await offline.rerank(
        "failed login brute force", ["brute force login failures", "weather report"]
    )
    assert results[0].index == 0 and results[0].score >= results[1].score


async def test_gateway_defaults_to_offline() -> None:
    gw = ProviderGateway(Settings(provider=ProviderKind.OFFLINE))
    assert gw.provider_name == "offline"
    resp = await gw.chat(ChatRequest(messages=[ChatMessage(role="user", content="hi")]))
    assert resp.offline is True
    assert gw.embedding_model_id().startswith("offline:")


async def test_gateway_switch_changes_provider() -> None:
    gw = ProviderGateway(Settings(provider=ProviderKind.OFFLINE))
    assert gw.provider_name == "offline"
    gw.switch(provider=ProviderKind.OLLAMA, model="qwen3:8b")
    assert gw.provider_name == "ollama"
    assert gw.model == "qwen3:8b"


async def test_gateway_embed_fallback_for_provider_without_embeddings() -> None:
    # Anthropic has no embeddings API; the gateway must still return embeddings (offline fallback).
    gw = ProviderGateway(Settings(provider=ProviderKind.ANTHROPIC, anthropic_api_key="x"))
    vecs = await gw.embed(["some case text"])
    assert len(vecs) == 1 and len(vecs[0]) == 256
    assert gw.embedding_model_id().startswith("offline:")
