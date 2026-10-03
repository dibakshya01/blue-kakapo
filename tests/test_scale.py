"""S7: backpressure under flood, live event stream, runtime provider switch."""

from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi.testclient import TestClient

from blue_kakapo.agents import TriageOrchestrator
from blue_kakapo.api import create_app
from blue_kakapo.config import ProviderKind, Settings
from blue_kakapo.core import EventBus, Store


def _gw():
    from blue_kakapo.providers import ProviderGateway

    return ProviderGateway(Settings(provider=ProviderKind.OFFLINE))


async def test_flood_is_bounded_and_lossless(tmp_path: Path) -> None:
    # Use a real file-backed store (per-thread connections + SQLite busy-timeout) — the production
    # concurrency path — rather than the single-connection in-memory StaticPool.
    store = Store.from_settings(Settings(data_dir=tmp_path))
    orch = TriageOrchestrator(store, _gw(), max_concurrent_cases=8)

    # Instrument the engine to record peak concurrency.
    peak = {"now": 0, "max": 0}
    original = orch.engine.run

    async def tracked(graph, ctx, **kw):
        peak["now"] += 1
        peak["max"] = max(peak["max"], peak["now"])
        try:
            return await original(graph, ctx, **kw)
        finally:
            peak["now"] -= 1

    orch.engine.run = tracked  # type: ignore[assignment]

    n = 60  # a flood far exceeding the cap
    cases = await asyncio.gather(
        *(
            orch.triage_alert({"title": f"alert {i}", "severity": "medium"}, tenant_id="t1")
            for i in range(n)
        )
    )
    assert len(cases) == n  # lossless
    assert len({c.id for c in cases}) == n  # all distinct
    assert peak["max"] <= 8  # backpressure held the cap
    assert orch.ledger.verify("t1") is True


async def test_triage_publishes_live_events() -> None:
    store = Store.in_memory()
    bus = EventBus()
    orch = TriageOrchestrator(store, _gw(), bus=bus)

    received: list[str] = []

    async def consume() -> None:
        async with bus.subscribe(tenant_id="t1") as q:
            while True:
                ev = await q.get()
                received.append(ev.payload.get("action", ev.topic))

    task = asyncio.create_task(consume())
    await asyncio.sleep(0)  # let the subscriber register
    await orch.triage_alert(
        {"title": "beacon", "severity": "high", "dst_ip": "198.51.100.23"}, tenant_id="t1"
    )
    await asyncio.sleep(0.05)
    task.cancel()
    assert any("node.enter:intake" in a or "l1.verdict" in a for a in received)


def test_provider_switch_endpoint() -> None:
    app = create_app(Settings(provider=ProviderKind.OFFLINE), store=Store.in_memory())
    client = TestClient(app)
    assert client.get("/api/provider").json()["offline"] is True
    r = client.post("/api/provider/switch", json={"provider": "ollama", "model": "qwen3:8b"})
    assert r.json()["provider"] == "ollama" and r.json()["model"] == "qwen3:8b"
    # switch back
    assert (
        client.post("/api/provider/switch", json={"provider": "offline"}).json()["offline"] is True
    )


def test_websocket_connects() -> None:
    app = create_app(Settings(provider=ProviderKind.OFFLINE), store=Store.in_memory())
    client = TestClient(app)
    with client.websocket_connect("/api/ws?tenant_id=default") as ws:
        # Trigger an event and expect at least one live message.
        client.post(
            "/api/ingest",
            json={"alert": {"title": "x", "severity": "high", "dst_ip": "198.51.100.23"}},
        )
        msg = ws.receive_json()
        assert "topic" in msg and "payload" in msg
