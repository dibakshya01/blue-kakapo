"""S5: memory subsystem — backends, poisoning defenses, recall, reembed, integration."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from blue_kakapo.agents import TriageOrchestrator
from blue_kakapo.api import create_app
from blue_kakapo.config import ProviderKind, Settings
from blue_kakapo.core import Store
from blue_kakapo.memory import FolderMemoryBackend, MemoryService, SqlMemoryBackend
from blue_kakapo.providers import ProviderGateway
from blue_kakapo.schema.common import MemoryTrustTier
from blue_kakapo.schema.models import Case, Verdict


def _gw() -> ProviderGateway:
    return ProviderGateway(Settings(provider=ProviderKind.OFFLINE))


def _case(title: str, technique: str = "T1486") -> Case:
    c = Case(tenant_id="t1", title=title, severity="high", attack_techniques=[technique])
    c.verdict = Verdict(
        verdict_class="malicious", routing="escalate", confidence=0.9, rationale=title
    )
    return c


async def test_folder_backend_roundtrip(tmp_path: Path) -> None:
    svc = MemoryService(FolderMemoryBackend(tmp_path), _gw())
    rec = await svc.remember(_case("ransomware on finance server"), outcome="confirmed")
    assert rec.trust_tier == MemoryTrustTier.QUARANTINED
    assert await svc.backend.count("t1") == 1
    assert (await svc.backend.get("t1", rec.id)).case_summary.startswith("ransomware")


async def test_sql_backend_roundtrip() -> None:
    svc = MemoryService(SqlMemoryBackend(Store.in_memory()), _gw())
    rec = await svc.remember(_case("c2 beacon"))
    assert await svc.backend.count("t1") == 1
    assert await svc.backend.get("t1", rec.id) is not None
    assert await svc.backend.get("t2", rec.id) is None  # tenant-scoped


async def test_quarantine_blocks_recall_until_promoted(tmp_path: Path) -> None:
    svc = MemoryService(FolderMemoryBackend(tmp_path), _gw())
    rec = await svc.remember(_case("ransomware on finance server"))
    # Quarantined (agent-authored) -> excluded from decisioning.
    assert await svc.recall("t1", "ransomware finance", use_memory=True) == []
    await svc.promote("t1", rec.id, MemoryTrustTier.REVIEWED)
    hits = await svc.recall("t1", "ransomware finance", use_memory=True)
    assert len(hits) == 1 and hits[0].record.id == rec.id


async def test_recall_is_opt_in(tmp_path: Path) -> None:
    svc = MemoryService(FolderMemoryBackend(tmp_path), _gw())
    rec = await svc.remember(_case("ransomware"))
    await svc.promote("t1", rec.id)
    assert await svc.recall("t1", "ransomware", use_memory=False) == []  # opt-out honored


async def test_hybrid_ranking_prefers_relevant(tmp_path: Path) -> None:
    svc = MemoryService(FolderMemoryBackend(tmp_path), _gw())
    a = await svc.remember(_case("ransomware encrypting finance file server"))
    b = await svc.remember(_case("printer offline in lobby", technique="T0000"))
    await svc.promote("t1", a.id)
    await svc.promote("t1", b.id)
    hits = await svc.recall("t1", "ransomware finance server encryption", k=2)
    assert hits and hits[0].record.id == a.id  # the relevant case ranks first


async def test_reembed_on_model_change(tmp_path: Path) -> None:
    gw = _gw()
    svc = MemoryService(FolderMemoryBackend(tmp_path), gw)
    rec = await svc.remember(_case("ransomware"))
    assert svc.needs_reembed(rec) is False
    gw.switch(embedding_model="different-embed")  # operator swaps embedding model
    assert svc.needs_reembed(rec) is True
    # Stale embeddings are excluded from recall until migrated...
    await svc.promote("t1", rec.id)
    assert await svc.recall("t1", "ransomware") == []
    # ...then reembed fixes them.
    assert await svc.reembed("t1") == 1
    assert len(await svc.recall("t1", "ransomware")) == 1


async def test_orchestrator_remembers_and_recalls_promoted(tmp_path: Path) -> None:
    store = Store.in_memory()
    gw = _gw()
    memory = MemoryService(FolderMemoryBackend(tmp_path), gw)
    orch = TriageOrchestrator(store, gw, memory=memory)

    c1 = await orch.triage_alert(
        {"title": "C2 beacon", "severity": "high", "dst_ip": "198.51.100.23"},
        tenant_id="t1",
        memory_enabled=True,
    )
    # One memory was written (quarantined).
    recs = await memory.backend.all("t1")
    assert len(recs) == 1 and recs[0].case_id == c1.id
    await memory.promote("t1", recs[0].id)

    c2 = await orch.triage_alert(
        {"title": "C2 beacon again", "severity": "high", "dst_ip": "198.51.100.23"},
        tenant_id="t1",
        memory_enabled=True,
    )
    assert any(e.source == "memory" and e.supports == "prior_case" for e in c2.evidence)


def test_api_memory_status_and_ingest_flag(tmp_path: Path) -> None:
    app = create_app(
        Settings(provider=ProviderKind.OFFLINE, memory_folder=tmp_path), store=Store.in_memory()
    )
    client = TestClient(app)
    status = client.get("/api/memory/status").json()
    assert status["backend"] == "folder" and status["count"] == 0
    r = client.post(
        "/api/ingest",
        json={
            "alert": {"title": "x", "severity": "high", "dst_ip": "198.51.100.23"},
            "memory_enabled": True,
        },
    )
    assert r.json()["case"]["memory_enabled"] is True
    assert client.get("/api/memory/status").json()["count"] == 1  # remembered
