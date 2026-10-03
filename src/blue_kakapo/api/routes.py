"""API routes: alert ingestion + case retrieval + ledger replay (S2 walking skeleton)."""

from __future__ import annotations

import contextlib
import json
from collections.abc import AsyncIterator
from typing import Any

from fastapi import APIRouter, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from ..agents import TriageOrchestrator
from ..core import CaseRepo, Ledger
from ..schema.models import Case

router = APIRouter(prefix="/api", tags=["triage"])


class IngestRequest(BaseModel):
    alert: dict[str, Any] = Field(..., description="The raw alert payload to triage.")
    tenant_id: str | None = Field(
        default=None, description="Defaults to the deployment's default tenant."
    )
    source: str = Field(default="webhook")
    memory_enabled: bool = Field(default=False, description="Opt-in: consult + write case memory.")


class IngestResponse(BaseModel):
    case: Case


class MemoryLinkRequest(BaseModel):
    folder: str = Field(..., description="Local system folder to create/link for case memory.")


def _orchestrator(request: Request) -> TriageOrchestrator:
    return request.app.state.orchestrator


@router.post("/ingest", response_model=IngestResponse)
async def ingest(req: IngestRequest, request: Request) -> IngestResponse:
    """Accept a raw alert, triage it end-to-end, and return the resulting Case (with verdict)."""
    orch = _orchestrator(request)
    tenant = req.tenant_id or request.app.state.settings.default_tenant
    case = await orch.triage_alert(
        req.alert, tenant_id=tenant, source=req.source, memory_enabled=req.memory_enabled
    )
    return IngestResponse(case=case)


class RespondRequest(BaseModel):
    dry_run: bool = Field(
        default=True, description="Dry-run by default; real actions are Guardian-gated."
    )
    actor_roles: list[str] = Field(default_factory=list)


@router.post("/cases/{case_id}/respond", response_model=Case)
async def respond(case_id: str, req: RespondRequest, request: Request) -> Case:
    """Run RESP on a case — Guardian-gated containment, explicit (never part of auto-triage)."""
    orch = _orchestrator(request)
    try:
        return await orch.respond(case_id, dry_run=req.dry_run, actor_roles=req.actor_roles)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/agents")
async def list_agents(request: Request) -> list[dict[str, Any]]:
    """The core-5 agent roster with their AgBOMs (what each can touch)."""
    orch = _orchestrator(request)
    agents = [orch.l1, orch.intel, orch.l2, orch.fusion, orch.resp]
    return [
        {
            "name": a.name,
            "autonomy_level": a.autonomy_level,
            "agbom": a.agbom().model_dump(),
            "rule_of_two": {
                "untrusted_input": a.handles_untrusted_input,
                "sensitive_access": a.holds_sensitive_access,
                "external_state_change": a.changes_external_state,
            },
        }
        for a in agents
    ]


@router.get("/eval")
async def run_evaluation(request: Request) -> dict[str, Any]:
    """Run the evaluation harness on the bundled dataset (reports the false-negative rate)."""
    from ..eval import run_eval

    report = await run_eval(gateway=request.app.state.gateway)
    return report.to_dict()


class ProviderSwitchRequest(BaseModel):
    provider: str = Field(..., description="offline | anthropic | openai | ollama")
    model: str | None = None
    embedding_model: str | None = None


@router.post("/provider/switch")
async def provider_switch(req: ProviderSwitchRequest, request: Request) -> dict[str, Any]:
    """Switch the active LLM provider/model at runtime (no restart)."""
    gateway = request.app.state.gateway
    overrides: dict[str, Any] = {"provider": req.provider}
    if req.model:
        overrides["model"] = req.model
    if req.embedding_model:
        overrides["embedding_model"] = req.embedding_model
    gateway.switch(**overrides)
    return {
        "provider": gateway.provider_name,
        "model": gateway.model,
        "offline": gateway.provider_name == "offline",
    }


class OllamaPullRequest(BaseModel):
    model: str = Field(..., description="Local model to pull, e.g. 'qwen3:8b'.")


@router.post("/provider/ollama/pull")
async def ollama_pull(req: OllamaPullRequest, request: Request) -> StreamingResponse:
    """Stream an Ollama model pull (the local-model bootstrap). NDJSON progress lines."""
    from ..providers import OllamaProvider, ProviderError

    settings = request.app.state.settings
    provider = OllamaProvider(base_url=settings.ollama_base_url)

    async def _stream() -> AsyncIterator[str]:
        try:
            async for progress in provider.pull_model(req.model):
                yield json.dumps(progress) + "\n"
        except ProviderError as exc:
            yield json.dumps({"error": str(exc)}) + "\n"

    return StreamingResponse(_stream(), media_type="application/x-ndjson")


@router.websocket("/ws")
async def live_updates(ws: WebSocket) -> None:
    """Live case/run events for the dashboard (tenant-filtered)."""
    await ws.accept()
    bus = ws.app.state.bus
    tenant = ws.query_params.get("tenant_id") or ws.app.state.settings.default_tenant
    try:
        async with bus.subscribe(topic_prefix="", tenant_id=tenant) as queue:
            while True:
                event = await queue.get()
                await ws.send_json({"topic": event.topic, "payload": event.payload, "ts": event.ts})
    except WebSocketDisconnect:
        return
    except Exception:  # noqa: BLE001 — never let a socket error crash the server
        with contextlib.suppress(Exception):
            await ws.close()


@router.get("/memory/status")
async def memory_status(request: Request, tenant_id: str | None = None) -> dict[str, Any]:
    memory = request.app.state.memory
    tenant = tenant_id or request.app.state.settings.default_tenant
    return {
        "backend": memory.backend.name,
        "embedding_model": memory.gateway.embedding_model_id(),
        "count": await memory.backend.count(tenant),
        "opt_in_default": request.app.state.settings.memory_enabled_default,
    }


@router.post("/memory/link")
async def memory_link(req: MemoryLinkRequest, request: Request) -> dict[str, Any]:
    """Create/link a local folder for case memory and switch the active backend to it (local mode)."""
    from ..memory import FolderMemoryBackend

    backend = FolderMemoryBackend(req.folder)
    request.app.state.memory.backend = backend
    return {"backend": backend.name, "folder": str(backend.folder), "linked": True}


@router.get("/cases", response_model=list[Case])
async def list_cases(
    request: Request, tenant_id: str | None = None, limit: int = 100
) -> list[Case]:
    repo: CaseRepo = request.app.state.repo
    tenant = tenant_id or request.app.state.settings.default_tenant
    return repo.list(tenant, limit=limit)


@router.get("/cases/{case_id}", response_model=Case)
async def get_case(case_id: str, request: Request) -> Case:
    repo: CaseRepo = request.app.state.repo
    case = repo.get(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    return case


@router.get("/cases/{case_id}/ledger")
async def get_case_ledger(case_id: str, request: Request) -> dict[str, Any]:
    """Replay the hash-chained decision path for a case (the glass-box trail)."""
    repo: CaseRepo = request.app.state.repo
    ledger: Ledger = request.app.state.ledger
    case = repo.get(case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    entries = ledger.replay(case.tenant_id, case_id=case_id)
    return {
        "case_id": case_id,
        "verified": ledger.verify(case.tenant_id),
        "entries": [e.model_dump(mode="json") for e in entries],
    }
