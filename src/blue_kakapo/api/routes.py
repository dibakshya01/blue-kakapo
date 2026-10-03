"""API routes: ingestion, cases, ledger, response, memory, provider, live events.

Every data route is tenant-scoped to the authenticated principal's tenant and gated by RBAC
permissions (VIEW / TRIAGE / PROPOSE_RESPONSE / MANAGE). With auth disabled (localhost) the implicit
local-admin principal grants all permissions on the default tenant, so dev is zero-friction.
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import AsyncIterator
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from ..agents import TriageOrchestrator
from ..core import CaseRepo, Ledger
from ..schema.models import Case
from ..security import Permission, Principal, require

router = APIRouter(prefix="/api", tags=["triage"])

# Module-level dependency singletons (FastAPI DI; avoids calling Depends/require in arg defaults).
_req_view = Depends(require(Permission.VIEW))
_req_triage = Depends(require(Permission.TRIAGE))
_req_respond = Depends(require(Permission.PROPOSE_RESPONSE))
_req_manage = Depends(require(Permission.MANAGE))


class IngestRequest(BaseModel):
    alert: dict[str, Any] = Field(..., description="The raw alert payload to triage.")
    source: str = Field(default="webhook")
    memory_enabled: bool = Field(default=False, description="Opt-in: consult + write case memory.")


class IngestResponse(BaseModel):
    case: Case


class MemoryLinkRequest(BaseModel):
    folder: str = Field(..., description="Local system folder to create/link for case memory.")


class RespondRequest(BaseModel):
    dry_run: bool = Field(
        default=True, description="Dry-run by default; real actions are Guardian-gated."
    )


class ProviderSwitchRequest(BaseModel):
    provider: str = Field(..., description="offline | anthropic | openai | ollama")
    model: str | None = None
    embedding_model: str | None = None


class OllamaPullRequest(BaseModel):
    model: str = Field(..., description="Local model to pull, e.g. 'qwen3:8b'.")


def _orchestrator(request: Request) -> TriageOrchestrator:
    return request.app.state.orchestrator


def _owned_case(request: Request, case_id: str, principal: Principal) -> Case:
    """Load a case and enforce tenant ownership (cross-tenant access → 404, not 403)."""
    repo: CaseRepo = request.app.state.repo
    case = repo.get(case_id)
    if case is None or case.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=404, detail="case not found")
    return case


@router.post("/ingest", response_model=IngestResponse)
async def ingest(
    req: IngestRequest, request: Request, principal: Principal = _req_triage
) -> IngestResponse:
    """Accept a raw alert, triage it end-to-end, and return the resulting Case (with verdict)."""
    case = await _orchestrator(request).triage_alert(
        req.alert,
        tenant_id=principal.tenant_id,
        source=req.source,
        memory_enabled=req.memory_enabled,
    )
    return IngestResponse(case=case)


@router.get("/cases", response_model=list[Case])
async def list_cases(
    request: Request, limit: int = 100, principal: Principal = _req_view
) -> list[Case]:
    repo: CaseRepo = request.app.state.repo
    return repo.list(principal.tenant_id, limit=limit)


@router.get("/cases/{case_id}", response_model=Case)
async def get_case(case_id: str, request: Request, principal: Principal = _req_view) -> Case:
    return _owned_case(request, case_id, principal)


@router.get("/cases/{case_id}/ledger")
async def get_case_ledger(
    case_id: str, request: Request, principal: Principal = _req_view
) -> dict[str, Any]:
    """Replay the hash-chained decision path for a case (the glass-box trail)."""
    case = _owned_case(request, case_id, principal)
    ledger: Ledger = request.app.state.ledger
    entries = ledger.replay(case.tenant_id, case_id=case_id)
    return {
        "case_id": case_id,
        "verified": ledger.verify(case.tenant_id),
        "entries": [e.model_dump(mode="json") for e in entries],
    }


@router.post("/cases/{case_id}/respond", response_model=Case)
async def respond(
    case_id: str,
    req: RespondRequest,
    request: Request,
    principal: Principal = _req_respond,
) -> Case:
    """Run RESP on a case — Guardian-gated containment, explicit (never part of auto-triage)."""
    _owned_case(request, case_id, principal)  # tenant check
    return await _orchestrator(request).respond(
        case_id, dry_run=req.dry_run, actor_roles=principal.roles
    )


@router.get("/agents")
async def list_agents(request: Request, _: Principal = _req_view) -> list[dict[str, Any]]:
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
async def run_evaluation(request: Request, _: Principal = _req_view) -> dict[str, Any]:
    """Run the evaluation harness on the bundled dataset (reports the false-negative rate)."""
    from ..eval import run_eval

    report = await run_eval(gateway=request.app.state.gateway)
    return report.to_dict()


@router.post("/provider/switch")
async def provider_switch(
    req: ProviderSwitchRequest, request: Request, _: Principal = _req_manage
) -> dict[str, Any]:
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


@router.post("/provider/ollama/pull")
async def ollama_pull(
    req: OllamaPullRequest, request: Request, _: Principal = _req_manage
) -> StreamingResponse:
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


@router.get("/memory/status")
async def memory_status(request: Request, principal: Principal = _req_view) -> dict[str, Any]:
    memory = request.app.state.memory
    return {
        "backend": memory.backend.name,
        "embedding_model": memory.gateway.embedding_model_id(),
        "count": await memory.backend.count(principal.tenant_id),
        "opt_in_default": request.app.state.settings.memory_enabled_default,
    }


@router.post("/memory/link")
async def memory_link(
    req: MemoryLinkRequest, request: Request, _: Principal = _req_manage
) -> dict[str, Any]:
    """Create/link a local folder for case memory and switch the active backend to it (local mode)."""
    from ..memory import FolderMemoryBackend

    backend = FolderMemoryBackend(req.folder)
    request.app.state.memory.backend = backend
    return {"backend": backend.name, "folder": str(backend.folder), "linked": True}


@router.websocket("/ws")
async def live_updates(ws: WebSocket) -> None:
    """Live case/run events for the dashboard (tenant-filtered; token via ?token= when auth enabled)."""
    authenticator = ws.app.state.authenticator
    try:
        token = ws.query_params.get("token")
        principal = authenticator.authenticate(f"Bearer {token}" if token else None)
    except Exception:  # noqa: BLE001 — reject unauthenticated sockets when auth is enabled
        await ws.close(code=4401)
        return
    await ws.accept()
    bus = ws.app.state.bus
    try:
        async with bus.subscribe(topic_prefix="", tenant_id=principal.tenant_id) as queue:
            while True:
                event = await queue.get()
                await ws.send_json({"topic": event.topic, "payload": event.payload, "ts": event.ts})
    except WebSocketDisconnect:
        return
    except Exception:  # noqa: BLE001 — never let a socket error crash the server
        with contextlib.suppress(Exception):
            await ws.close()
