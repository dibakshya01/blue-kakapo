"""API routes: alert ingestion + case retrieval + ledger replay (S2 walking skeleton)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request
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


class IngestResponse(BaseModel):
    case: Case


def _orchestrator(request: Request) -> TriageOrchestrator:
    return request.app.state.orchestrator


@router.post("/ingest", response_model=IngestResponse)
async def ingest(req: IngestRequest, request: Request) -> IngestResponse:
    """Accept a raw alert, triage it end-to-end, and return the resulting Case (with verdict)."""
    orch = _orchestrator(request)
    tenant = req.tenant_id or request.app.state.settings.default_tenant
    case = await orch.triage_alert(req.alert, tenant_id=tenant, source=req.source)
    return IngestResponse(case=case)


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
