"""FastAPI control-plane application factory.

Wires the shared services (store, ledger, bus, provider gateway, triage orchestrator), the triage
routes, the ops endpoints, and the minimal case UI. Offline by default — no key, no external calls.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse

from .. import __version__
from ..agents import TriageOrchestrator
from ..assets import AssetInventory
from ..config import Settings, get_settings
from ..connectors import ConnectorRegistry, MockEDR, MockSIEM
from ..core import CaseRepo, EventBus, Ledger, Store
from ..guardian import GuardedExecutor, Guardian
from ..logging import configure_logging, get_logger, maybe_setup_otel
from ..memory import MemoryService, build_memory_backend
from ..providers import ProviderGateway
from .routes import router

_STATIC_DIR = Path(__file__).parent / "static"


def create_app(settings: Settings | None = None, *, store: Store | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(level=settings.log_level, json_logs=settings.log_json)
    if settings.otel_enabled:
        maybe_setup_otel(settings.deployment_name, settings.otel_endpoint)
    log = get_logger("blue_kakapo.api")

    app = FastAPI(
        title="blue-kakapo",
        version=__version__,
        description="Open-source agentic SOC — a transparent coworker for L2/L3 analysts.",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    store = store or Store.from_settings(settings)
    gateway = ProviderGateway(settings)
    bus = EventBus()
    ledger = Ledger(store)
    repo = CaseRepo(store)
    memory = MemoryService(build_memory_backend(settings, store), gateway)

    # Default reference connectors so the full agent flow works out of the box (swap for real ones).
    registry = ConnectorRegistry()
    registry.register(MockSIEM())
    registry.register(MockEDR())
    inventory = AssetInventory(store)
    guardian = GuardedExecutor(
        Guardian(
            inventory,
            registry,
            max_concurrent_actions=settings.max_concurrent_actions,
            containment_ttl_seconds=settings.containment_default_ttl_seconds,
        ),
        registry,
        ledger,
        store,
    )
    orchestrator = TriageOrchestrator(
        store,
        gateway,
        bus=bus,
        ledger=ledger,
        memory=memory,
        registry=registry,
        inventory=inventory,
        guardian=guardian,
    )

    app.state.settings = settings
    app.state.store = store
    app.state.gateway = gateway
    app.state.bus = bus
    app.state.ledger = ledger
    app.state.repo = repo
    app.state.memory = memory
    app.state.registry = registry
    app.state.inventory = inventory
    app.state.guardian = guardian
    app.state.orchestrator = orchestrator

    app.include_router(router)

    @app.get("/healthz", tags=["ops"])
    async def healthz() -> dict:
        return {"status": "ok", "version": __version__}

    @app.get("/readyz", tags=["ops"])
    async def readyz() -> dict:
        return {"ready": True, "provider": gateway.provider_name}

    @app.get("/version", tags=["ops"])
    async def version() -> dict:
        return {"name": "blue-kakapo", "version": __version__}

    @app.get("/api/provider", tags=["config"])
    async def provider_status() -> dict:
        return {
            "provider": gateway.provider_name,
            "model": gateway.model,
            "embedding_model_id": gateway.embedding_model_id(),
            "offline": gateway.provider_name == "offline",
            "tenant_default": settings.default_tenant,
        }

    @app.get("/", response_class=HTMLResponse, tags=["ui"])
    async def index() -> FileResponse:
        return FileResponse(_STATIC_DIR / "index.html")

    log.info(
        "api_initialized",
        version=__version__,
        provider=gateway.provider_name,
        offline=gateway.provider_name == "offline",
    )
    return app
