"""FastAPI control-plane application factory.

Wires the shared services (store, ledger, bus, provider gateway, triage orchestrator), the triage
routes, the ops endpoints, and the minimal case UI. Offline by default — no key, no external calls.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

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
from ..security import Authenticator, Permission, Principal, build_secret_store, require
from ..security.scim import UserStore
from .routes import router
from .scim import scim_router

_STATIC_DIR = Path(__file__).parent / "static"  # fallback minimal UI
_DASHBOARD_DIR = Path(__file__).resolve().parents[3] / "web" / "dist"  # built React dashboard

# Module-level DI singleton (avoids calling Depends/require in an argument default — ruff B008).
_REQ_VIEW = Depends(require(Permission.VIEW))


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
    # A wildcard origin with credentials is a footgun (and browsers reject the combination); only
    # allow credentials when the operator has pinned explicit origins.
    cors_wildcard = "*" in settings.cors_origins
    if cors_wildcard:
        log.warning("cors_wildcard_origins", detail="allow_credentials forced off for '*' origins")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=not cors_wildcard,
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
    authenticator = Authenticator(settings)
    user_store = UserStore(store)
    authenticator.set_user_store(user_store)
    app.state.authenticator = authenticator
    app.state.user_store = user_store
    app.state.secrets = build_secret_store(settings)

    app.include_router(router)
    app.include_router(scim_router)

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
    async def provider_status(_: Principal = _REQ_VIEW) -> dict:
        return {
            "provider": gateway.provider_name,
            "model": gateway.model,
            "embedding_model_id": gateway.embedding_model_id(),
            "offline": gateway.provider_name == "offline",
            "tenant_default": settings.default_tenant,
        }

    # Serve the built React dashboard if present, else the minimal fallback UI. Mounted LAST so API
    # routes always take precedence over the SPA catch-all.
    ui_dir = _DASHBOARD_DIR if _DASHBOARD_DIR.is_dir() else _STATIC_DIR
    app.mount("/", StaticFiles(directory=str(ui_dir), html=True), name="ui")

    log.info(
        "api_initialized",
        version=__version__,
        provider=gateway.provider_name,
        offline=gateway.provider_name == "offline",
        ui="dashboard" if ui_dir == _DASHBOARD_DIR else "minimal",
    )
    return app
