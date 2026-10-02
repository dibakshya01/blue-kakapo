"""FastAPI control-plane application factory.

S0 ships the operational surface: health, readiness, version, and a provider/settings summary (with
secrets redacted). Ingestion, cases, verdicts, approvals, and the WebSocket stream are layered on in
later stages.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .. import __version__
from ..config import Settings, get_settings
from ..logging import configure_logging, get_logger, maybe_setup_otel
from ..providers import ProviderGateway


def create_app(settings: Settings | None = None) -> FastAPI:
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

    gateway = ProviderGateway(settings)
    app.state.settings = settings
    app.state.gateway = gateway

    @app.get("/healthz", tags=["ops"])
    async def healthz() -> dict:
        return {"status": "ok", "version": __version__}

    @app.get("/readyz", tags=["ops"])
    async def readyz() -> dict:
        # Readiness is intentionally conservative; later stages add DB/connector checks.
        return {"ready": True, "provider": gateway.provider_name}

    @app.get("/version", tags=["ops"])
    async def version() -> dict:
        return {"name": "blue-kakapo", "version": __version__}

    @app.get("/api/provider", tags=["config"])
    async def provider_status() -> dict:
        """Current provider config, with secrets redacted — powers the settings UI."""
        return {
            "provider": gateway.provider_name,
            "model": gateway.model,
            "embedding_model_id": gateway.embedding_model_id(),
            "offline": gateway.provider_name == "offline",
            "tenant_default": settings.default_tenant,
        }

    log.info(
        "api_initialized",
        version=__version__,
        provider=gateway.provider_name,
        offline=gateway.provider_name == "offline",
    )
    return app
