"""Structured logging and (optional) OpenTelemetry wiring.

Human-readable logs by default; set ``BK_LOG_JSON=true`` for SIEM-friendly JSON. OpenTelemetry is
off unless ``BK_OTEL_ENABLED=true`` and the ``otel`` extra is installed — the core never hard-depends
on it.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog

_configured = False


def configure_logging(level: str = "INFO", json_logs: bool = False) -> None:
    """Configure structlog + stdlib logging once, idempotently."""
    global _configured
    if _configured:
        return

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, level.upper(), logging.INFO),
    )

    shared: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
    ]
    renderer: Any = (
        structlog.processors.JSONRenderer()
        if json_logs
        else structlog.dev.ConsoleRenderer(colors=sys.stdout.isatty())
    )
    structlog.configure(
        processors=[*shared, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
    _configured = True


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Return a bound structlog logger."""
    if not _configured:
        configure_logging()
    return structlog.get_logger(name)


def maybe_setup_otel(service_name: str, endpoint: str | None) -> None:
    """Best-effort OpenTelemetry tracer setup. No-op if the otel extra is absent."""
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
    except ImportError:  # otel extra not installed — stay silent, core must not require it
        get_logger(__name__).debug("otel_extra_not_installed")
        return

    provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
    trace.set_tracer_provider(provider)
    get_logger(__name__).info("otel_configured", service=service_name, endpoint=endpoint)
