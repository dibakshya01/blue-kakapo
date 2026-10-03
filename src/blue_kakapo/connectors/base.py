"""The Connector SDK — one capability-declaring contract for every integration.

A connector declares which capabilities it supports (read_alerts / query / enrich / act) and, for each
action verb, its **reversibility** and **required scope**. The orchestrator and the Guardian use these
declarations to decide what is even *possible* before anything runs — you can't gate what you don't
know about. Every connector also exposes a **native-query escape hatch** where it wraps a query engine
(true cross-vendor query abstraction is lossy), and reports health.

Reference connectors (mock SIEM/EDR, file/syslog ingest, Wazuh, Elastic) implement this; real vendor
adapters (Splunk, Sentinel, CrowdStrike, ...) are a community-extensible roadmap.
"""

from __future__ import annotations

import datetime as _dt
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from pydantic import Field

from ..schema.actions import Action
from ..schema.common import BKModel
from ..schema.models import Alert, Evidence
from ..schema.ocsf import Observable


class Capability(StrEnum):
    READ_ALERTS = "read_alerts"
    QUERY = "query"
    ENRICH = "enrich"
    ACT = "act"


class ActionSpec(BKModel):
    """What a connector declares about an action it can perform — used by the Guardian for gating."""

    verb: str
    reversible: bool
    reverse_verb: str | None = Field(default=None, description="The inverse action, if reversible.")
    required_scope: str = Field(default="", description="Least-privilege scope this action needs.")
    description: str = ""


class ConnectorInfo(BKModel):
    """Static description of a connector instance."""

    name: str
    kind: str
    capabilities: list[Capability]
    actions: list[ActionSpec] = Field(default_factory=list)
    supports_native_query: bool = False


class ActionResult(BKModel):
    verb: str
    target: str
    status: str = Field(default="ok", description="ok | dry_run | failed | denied")
    reversible: bool = True
    idempotency_key: str | None = None
    detail: str = ""
    executed_at: _dt.datetime = Field(default_factory=lambda: _dt.datetime.now(_dt.UTC))
    raw: dict[str, Any] = Field(default_factory=dict)


class QueryResult(BKModel):
    rows: list[dict[str, Any]] = Field(default_factory=list)
    count: int = 0
    raw: dict[str, Any] = Field(default_factory=dict)


class HealthStatus(BKModel):
    healthy: bool
    detail: str = ""


class ConnectorError(RuntimeError):
    """Raised on connector failures (auth, network, unsupported capability)."""


@runtime_checkable
class Connector(Protocol):
    """The contract. Methods raise ConnectorError for unsupported capabilities."""

    def info(self) -> ConnectorInfo: ...

    async def health(self) -> HealthStatus: ...

    async def read_alerts(
        self, *, tenant_id: str, since: _dt.datetime | None = None, limit: int = 100
    ) -> list[Alert]: ...

    async def query(
        self, *, tenant_id: str, native_query: str, limit: int = 100
    ) -> QueryResult: ...

    async def enrich(self, *, tenant_id: str, observable: Observable) -> list[Evidence]: ...

    async def act(self, action: Action, *, dry_run: bool = False) -> ActionResult: ...


class BaseConnector:
    """Convenience base: declares no capabilities and raises for everything until overridden."""

    kind: str = "base"

    def __init__(self, name: str) -> None:
        self.name = name

    def info(self) -> ConnectorInfo:  # pragma: no cover - overridden
        return ConnectorInfo(name=self.name, kind=self.kind, capabilities=[])

    async def health(self) -> HealthStatus:
        return HealthStatus(healthy=True, detail="base connector")

    async def read_alerts(
        self, *, tenant_id: str, since: _dt.datetime | None = None, limit: int = 100
    ) -> list[Alert]:
        raise ConnectorError(f"{self.name}: read_alerts not supported")

    async def query(self, *, tenant_id: str, native_query: str, limit: int = 100) -> QueryResult:
        raise ConnectorError(f"{self.name}: query not supported")

    async def enrich(self, *, tenant_id: str, observable: Observable) -> list[Evidence]:
        raise ConnectorError(f"{self.name}: enrich not supported")

    async def act(self, action: Action, *, dry_run: bool = False) -> ActionResult:
        raise ConnectorError(f"{self.name}: act not supported")
