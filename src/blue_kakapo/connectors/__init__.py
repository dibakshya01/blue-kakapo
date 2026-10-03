"""blue-kakapo connector SDK + reference connectors (mock SIEM/EDR, file/syslog, Wazuh, Elastic, MCP)."""

from __future__ import annotations

from .base import (
    ActionResult,
    ActionSpec,
    BaseConnector,
    Capability,
    Connector,
    ConnectorError,
    ConnectorInfo,
    HealthStatus,
    QueryResult,
)
from .elastic import ElasticConnector, map_elastic_alert
from .ingest import FileIngestConnector, parse_syslog_line
from .mcp import MCPClient, MCPRugPullError, MCPSchemaError, ToolDef, compute_fingerprint
from .mock import MockEDR, MockSIEM
from .registry import ConnectorRegistry
from .wazuh import WazuhConnector, map_wazuh_alert

__all__ = [
    "Capability",
    "Connector",
    "BaseConnector",
    "ConnectorInfo",
    "ConnectorError",
    "ActionSpec",
    "ActionResult",
    "QueryResult",
    "HealthStatus",
    "ConnectorRegistry",
    "MockSIEM",
    "MockEDR",
    "FileIngestConnector",
    "parse_syslog_line",
    "WazuhConnector",
    "map_wazuh_alert",
    "ElasticConnector",
    "map_elastic_alert",
    "MCPClient",
    "MCPRugPullError",
    "MCPSchemaError",
    "ToolDef",
    "compute_fingerprint",
]
