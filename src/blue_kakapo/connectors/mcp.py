"""MCP (Model Context Protocol) client with tool-manifest fingerprint pinning.

MCP lets agents use external tool servers — but it introduces **tool poisoning** (malicious
instructions hidden in a tool's description/schema) and **rug-pulls** (a tool's definition changes
after you approved it). Defenses here (OWASP MCP Top 10):

- **Fingerprint pinning:** on connect we hash the full tool manifest (names + descriptions + schemas)
  and pin it. Before every call we re-fetch and re-hash; a mismatch raises ``MCPRugPullError`` and the
  call is refused until a human re-approves the new fingerprint.
- **Argument validation:** tool arguments are validated against the tool's declared input schema
  before the call.
- **Descriptions are data, never instructions:** tool descriptions are surfaced as metadata only;
  the agent layer + Guardian decide whether/how to call — the model is never told to obey them.

Transport is injected, so this is testable without a live server; a real HTTP/stdio transport
implements the same ``Transport`` protocol.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Protocol, runtime_checkable

from ..schema.common import BKModel


class MCPError(RuntimeError):
    pass


class MCPRugPullError(MCPError):
    """The tool manifest changed after it was pinned — refuse until re-approved."""


class MCPSchemaError(MCPError):
    """Arguments did not satisfy a tool's declared input schema."""


class ToolDef(BKModel):
    name: str
    description: str = ""
    input_schema: dict[str, Any] = {}


@runtime_checkable
class Transport(Protocol):
    async def list_tools(self) -> list[dict[str, Any]]: ...
    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]: ...


def compute_fingerprint(tools: list[ToolDef]) -> str:
    """Stable hash over the full tool surface — any change to names/descriptions/schemas changes it."""
    canon = json.dumps(
        [t.model_dump() for t in sorted(tools, key=lambda x: x.name)],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def _validate_args(schema: dict[str, Any], arguments: dict[str, Any]) -> None:
    """Minimal JSON-schema check: required keys present, declared top-level types roughly match."""
    required = schema.get("required", [])
    for key in required:
        if key not in arguments:
            raise MCPSchemaError(f"missing required argument: {key!r}")
    props = schema.get("properties", {})
    type_map: dict[str, type | tuple[type, ...]] = {
        "string": str,
        "integer": int,
        "number": (int, float),
        "boolean": bool,
        "object": dict,
        "array": list,
    }
    for key, value in arguments.items():
        spec = props.get(key)
        if not spec or "type" not in spec:
            continue
        expected = type_map.get(spec["type"])
        if expected and not isinstance(value, expected):
            raise MCPSchemaError(f"argument {key!r} should be {spec['type']}")


class MCPClient:
    """A pinned MCP client. Call ``connect()`` once to pin, then ``call(name, args)``."""

    def __init__(self, transport: Transport, *, server_name: str = "mcp") -> None:
        self.transport = transport
        self.server_name = server_name
        self._pinned_fingerprint: str | None = None
        self._tools: dict[str, ToolDef] = {}

    async def _fetch_tools(self) -> list[ToolDef]:
        return [ToolDef.model_validate(t) for t in await self.transport.list_tools()]

    async def connect(self) -> str:
        """Fetch + pin the current tool manifest. Returns the pinned fingerprint."""
        tools = await self._fetch_tools()
        self._tools = {t.name: t for t in tools}
        self._pinned_fingerprint = compute_fingerprint(tools)
        return self._pinned_fingerprint

    @property
    def pinned_fingerprint(self) -> str | None:
        return self._pinned_fingerprint

    def tools(self) -> list[ToolDef]:
        return list(self._tools.values())

    async def _verify_not_rugpulled(self) -> None:
        if self._pinned_fingerprint is None:
            raise MCPError("client not connected/pinned; call connect() first")
        current = await self._fetch_tools()
        if compute_fingerprint(current) != self._pinned_fingerprint:
            raise MCPRugPullError(
                f"{self.server_name}: tool manifest changed since pinning — refusing (re-approval required)"
            )
        self._tools = {t.name: t for t in current}

    async def call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Call a tool, after verifying the manifest is unchanged and validating arguments."""
        await self._verify_not_rugpulled()
        tool = self._tools.get(name)
        if tool is None:
            raise MCPError(f"{self.server_name}: unknown tool {name!r}")
        _validate_args(tool.input_schema, arguments)
        return await self.transport.call_tool(name, arguments)

    def repin(self) -> None:
        """Explicitly clear the pin so the next connect() re-approves a changed manifest."""
        self._pinned_fingerprint = None
        self._tools = {}
