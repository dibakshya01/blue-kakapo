"""Wazuh connector — read alerts from the Wazuh indexer (OpenSearch) + active-response act.

Wazuh stores alerts in its indexer (an OpenSearch index ``wazuh-alerts-*``), while containment goes
through the manager's **Active Response** API. This adapter maps Wazuh alert documents to OCSF Alerts
and exposes active-response commands as capability-declared actions. HTTP via httpx; the alert mapping
is contract-tested with ``respx``.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any

import httpx

from ..schema.actions import Action
from ..schema.common import Severity
from ..schema.models import Alert
from ..schema.ocsf import Event, Observable, ObservableType
from .base import (
    ActionResult,
    ActionSpec,
    BaseConnector,
    Capability,
    ConnectorError,
    ConnectorInfo,
    HealthStatus,
)


def _severity_from_level(level: int) -> str:
    if level >= 12:
        return Severity.CRITICAL
    if level >= 8:
        return Severity.HIGH
    if level >= 4:
        return Severity.MEDIUM
    if level >= 1:
        return Severity.LOW
    return Severity.INFORMATIONAL


def map_wazuh_alert(doc: dict[str, Any], *, tenant_id: str, source: str = "wazuh") -> Alert:
    """Map a Wazuh alert document (``_source``) to an OCSF-aligned Alert."""
    rule = doc.get("rule", {}) or {}
    agent = doc.get("agent", {}) or {}
    data = doc.get("data", {}) or {}
    level = int(rule.get("level", 0) or 0)
    severity = _severity_from_level(level)

    obs: list[Observable] = []
    if agent.get("ip"):
        obs.append(Observable(type=ObservableType.IP, value=str(agent["ip"])))
    if agent.get("name"):
        obs.append(Observable(type=ObservableType.HOSTNAME, value=str(agent["name"])))
    for key, otype, pii in (
        ("srcip", ObservableType.IP, False),
        ("dstip", ObservableType.IP, False),
        ("srcuser", ObservableType.USER, True),
        ("dstuser", ObservableType.USER, True),
    ):
        if data.get(key):
            obs.append(Observable(type=otype, value=str(data[key]), contains_pii=pii))

    techniques = []
    mitre = rule.get("mitre", {}) or {}
    if mitre.get("id"):
        techniques = (
            [str(t) for t in mitre["id"]] if isinstance(mitre["id"], list) else [str(mitre["id"])]
        )

    event = Event(
        tenant_id=tenant_id,
        source=source,
        product="Wazuh",
        severity=severity,
        class_uid=2004,
        message=str(rule.get("description", "Wazuh alert")),
        observables=obs,
        raw=doc,
        metadata={"wazuh_rule_level": level, "agent_id": agent.get("id")},
    )
    return Alert(
        tenant_id=tenant_id,
        title=str(rule.get("description", "Wazuh alert"))[:300],
        source=source,
        severity=severity,
        rule_id=str(rule.get("id")) if rule.get("id") else None,
        rule_name=str(rule.get("description")) if rule.get("description") else None,
        attack_techniques=techniques,
        events=[event],
        raw=doc,
    )


class WazuhConnector(BaseConnector):
    kind = "wazuh"

    _ACTIONS = [
        ActionSpec(
            verb="firewall_drop",
            reversible=True,
            reverse_verb="firewall_allow",
            required_scope="active-response",
            description="Block an IP via active-response firewall-drop.",
        ),
        ActionSpec(verb="restart_agent", reversible=False, required_scope="active-response"),
    ]

    def __init__(
        self,
        *,
        indexer_url: str,
        manager_url: str,
        username: str,
        password: str,
        name: str = "wazuh",
        verify_tls: bool = True,
        timeout: float = 30.0,
    ) -> None:
        super().__init__(name)
        self.indexer_url = indexer_url.rstrip("/")
        self.manager_url = manager_url.rstrip("/")
        self.username = username
        self.password = password
        self.verify_tls = verify_tls
        self.timeout = timeout

    def info(self) -> ConnectorInfo:
        return ConnectorInfo(
            name=self.name,
            kind=self.kind,
            capabilities=[Capability.READ_ALERTS, Capability.QUERY, Capability.ACT],
            actions=list(self._ACTIONS),
            supports_native_query=True,
        )

    async def read_alerts(
        self, *, tenant_id: str, since: _dt.datetime | None = None, limit: int = 100
    ) -> list[Alert]:
        query: dict[str, Any] = {
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {"match_all": {}},
        }
        if since is not None:
            query["query"] = {"range": {"timestamp": {"gte": since.isoformat()}}}
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=self.verify_tls) as client:
                resp = await client.post(
                    f"{self.indexer_url}/wazuh-alerts-*/_search",
                    json=query,
                    auth=(self.username, self.password),
                )
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPError as exc:
            raise ConnectorError(f"wazuh read_alerts failed: {exc}") from exc
        hits = (data.get("hits", {}) or {}).get("hits", [])
        return [
            map_wazuh_alert(h.get("_source", {}), tenant_id=tenant_id, source=self.name)
            for h in hits
        ]

    async def query(self, *, tenant_id: str, native_query: str, limit: int = 100) -> Any:
        from .base import QueryResult

        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=self.verify_tls) as client:
                resp = await client.post(
                    f"{self.indexer_url}/wazuh-alerts-*/_search",
                    content=native_query,
                    headers={"Content-Type": "application/json"},
                    auth=(self.username, self.password),
                )
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPError as exc:
            raise ConnectorError(f"wazuh query failed: {exc}") from exc
        hits = (data.get("hits", {}) or {}).get("hits", [])
        return QueryResult(rows=[h.get("_source", {}) for h in hits], count=len(hits), raw=data)

    async def _authenticate(self, client: httpx.AsyncClient) -> str:
        resp = await client.post(
            f"{self.manager_url}/security/user/authenticate", auth=(self.username, self.password)
        )
        resp.raise_for_status()
        return resp.json()["data"]["token"]

    async def act(self, action: Action, *, dry_run: bool = False) -> ActionResult:
        spec = next((s for s in self._ACTIONS if s.verb == action.verb), None)
        if spec is None:
            raise ConnectorError(f"{self.name}: unsupported action {action.verb!r}")
        command = {"firewall_drop": "firewall-drop", "restart_agent": "restart-wazuh"}[action.verb]
        if dry_run or action.dry_run:
            return ActionResult(
                verb=action.verb,
                target=action.target,
                status="dry_run",
                reversible=spec.reversible,
                idempotency_key=action.idempotency_key,
                detail=f"[dry-run] active-response {command} on {action.target}",
            )
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=self.verify_tls) as client:
                token = await self._authenticate(client)
                resp = await client.put(
                    f"{self.manager_url}/active-response",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"command": command, "agents_list": [action.target]},
                )
                resp.raise_for_status()
                raw = resp.json()
        except (httpx.HTTPError, KeyError) as exc:
            raise ConnectorError(f"wazuh act failed: {exc}") from exc
        return ActionResult(
            verb=action.verb,
            target=action.target,
            status="ok",
            reversible=spec.reversible,
            idempotency_key=action.idempotency_key,
            detail=f"active-response {command} sent",
            raw=raw,
        )

    async def health(self) -> HealthStatus:
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=self.verify_tls) as client:
                resp = await client.get(
                    f"{self.indexer_url}/_cluster/health", auth=(self.username, self.password)
                )
                resp.raise_for_status()
            return HealthStatus(healthy=True, detail="indexer reachable")
        except httpx.HTTPError as exc:
            return HealthStatus(healthy=False, detail=str(exc))
