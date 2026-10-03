"""Elastic Security connector — read detection alerts + endpoint isolate/unisolate.

Reads from the ``.alerts-security.alerts-*`` index (ECS) and maps to OCSF Alerts; containment uses the
Elastic Defend endpoint response actions API. HTTP via httpx (API-key auth); alert mapping is
contract-tested with ``respx``.
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
    QueryResult,
)

_ECS_SEVERITY = {
    "informational": Severity.INFORMATIONAL,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


def _dig(d: dict[str, Any], path: str) -> Any:
    cur: Any = d
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def map_elastic_alert(src: dict[str, Any], *, tenant_id: str, source: str = "elastic") -> Alert:
    """Map an ECS security-alert ``_source`` document to an OCSF-aligned Alert."""
    name = _dig(src, "kibana.alert.rule.name") or _dig(src, "rule.name") or "Elastic detection"
    severity = _ECS_SEVERITY.get(
        str(_dig(src, "kibana.alert.severity") or "medium").lower(), Severity.MEDIUM
    )

    obs: list[Observable] = []
    for path, otype, pii in (
        ("host.name", ObservableType.HOSTNAME, False),
        ("source.ip", ObservableType.IP, False),
        ("destination.ip", ObservableType.IP, False),
        ("user.name", ObservableType.USER, True),
    ):
        val = _dig(src, path)
        if val:
            obs.append(Observable(type=otype, value=str(val), contains_pii=pii))

    techniques: list[str] = []
    threats = _dig(src, "kibana.alert.rule.threat") or _dig(src, "threat") or []
    if isinstance(threats, list):
        for t in threats:
            for tech in (t.get("technique") or []) if isinstance(t, dict) else []:
                if tech.get("id"):
                    techniques.append(str(tech["id"]))

    message = _dig(src, "kibana.alert.reason") or _dig(src, "message") or str(name)
    event = Event(
        tenant_id=tenant_id,
        source=source,
        product="Elastic Security",
        severity=severity,
        class_uid=2004,
        message=str(message),
        observables=obs,
        raw=src,
    )
    return Alert(
        tenant_id=tenant_id,
        title=str(name)[:300],
        source=source,
        severity=severity,
        rule_name=str(name),
        attack_techniques=techniques,
        events=[event],
        raw=src,
    )


class ElasticConnector(BaseConnector):
    kind = "elastic"

    _ACTIONS = [
        ActionSpec(
            verb="isolate_host",
            reversible=True,
            reverse_verb="unisolate_host",
            required_scope="endpoint:isolate",
            description="Isolate an Elastic Defend endpoint.",
        ),
        ActionSpec(verb="unisolate_host", reversible=False, required_scope="endpoint:isolate"),
    ]

    def __init__(
        self,
        *,
        es_url: str,
        kibana_url: str,
        api_key: str,
        name: str = "elastic",
        verify_tls: bool = True,
        timeout: float = 30.0,
    ) -> None:
        super().__init__(name)
        self.es_url = es_url.rstrip("/")
        self.kibana_url = kibana_url.rstrip("/")
        self.api_key = api_key
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

    def _es_headers(self) -> dict[str, str]:
        return {"Authorization": f"ApiKey {self.api_key}", "Content-Type": "application/json"}

    async def read_alerts(
        self, *, tenant_id: str, since: _dt.datetime | None = None, limit: int = 100
    ) -> list[Alert]:
        query: dict[str, Any] = {
            "size": limit,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {"match_all": {}},
        }
        if since is not None:
            query["query"] = {"range": {"@timestamp": {"gte": since.isoformat()}}}
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=self.verify_tls) as client:
                resp = await client.post(
                    f"{self.es_url}/.alerts-security.alerts-*/_search",
                    headers=self._es_headers(),
                    json=query,
                )
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPError as exc:
            raise ConnectorError(f"elastic read_alerts failed: {exc}") from exc
        hits = (data.get("hits", {}) or {}).get("hits", [])
        return [
            map_elastic_alert(h.get("_source", {}), tenant_id=tenant_id, source=self.name)
            for h in hits
        ]

    async def query(self, *, tenant_id: str, native_query: str, limit: int = 100) -> QueryResult:
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=self.verify_tls) as client:
                resp = await client.post(
                    f"{self.es_url}/_search", headers=self._es_headers(), content=native_query
                )
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPError as exc:
            raise ConnectorError(f"elastic query failed: {exc}") from exc
        hits = (data.get("hits", {}) or {}).get("hits", [])
        return QueryResult(rows=[h.get("_source", {}) for h in hits], count=len(hits), raw=data)

    async def act(self, action: Action, *, dry_run: bool = False) -> ActionResult:
        spec = next((s for s in self._ACTIONS if s.verb == action.verb), None)
        if spec is None:
            raise ConnectorError(f"{self.name}: unsupported action {action.verb!r}")
        endpoint = {"isolate_host": "isolate", "unisolate_host": "unisolate"}[action.verb]
        if dry_run or action.dry_run:
            return ActionResult(
                verb=action.verb,
                target=action.target,
                status="dry_run",
                reversible=spec.reversible,
                idempotency_key=action.idempotency_key,
                detail=f"[dry-run] {endpoint} {action.target}",
            )
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=self.verify_tls) as client:
                resp = await client.post(
                    f"{self.kibana_url}/api/endpoint/action/{endpoint}",
                    headers={
                        "Authorization": f"ApiKey {self.api_key}",
                        "kbn-xsrf": "blue-kakapo",
                        "Content-Type": "application/json",
                    },
                    json={"endpoint_ids": [action.target], "comment": "blue-kakapo containment"},
                )
                resp.raise_for_status()
                raw = resp.json()
        except httpx.HTTPError as exc:
            raise ConnectorError(f"elastic act failed: {exc}") from exc
        return ActionResult(
            verb=action.verb,
            target=action.target,
            status="ok",
            reversible=spec.reversible,
            idempotency_key=action.idempotency_key,
            detail=f"endpoint {endpoint} requested",
            raw=raw,
        )

    async def health(self) -> HealthStatus:
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=self.verify_tls) as client:
                resp = await client.get(
                    f"{self.es_url}/_cluster/health", headers=self._es_headers()
                )
                resp.raise_for_status()
            return HealthStatus(healthy=True, detail="cluster reachable")
        except httpx.HTTPError as exc:
            return HealthStatus(healthy=False, detail=str(exc))
