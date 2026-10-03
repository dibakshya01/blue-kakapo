"""Deterministic mock connectors — a SIEM (read/query/enrich) and an EDR (act).

These make the platform fully exercisable offline and in tests: the mock SIEM emits a stable set of
synthetic alerts, and the mock EDR records containment actions with correct reversibility, dry-run,
and idempotency semantics (state kept in memory). No real system is touched.
"""

from __future__ import annotations

import datetime as _dt

from ..normalize import normalize_alert
from ..schema.actions import Action
from ..schema.models import Alert, Evidence
from ..schema.ocsf import Observable
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

_SAMPLE_ALERTS: list[dict] = [
    {
        "title": "Outbound connection to known C2",
        "severity": "high",
        "rule_name": "C2 beacon detected",
        "src_ip": "10.0.0.14",
        "dst_ip": "198.51.100.23",
        "user": "svc-web",
        "domain": "malware.example",
        "attack_techniques": ["T1071"],
        "message": "Host contacted malware.example over HTTPS",
    },
    {
        "title": "Scheduled backup login",
        "severity": "low",
        "rule_name": "Successful login (test)",
        "src_ip": "10.0.0.9",
        "user": "backup-svc",
        "domain": "internal.example",
        "message": "Routine scheduled backup job authenticated",
    },
    {
        "title": "Encoded PowerShell execution",
        "severity": "medium",
        "rule_name": "Suspicious PowerShell exploit attempt",
        "host": "WS-204",
        "user": "jdoe",
        "message": "Possible credential access via encoded PowerShell",
        "attack_techniques": ["T1059.001"],
    },
]


class MockSIEM(BaseConnector):
    kind = "mock-siem"

    def __init__(self, name: str = "mock-siem") -> None:
        super().__init__(name)

    def info(self) -> ConnectorInfo:
        return ConnectorInfo(
            name=self.name,
            kind=self.kind,
            capabilities=[Capability.READ_ALERTS, Capability.QUERY, Capability.ENRICH],
            supports_native_query=True,
        )

    async def read_alerts(
        self, *, tenant_id: str, since: _dt.datetime | None = None, limit: int = 100
    ) -> list[Alert]:
        return [
            normalize_alert(a, tenant_id=tenant_id, source=self.name)
            for a in _SAMPLE_ALERTS[:limit]
        ]

    async def query(self, *, tenant_id: str, native_query: str, limit: int = 100) -> QueryResult:
        # Deterministic echo result — proves the native-query escape hatch end-to-end.
        rows = [{"query": native_query, "tenant_id": tenant_id, "matched": len(_SAMPLE_ALERTS)}]
        return QueryResult(rows=rows, count=len(rows), raw={"engine": "mock"})

    async def enrich(self, *, tenant_id: str, observable: Observable) -> list[Evidence]:
        # Deterministic enrichment: a stable "seen count" derived from the value length.
        seen = (len(observable.value) % 5) + 1
        return [
            Evidence(
                tenant_id=tenant_id,
                source=self.name,
                connector=self.name,
                query=f"search {observable.type}={observable.value}",
                summary=f"{observable.type} {observable.value} seen {seen} time(s) in the last 24h.",
                supports="context",
            )
        ]


class MockEDR(BaseConnector):
    kind = "mock-edr"

    _ACTIONS = [
        ActionSpec(
            verb="isolate_host",
            reversible=True,
            reverse_verb="unisolate_host",
            required_scope="edr:isolate",
            description="Network-isolate a host.",
        ),
        ActionSpec(verb="unisolate_host", reversible=False, required_scope="edr:isolate"),
        ActionSpec(
            verb="disable_user",
            reversible=True,
            reverse_verb="enable_user",
            required_scope="idp:disable",
            description="Disable a user account.",
        ),
        ActionSpec(verb="enable_user", reversible=False, required_scope="idp:disable"),
        ActionSpec(
            verb="block_ioc", reversible=True, reverse_verb="unblock_ioc", required_scope="edr:ioc"
        ),
        ActionSpec(verb="unblock_ioc", reversible=False, required_scope="edr:ioc"),
        ActionSpec(
            verb="kill_process",
            reversible=False,
            required_scope="edr:kill",
            description="Terminate a process (irreversible).",
        ),
    ]

    def __init__(self, name: str = "mock-edr") -> None:
        super().__init__(name)
        self.isolated_hosts: set[str] = set()
        self.disabled_users: set[str] = set()
        self.blocked_iocs: set[str] = set()
        self._by_idem: dict[str, ActionResult] = {}
        self.action_log: list[ActionResult] = []

    def info(self) -> ConnectorInfo:
        return ConnectorInfo(
            name=self.name,
            kind=self.kind,
            capabilities=[Capability.ACT],
            actions=list(self._ACTIONS),
        )

    def _spec(self, verb: str) -> ActionSpec | None:
        return next((s for s in self._ACTIONS if s.verb == verb), None)

    async def act(self, action: Action, *, dry_run: bool = False) -> ActionResult:
        spec = self._spec(action.verb)
        if spec is None:
            raise ConnectorError(f"{self.name}: unsupported action {action.verb!r}")

        # Idempotency: a repeated key returns the first result without re-applying.
        if action.idempotency_key in self._by_idem:
            return self._by_idem[action.idempotency_key]

        if dry_run or action.dry_run:
            result = ActionResult(
                verb=action.verb,
                target=action.target,
                status="dry_run",
                reversible=spec.reversible,
                idempotency_key=action.idempotency_key,
                detail=f"[dry-run] would {action.verb} {action.target}",
            )
            return result

        if action.verb == "isolate_host":
            self.isolated_hosts.add(action.target)
        elif action.verb == "unisolate_host":
            self.isolated_hosts.discard(action.target)
        elif action.verb == "disable_user":
            self.disabled_users.add(action.target)
        elif action.verb == "enable_user":
            self.disabled_users.discard(action.target)
        elif action.verb == "block_ioc":
            self.blocked_iocs.add(action.target)
        elif action.verb == "unblock_ioc":
            self.blocked_iocs.discard(action.target)

        result = ActionResult(
            verb=action.verb,
            target=action.target,
            status="ok",
            reversible=spec.reversible,
            idempotency_key=action.idempotency_key,
            detail=f"{action.verb} applied to {action.target}",
        )
        self._by_idem[action.idempotency_key] = result
        self.action_log.append(result)
        return result

    async def health(self) -> HealthStatus:
        return HealthStatus(healthy=True, detail=f"{len(self.action_log)} actions applied")


__all__ = ["MockSIEM", "MockEDR"]
