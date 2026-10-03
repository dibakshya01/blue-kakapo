"""File + syslog ingestion.

``FileIngestConnector`` reads alerts from a ``.json`` (array) or ``.jsonl`` file, or every such file in
a directory, and normalizes them to OCSF Alerts. ``parse_syslog_line`` turns an RFC 3164/5424-style
line into an alert dict (a thin asyncio UDP/TCP listener can wrap it for a live syslog feed). The
webhook source is already served by the API (``POST /api/ingest``).
"""

from __future__ import annotations

import datetime as _dt
import json
import re
from pathlib import Path
from typing import Any

from ..normalize import normalize_alert
from ..schema.models import Alert
from .base import BaseConnector, Capability, ConnectorError, ConnectorInfo, HealthStatus

# RFC 5424: <PRI>VERSION TIMESTAMP HOST APP PROCID MSGID MSG. The version digit is mandatory and is
# what distinguishes 5424 from 3164 (whose PRI is followed by a month name, not a digit).
_SYSLOG_5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ver>\d)\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+"
    r"(?P<procid>\S+)\s+(?P<msgid>\S+)\s+(?P<msg>.*)$"
)
# RFC 3164-ish: <PRI>MMM dd HH:MM:SS HOST TAG: MSG
_SYSLOG_3164 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ts>\w{3}\s+\d+\s[\d:]+)\s+(?P<host>\S+)\s+(?P<tag>[^:]+):\s*(?P<msg>.*)$"
)
_KV = re.compile(r"(\w+)=([^\s]+)")

_SEVERITY_BY_PRI = {
    0: "fatal",
    1: "critical",
    2: "critical",
    3: "high",
    4: "medium",
    5: "low",
    6: "informational",
    7: "informational",
}


def parse_syslog_line(line: str) -> dict[str, Any]:
    """Parse a syslog line into an alert dict suitable for ``normalize_alert``. Lossless-ish."""
    line = line.strip()
    m = _SYSLOG_5424.match(line) or _SYSLOG_3164.match(line)
    if not m:
        return {"title": "syslog message", "message": line, "severity": "medium"}
    gd = m.groupdict()
    pri = int(gd.get("pri", "13"))
    severity = _SEVERITY_BY_PRI.get(pri & 0x7, "medium")
    msg = gd.get("msg", "")
    out: dict[str, Any] = {
        "title": (gd.get("app") or gd.get("tag") or "syslog").strip(),
        "message": msg,
        "severity": severity,
        "host": gd.get("host"),
        "source_timestamp": gd.get("ts"),
    }
    out.update({k: v for k, v in _KV.findall(msg)})  # pull key=value pairs from the message
    return out


class FileIngestConnector(BaseConnector):
    kind = "file-ingest"

    def __init__(self, path: str | Path, name: str = "file-ingest") -> None:
        super().__init__(name)
        self.path = Path(path)

    def info(self) -> ConnectorInfo:
        return ConnectorInfo(name=self.name, kind=self.kind, capabilities=[Capability.READ_ALERTS])

    def _files(self) -> list[Path]:
        if self.path.is_dir():
            return sorted(p for p in self.path.iterdir() if p.suffix in (".json", ".jsonl"))
        return [self.path] if self.path.exists() else []

    @staticmethod
    def _load(p: Path) -> list[dict[str, Any]]:
        text = p.read_text(encoding="utf-8")
        if p.suffix == ".jsonl":
            return [json.loads(line) for line in text.splitlines() if line.strip()]
        data = json.loads(text)
        return data if isinstance(data, list) else [data]

    async def read_alerts(
        self, *, tenant_id: str, since: _dt.datetime | None = None, limit: int = 100
    ) -> list[Alert]:
        files = self._files()
        if not files:
            raise ConnectorError(f"{self.name}: no .json/.jsonl files at {self.path}")
        alerts: list[Alert] = []
        for p in files:
            for raw in self._load(p):
                alerts.append(normalize_alert(raw, tenant_id=tenant_id, source=self.name))
                if len(alerts) >= limit:
                    return alerts
        return alerts

    async def health(self) -> HealthStatus:
        n = len(self._files())
        return HealthStatus(healthy=n > 0, detail=f"{n} ingest file(s) at {self.path}")
