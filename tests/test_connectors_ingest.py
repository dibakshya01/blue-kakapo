"""S3: file + syslog ingestion."""

from __future__ import annotations

import json
from pathlib import Path

from blue_kakapo.connectors import FileIngestConnector, parse_syslog_line


async def test_file_ingest_json_array(tmp_path: Path) -> None:
    p = tmp_path / "alerts.json"
    p.write_text(
        json.dumps([{"title": "a", "severity": "high"}, {"title": "b", "severity": "low"}])
    )
    alerts = await FileIngestConnector(p).read_alerts(tenant_id="t1")
    assert [a.title for a in alerts] == ["a", "b"]
    assert all(a.source == "file-ingest" for a in alerts)


async def test_file_ingest_jsonl_and_directory(tmp_path: Path) -> None:
    (tmp_path / "a.jsonl").write_text(
        '{"title":"x","severity":"medium"}\n{"title":"y","severity":"low"}\n'
    )
    alerts = await FileIngestConnector(tmp_path).read_alerts(tenant_id="t1")
    assert {a.title for a in alerts} == {"x", "y"}


def test_parse_syslog_5424_pulls_kv() -> None:
    line = "<34>1 2026-10-03T10:00:00Z host42 sshd 1234 ID47 Failed login srcip=198.51.100.23 user=root"
    out = parse_syslog_line(line)
    assert out["host"] == "host42"
    assert out["title"] == "sshd"
    assert out["srcip"] == "198.51.100.23"
    assert out["user"] == "root"


def test_parse_syslog_3164_and_freeform() -> None:
    out = parse_syslog_line("<13>Oct  3 10:00:00 web01 nginx: 404 for /x")
    assert out["host"] == "web01" and out["title"] == "nginx"
    free = parse_syslog_line("not a syslog line at all")
    assert free["message"] == "not a syslog line at all"
