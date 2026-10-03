"""Normalize a raw inbound alert (generic webhook/JSON) into an OCSF-aligned Alert.

This is the minimal, source-agnostic normalizer used by the webhook ingester. Vendor-specific
connectors (Wazuh, Elastic, ...) ship their own richer mappers via the Connector SDK (S3); they all
target the same OCSF `Event`/`Alert` shape so downstream agents reason source-independently.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from .schema.common import Severity, new_token
from .schema.models import Alert
from .schema.ocsf import Event, Observable, ObservableType

# Common field aliases seen across alert sources, mapped to our observable types.
_FIELD_ALIASES: dict[str, list[str]] = {
    ObservableType.IP: [
        "ip",
        "src_ip",
        "source_ip",
        "dst_ip",
        "dest_ip",
        "destination_ip",
        "client_ip",
    ],
    ObservableType.USER: ["user", "username", "user_name", "account", "src_user", "subject_user"],
    ObservableType.HOSTNAME: ["host", "hostname", "computer", "device", "src_host", "endpoint"],
    ObservableType.FQDN: ["fqdn"],
    ObservableType.DOMAIN: ["domain", "dns", "query"],
    ObservableType.URL: ["url", "uri", "request_url"],
    ObservableType.FILE_HASH: ["hash", "sha256", "sha1", "md5", "file_hash"],
    ObservableType.FILE_PATH: ["file", "file_path", "path", "image"],
    ObservableType.PROCESS: ["process", "process_name", "proc"],
}

_SEVERITY_ALIASES: dict[str, str] = {
    "0": Severity.INFORMATIONAL,
    "info": Severity.INFORMATIONAL,
    "informational": Severity.INFORMATIONAL,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "severe": Severity.CRITICAL,
    "fatal": Severity.FATAL,
}

_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
_PII_TYPES = {ObservableType.USER, ObservableType.EMAIL}


def _coerce_severity(value: Any) -> str:
    if value is None:
        return Severity.MEDIUM
    key = str(value).strip().lower()
    if key in _SEVERITY_ALIASES:
        return _SEVERITY_ALIASES[key]
    # numeric OCSF-style severity_id 0..6
    if key.isdigit():
        idx = int(key)
        order = [
            Severity.UNKNOWN,
            Severity.INFORMATIONAL,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
            Severity.FATAL,
        ]
        if 0 <= idx < len(order):
            return order[idx]
    return Severity.MEDIUM


def _classify_ip(value: str) -> str:
    try:
        ipaddress.ip_address(value)
        return ObservableType.IP
    except ValueError:
        return ObservableType.HOSTNAME


def extract_observables(raw: dict[str, Any]) -> list[Observable]:
    """Pull observables from known field aliases + a light hash scan. Deterministic and lossless-ish."""
    seen: set[tuple[str, str]] = set()
    out: list[Observable] = []

    def add(otype: str, value: Any) -> None:
        if value is None:
            return
        sval = str(value).strip()
        if not sval:
            return
        # Refine ip-vs-hostname when the alias was generic.
        if otype in (ObservableType.IP, ObservableType.HOSTNAME):
            otype = _classify_ip(sval)
        key = (otype, sval.lower())
        if key in seen:
            return
        seen.add(key)
        out.append(Observable(type=otype, value=sval, contains_pii=otype in _PII_TYPES))

    for otype, aliases in _FIELD_ALIASES.items():
        for alias in aliases:
            if alias in raw:
                add(otype, raw[alias])

    # Light scan of string values for file hashes not caught by aliases.
    for value in raw.values():
        if isinstance(value, str):
            for m in _HASH_RE.findall(value):
                add(ObservableType.FILE_HASH, m)

    return out


def normalize_alert(raw: dict[str, Any], *, tenant_id: str, source: str = "webhook") -> Alert:
    """Map a generic alert dict to an OCSF-aligned Alert (one Event). Raw payload is retained."""
    title = str(
        raw.get("title")
        or raw.get("name")
        or raw.get("rule_name")
        or raw.get("message")
        or "Untitled alert"
    )
    severity = _coerce_severity(raw.get("severity") or raw.get("priority"))
    observables = extract_observables(raw)
    techniques = raw.get("attack_techniques") or raw.get("techniques") or []
    if isinstance(techniques, str):
        techniques = [techniques]

    event = Event(
        tenant_id=tenant_id,
        source=source,
        product=str(raw["product"]) if raw.get("product") else None,
        severity=severity,
        message=str(raw.get("message") or title),
        observables=observables,
        raw=raw,
        metadata={"ingest_id": new_token(8)},
    )
    return Alert(
        tenant_id=tenant_id,
        title=title[:300],
        source=source,
        severity=severity,
        rule_id=str(raw["rule_id"]) if raw.get("rule_id") else None,
        rule_name=str(raw["rule_name"]) if raw.get("rule_name") else None,
        attack_techniques=[str(t) for t in techniques],
        dedup_key=str(raw["dedup_key"]) if raw.get("dedup_key") else None,
        events=[event],
        raw=raw,
    )
