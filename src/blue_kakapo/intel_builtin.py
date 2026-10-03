"""A tiny, built-in indicator set for offline/demo enrichment — NOT a threat-intel feed.

Real intelligence comes from the INTEL agent + MISP/OpenCTI connectors (later stages). This module
exists only so offline mode produces *something* deterministic and honest to reason over. The
"malicious" examples use reserved documentation ranges (RFC 5737 TEST-NET, RFC 2606 .example) so no
real host, domain, or file is ever implicated.
"""

from __future__ import annotations

import ipaddress

from .schema.ocsf import Observable, ObservableType

# Obviously-synthetic "known bad" examples (documentation/reserved values only).
KNOWN_BAD_IPS: frozenset[str] = frozenset(
    {"198.51.100.23", "203.0.113.66"}
)  # RFC 5737 TEST-NET-2/3
KNOWN_BAD_DOMAINS: frozenset[str] = frozenset({"malware.example", "c2.example", "evil.test"})
KNOWN_BAD_HASHES: frozenset[str] = frozenset({"a" * 64, "d41d8cd98f00b204e9800998ecf8427e"})

# Benign hostnames/domains for the demo allowlist.
BENIGN_DOMAINS: frozenset[str] = frozenset({"internal.example", "updates.example"})

_BENIGN_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _BENIGN_NETS)


def check_indicator(obs: Observable) -> str | None:
    """Return 'malicious', 'benign', or None for a single observable (deterministic)."""
    val = obs.value.strip().lower()
    if obs.type == ObservableType.IP:
        if obs.value in KNOWN_BAD_IPS:
            return "malicious"
        if _is_private(obs.value):
            return "benign"
    elif obs.type in (ObservableType.DOMAIN, ObservableType.FQDN):
        if val in KNOWN_BAD_DOMAINS:
            return "malicious"
        if val in BENIGN_DOMAINS:
            return "benign"
    elif obs.type == ObservableType.FILE_HASH:
        if val in KNOWN_BAD_HASHES:
            return "malicious"
    return None
