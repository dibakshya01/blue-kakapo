"""A small built-in vulnerability/KEV feed for the VULN agent (offline/demo).

Real deployments plug in a live feed (NVD, vendor, CISA KEV) via a connector; this bundled sample lets
VULN demonstrate exposure prioritization offline. Not a real feed.
"""

from __future__ import annotations

from .schema.common import BKModel


class Vulnerability(BKModel):
    cve: str
    cvss: float
    kev: bool = False  # on CISA's Known Exploited Vulnerabilities list
    affected_identifiers: list[str] = []  # host/asset identifiers
    technique: str | None = None  # associated ATT&CK technique, if known
    description: str = ""


_SAMPLE: list[Vulnerability] = [
    Vulnerability(
        cve="CVE-2026-1001",
        cvss=9.8,
        kev=True,
        affected_identifiers=["WS-14", "10.0.0.14"],
        technique="T1190",
        description="RCE in edge appliance (exploited in the wild).",
    ),
    Vulnerability(
        cve="CVE-2026-1002",
        cvss=7.5,
        kev=False,
        affected_identifiers=["WS-204"],
        technique="T1059",
        description="Privilege escalation via scripting host.",
    ),
    Vulnerability(
        cve="CVE-2026-1003",
        cvss=5.3,
        kev=False,
        affected_identifiers=["printer-lobby"],
        description="Info disclosure on a printer.",
    ),
]


def sample_vulnerabilities() -> list[Vulnerability]:
    return list(_SAMPLE)
