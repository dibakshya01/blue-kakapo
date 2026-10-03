"""A small MITRE ATT&CK technique → tactic map for triage prioritization.

Not exhaustive — a pragmatic subset used to tag cases with kill-chain position. The authoritative
STIX data (ATT&CK v19.x) is a drop-in replacement via the DET/INTEL agents later. Note v19 split
Defense Evasion into "Stealth" and "Defense Impairment"; both labels are accepted here.
"""

from __future__ import annotations

# technique id (major, sub-technique trimmed to major) -> tactic label
_TECHNIQUE_TACTIC: dict[str, str] = {
    "T1078": "initial-access",
    "T1566": "initial-access",
    "T1190": "initial-access",
    "T1059": "execution",
    "T1203": "execution",
    "T1053": "execution",
    "T1547": "persistence",
    "T1136": "persistence",
    "T1548": "privilege-escalation",
    "T1068": "privilege-escalation",
    "T1110": "credential-access",
    "T1003": "credential-access",
    "T1055": "defense-evasion",  # a.k.a. Stealth / Defense Impairment (ATT&CK v19)
    "T1562": "defense-impairment",
    "T1021": "lateral-movement",
    "T1071": "command-and-control",
    "T1105": "command-and-control",
    "T1041": "exfiltration",
    "T1486": "impact",
    "T1490": "impact",
}

# Rough kill-chain ordering for severity weighting (later = closer to impact).
_TACTIC_WEIGHT: dict[str, int] = {
    "initial-access": 2,
    "execution": 3,
    "persistence": 4,
    "privilege-escalation": 5,
    "credential-access": 5,
    "defense-evasion": 4,
    "defense-impairment": 4,
    "lateral-movement": 6,
    "command-and-control": 7,
    "exfiltration": 8,
    "impact": 9,
}


def _major(technique: str) -> str:
    return technique.split(".", 1)[0].upper()


def tactic_for(technique: str) -> str | None:
    return _TECHNIQUE_TACTIC.get(_major(technique))


def tactics_for(techniques: list[str]) -> list[str]:
    out: list[str] = []
    for t in techniques:
        tac = tactic_for(t)
        if tac and tac not in out:
            out.append(tac)
    return out


def kill_chain_weight(techniques: list[str]) -> int:
    """The highest kill-chain weight among the techniques (0 if none mapped)."""
    return max((_TACTIC_WEIGHT.get(t, 0) for t in tactics_for(techniques)), default=0)
