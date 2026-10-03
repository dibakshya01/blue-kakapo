"""blue-kakapo agents — the triage swarm.

Core-5 (deeply built, S6): L1, L2, INTEL, FUSION, RESP + the orchestrator. The remaining agents (WATCH,
HUNT, DET, VULN, INSIDER, COMMS, RPT, MAINT, MGR) build against the same SDK in S9.
"""

from __future__ import annotations

from .fusion import FusionAgent
from .intel import IntelAgent
from .l1 import L1Agent, deterministic_triage, triage
from .l2 import L2Agent
from .orchestrator import TriageOrchestrator, TriageState
from .proactive import DetAgent, HuntAgent, InsiderAgent, VulnAgent, WatchAgent
from .resp import RespAgent
from .sdk import Agent, AgentConfigError, AgentOutput, AgentServices
from .serviceops import CommsAgent, MaintAgent, MgrAgent, RptAgent

__all__ = [
    "TriageOrchestrator",
    "TriageState",
    "Agent",
    "AgentServices",
    "AgentOutput",
    "AgentConfigError",
    # core-5
    "L1Agent",
    "L2Agent",
    "IntelAgent",
    "FusionAgent",
    "RespAgent",
    # proactive
    "WatchAgent",
    "HuntAgent",
    "DetAgent",
    "VulnAgent",
    "InsiderAgent",
    # service ops
    "CommsAgent",
    "RptAgent",
    "MaintAgent",
    "MgrAgent",
    "triage",
    "deterministic_triage",
]
