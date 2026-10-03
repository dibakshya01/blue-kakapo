"""The Agent SDK — the frozen contract every blue-kakapo agent implements.

An agent is a scoped, auditable unit: it declares an **AgBOM** (tools/models/connectors/scopes), an
**autonomy level**, and its Rule-of-Two legs (untrusted input / sensitive access / external state
change) — and construction **fails** if all three legs are present. It runs over a `Case` with shared
`AgentServices` and returns a typed `AgentOutput`; the orchestrator wraps each agent as a kernel node,
merges its output into the case, and records it in the ledger. The core-5 build against this; the
remaining agents (S9) build against the same surface.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ..guardian.injection import rule_of_two_ok
from ..providers import ProviderGateway
from ..schema.actions import Action
from ..schema.ledger import ModelRef
from ..schema.models import AgBOM, Case, Entity, Evidence, Verdict

if TYPE_CHECKING:  # avoid runtime import weight / cycles; annotations are strings (PEP 563)
    from ..assets import AssetInventory
    from ..connectors import ConnectorRegistry
    from ..core import CaseRepo
    from ..guardian import GuardedExecutor
    from ..memory import MemoryService


@dataclass
class AgentServices:
    """Everything an agent may use. Optional services are None when not wired."""

    tenant_id: str
    gateway: ProviderGateway
    emit: Callable[..., Awaitable[None]]
    registry: ConnectorRegistry | None = None
    inventory: AssetInventory | None = None
    guardian: GuardedExecutor | None = None
    memory: MemoryService | None = None
    repo: CaseRepo | None = None
    options: dict[str, Any] = field(default_factory=dict)  # per-run flags (e.g. dry_run)


@dataclass
class AgentOutput:
    evidence: list[Evidence] = field(default_factory=list)
    entities: list[Entity] = field(default_factory=list)
    verdict: Verdict | None = None
    techniques: list[str] = field(default_factory=list)
    proposed_actions: list[Action] = field(default_factory=list)
    notes: str = ""
    cost: ModelRef | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class AgentConfigError(ValueError):
    """Raised when an agent's declared capabilities violate a safety invariant (e.g. Rule of Two)."""


class Agent(ABC):
    """Base class. Subclasses set class attrs and implement ``run``."""

    name: str = "agent"
    autonomy_level: str = "propose"
    # Rule-of-Two legs — an agent must break at least one.
    handles_untrusted_input: bool = True
    holds_sensitive_access: bool = False
    changes_external_state: bool = False

    def __init__(self) -> None:
        if not rule_of_two_ok(
            untrusted_input=self.handles_untrusted_input,
            sensitive_access=self.holds_sensitive_access,
            external_state_change=self.changes_external_state,
        ):
            raise AgentConfigError(
                f"agent {self.name!r} violates the Rule of Two (untrusted input + sensitive access + "
                "external state change). Break at least one leg."
            )

    @abstractmethod
    def agbom(self) -> AgBOM: ...

    @abstractmethod
    async def run(self, case: Case, svc: AgentServices) -> AgentOutput: ...
