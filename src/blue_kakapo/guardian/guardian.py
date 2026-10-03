"""The Guardian — the single gate every state-changing action must pass.

``Guardian.check`` turns an action + context into an ACS ``Disposition`` via the policy engine.
``GuardedExecutor`` is the only path to a connector's ``act``: it records the disposition in the
ledger, refuses denies, opens a maker-checker **approval** for ask/defer, and executes allow/modify
(using the rewritten action for *modify*). No action reaches a connector without a disposition and a
ledger entry.
"""

from __future__ import annotations

import datetime as _dt

from ..assets.inventory import AssetInventory
from ..connectors.registry import ConnectorRegistry
from ..core.ledger import Ledger
from ..core.store import Store
from ..schema.actions import Action, Disposition
from ..schema.common import ACSDisposition, BKModel, TenantScoped, new_id, utcnow
from .policy import DecisionInput, PolicyEngine


class ApprovalRequest(TenantScoped):
    id: str
    case_id: str | None = None
    action: Action  # the EFFECTIVE action approvers authorize (e.g. a TTL-boxed containment)
    proposer: str | None = None  # the agent/actor that proposed it — may NOT approve its own action
    reason: str = ""
    required_approvals: int = 1
    approvals_received: int = 0
    approvers: list[str] = []
    status: str = "pending"  # pending | approved | denied | expired
    created_at: _dt.datetime


class ExecutionResult(BKModel):
    status: str  # ok | dry_run | denied | pending_approval | failed
    disposition: Disposition
    approval_id: str | None = None
    detail: str = ""


class Guardian:
    def __init__(
        self,
        inventory: AssetInventory,
        registry: ConnectorRegistry,
        *,
        policy_engine: PolicyEngine | None = None,
        max_concurrent_actions: int = 5,
        containment_ttl_seconds: int = 3600,
    ) -> None:
        self.inventory = inventory
        self.registry = registry
        self.engine = policy_engine or PolicyEngine()
        self.max_concurrent_actions = max_concurrent_actions
        self.containment_ttl_seconds = containment_ttl_seconds

    def check(
        self,
        action: Action,
        *,
        actor_roles: list[str] | None = None,
        confidence: float | None = None,
        case_id: str | None = None,
        in_flight: int = 0,
    ) -> Disposition:
        criticality = self.inventory.criticality_for(action.tenant_id, action.target)
        supports = self.registry.find_action(action.verb) is not None
        d = DecisionInput(
            tenant_id=action.tenant_id,
            action=action,
            actor_roles=actor_roles or [],
            asset_criticality=criticality,
            blast_radius_estimate=action.blast_radius_estimate,
            in_flight_actions=in_flight,
            max_concurrent_actions=self.max_concurrent_actions,
            confidence=confidence,
            case_id=case_id,
            connector_supports=supports,
            containment_ttl_seconds=self.containment_ttl_seconds,
        )
        return self.engine.decide(d)


class GuardedExecutor:
    """The only sanctioned path from a proposed action to a connector action."""

    def __init__(
        self, guardian: Guardian, registry: ConnectorRegistry, ledger: Ledger, store: Store
    ) -> None:
        self.guardian = guardian
        self.registry = registry
        self.ledger = ledger
        self.store = store
        self._in_flight = 0  # state-changing actions currently executing (feeds blast-radius guard)

    def _ledger(
        self, action: str, *, tenant_id: str, case_id: str | None, disposition: str | None = None
    ) -> None:
        self.ledger.append(
            tenant_id=tenant_id,
            action=action,
            actor="system",
            actor_id="guardian",
            case_id=case_id,
            disposition=disposition,
        )

    async def execute(
        self,
        action: Action,
        *,
        actor_roles: list[str] | None = None,
        case_id: str | None = None,
        confidence: float | None = None,
        dry_run: bool = False,
        in_flight: int = 0,
    ) -> ExecutionResult:
        disp = self.guardian.check(
            action,
            actor_roles=actor_roles,
            confidence=confidence,
            case_id=case_id,
            in_flight=in_flight + self._in_flight,
        )
        self._ledger(
            f"guardian.disposition:{action.verb}:{disp.decision}",
            tenant_id=action.tenant_id,
            case_id=case_id,
            disposition=disp.decision,
        )

        if disp.decision == ACSDisposition.DENY:
            return ExecutionResult(status="denied", disposition=disp, detail=disp.reason)

        if disp.decision in (ACSDisposition.ASK, ACSDisposition.DEFER):
            # The approvers authorize the EFFECTIVE action: a modify-rewrite (e.g. a TTL-boxed
            # containment) when the policy attached one, else the original. A modify can therefore
            # never bypass the human gate for a high-impact verb — it only shapes what gets run.
            effective = disp.modified_action or action
            approval = ApprovalRequest(
                tenant_id=action.tenant_id,
                id=new_id("appr"),
                case_id=case_id,
                action=effective,
                proposer=action.proposed_by,
                reason=disp.reason,
                required_approvals=disp.required_approvals or 1,
                created_at=utcnow(),
            )
            self.store.insert_approval(
                {
                    "id": approval.id,
                    "tenant_id": approval.tenant_id,
                    "case_id": case_id,
                    "status": approval.status,
                    "created_at": approval.created_at,
                    "data": approval.model_dump(mode="json"),
                }
            )
            self._ledger(
                f"approval.requested:{action.verb}", tenant_id=action.tenant_id, case_id=case_id
            )
            return ExecutionResult(
                status="pending_approval", disposition=disp, approval_id=approval.id
            )

        # allow / modify
        chosen = (
            disp.modified_action
            if disp.decision == ACSDisposition.MODIFY and disp.modified_action
            else action
        )
        return await self._run_action(chosen, disp, case_id=case_id, dry_run=dry_run)

    async def _run_action(
        self, action: Action, disp: Disposition, *, case_id: str | None, dry_run: bool
    ) -> ExecutionResult:
        found = self.registry.find_action(action.verb)
        if found is None:
            return ExecutionResult(
                status="denied", disposition=disp, detail="no connector for action"
            )
        connector, _ = found
        self._in_flight += 1
        try:
            result = await connector.act(action, dry_run=dry_run or action.dry_run)
        finally:
            self._in_flight -= 1
        self._ledger(
            f"action.executed:{action.verb}:{result.status}",
            tenant_id=action.tenant_id,
            case_id=case_id,
        )
        return ExecutionResult(status=result.status, disposition=disp, detail=result.detail)

    async def approve(
        self, approval_id: str, approver_id: str, *, dry_run: bool = False
    ) -> ExecutionResult:
        """Record a maker-checker approval; execute once enough approvals are gathered."""
        row = self.store.get_approval(approval_id)
        if row is None:
            raise ValueError(f"unknown approval {approval_id!r}")
        appr = ApprovalRequest.model_validate(row["data"])
        if appr.status != "pending":
            raise ValueError(f"approval {approval_id!r} is {appr.status}")
        if appr.proposer is not None and approver_id == appr.proposer:
            raise ValueError("maker-checker: the proposer may not approve its own action")
        if approver_id in appr.approvers:
            raise ValueError("duplicate approver (two-person rule)")
        appr.approvers.append(approver_id)
        appr.approvals_received += 1
        self._ledger(
            f"approval.granted:{appr.action.verb}", tenant_id=appr.tenant_id, case_id=appr.case_id
        )

        if appr.approvals_received < appr.required_approvals:
            self.store.update_approval(
                approval_id, {"status": "pending", "data": appr.model_dump(mode="json")}
            )
            disp = Disposition(decision=ACSDisposition.ASK, reason="awaiting more approvals")
            return ExecutionResult(
                status="pending_approval", disposition=disp, approval_id=approval_id
            )

        appr.status = "approved"
        self.store.update_approval(
            approval_id, {"status": "approved", "data": appr.model_dump(mode="json")}
        )
        allow = Disposition(decision=ACSDisposition.ALLOW, reason="approved by human(s)")
        return await self._run_action(appr.action, allow, case_id=appr.case_id, dry_run=dry_run)

    async def deny(self, approval_id: str, approver_id: str) -> ExecutionResult:
        row = self.store.get_approval(approval_id)
        if row is None:
            raise ValueError(f"unknown approval {approval_id!r}")
        appr = ApprovalRequest.model_validate(row["data"])
        appr.status = "denied"
        self.store.update_approval(
            approval_id, {"status": "denied", "data": appr.model_dump(mode="json")}
        )
        self._ledger(
            f"approval.denied:{appr.action.verb}", tenant_id=appr.tenant_id, case_id=appr.case_id
        )
        return ExecutionResult(
            status="denied",
            disposition=Disposition(decision=ACSDisposition.DENY, reason="denied by human"),
        )
