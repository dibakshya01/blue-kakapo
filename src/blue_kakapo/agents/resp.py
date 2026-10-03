"""RESP — Containment. Proposes response actions and runs them through the Guardian (approval-gated).

RESP is the only agent that can change external state, and it does so **only** via the GuardedExecutor
— so every action is dispositioned, blast-radius-limited, reversible-where-possible, and recorded. It
acts on the structured, already-triaged case + human approval, not on raw alert text (Rule of Two:
breaks the untrusted-input leg). Default is dry-run; real execution needs explicit opt-in and passes
through maker-checker for high-impact actions.
"""

from __future__ import annotations

from ..schema.actions import Action
from ..schema.common import AutonomyLevel, VerdictClass
from ..schema.models import AgBOM, Case, Evidence
from ..schema.ocsf import ObservableType
from .l2 import _observables
from .sdk import Agent, AgentOutput, AgentServices

_ACTIONABLE_VERDICTS = {VerdictClass.MALICIOUS, VerdictClass.SUSPICIOUS}


class RespAgent(Agent):
    name = "RESP"
    autonomy_level = AutonomyLevel.ACT_ON_APPROVAL
    handles_untrusted_input = False  # acts on structured case + approval, not raw alert text
    holds_sensitive_access = True
    changes_external_state = True

    def agbom(self) -> AgBOM:
        return AgBOM(
            agent=self.name,
            autonomy_level=self.autonomy_level,
            tools=["connector.act (via Guardian)"],
            data_scopes=["case:read"],
            permissions=["containment:propose"],
        )

    def propose_actions(self, case: Case) -> list[Action]:
        """Deterministically derive candidate containment actions from the verdict + entities."""
        if not case.verdict or case.verdict.verdict_class not in _ACTIONABLE_VERDICTS:
            return []
        registry = None  # filled in run(); here we build candidates regardless of connector support
        actions: list[Action] = []
        hosts = {
            o.value
            for o in _observables(case)
            if o.type in (ObservableType.HOSTNAME, ObservableType.FQDN)
        }
        ips = {o.value for o in _observables(case) if o.type == ObservableType.IP}
        users = {o.value for o in _observables(case) if o.type == ObservableType.USER}
        for h in sorted(hosts):
            actions.append(
                Action(
                    tenant_id=case.tenant_id,
                    verb="isolate_host",
                    target=h,
                    proposed_by="RESP",
                    case_id=case.id,
                )
            )
        for ip in sorted(ips):
            actions.append(
                Action(
                    tenant_id=case.tenant_id,
                    verb="block_ioc",
                    target=ip,
                    proposed_by="RESP",
                    case_id=case.id,
                    reversible=True,
                )
            )
        for u in sorted(users):
            actions.append(
                Action(
                    tenant_id=case.tenant_id,
                    verb="disable_user",
                    target=u,
                    proposed_by="RESP",
                    case_id=case.id,
                )
            )
        _ = registry
        return actions

    async def run(self, case: Case, svc: AgentServices) -> AgentOutput:
        candidates = self.propose_actions(case)
        if not candidates:
            return AgentOutput(notes="no actionable verdict; RESP proposes nothing")

        # Only keep actions some connector can actually perform.
        registry = svc.registry
        actions = [
            a for a in candidates if registry is None or registry.find_action(a.verb) is not None
        ]

        evidence: list[Evidence] = []
        results: list[dict[str, object]] = []
        guardian = svc.guardian
        dry_run = bool(svc.options.get("dry_run", True))
        actor_roles = list(svc.options.get("actor_roles", []))  # type: ignore[arg-type]

        if guardian is None:
            # No executor wired: propose only.
            for a in actions:
                evidence.append(
                    Evidence(
                        tenant_id=case.tenant_id,
                        source="RESP",
                        summary=f"Proposed {a.verb} on {a.target} (no executor wired).",
                        supports="response",
                    )
                )
            return AgentOutput(
                proposed_actions=actions, evidence=evidence, notes="proposed (not executed)"
            )

        for a in actions:
            res = await guardian.execute(  # type: ignore[attr-defined]
                a,
                actor_roles=actor_roles,
                case_id=case.id,
                confidence=(case.verdict.confidence if case.verdict else None),
                dry_run=dry_run,
            )
            results.append(
                {
                    "verb": a.verb,
                    "target": a.target,
                    "status": res.status,
                    "disposition": res.disposition.decision,
                }
            )
            evidence.append(
                Evidence(
                    tenant_id=case.tenant_id,
                    source="RESP",
                    summary=f"{a.verb} on {a.target}: {res.status} (guardian: {res.disposition.decision}).",
                    supports="response",
                )
            )

        return AgentOutput(
            proposed_actions=actions,
            evidence=evidence,
            metadata={"results": results},
            notes=f"RESP processed {len(actions)} action(s) through the Guardian.",
        )
