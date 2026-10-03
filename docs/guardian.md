# Guardian & policies

The Guardian is the single gate every state-changing action passes through. No action reaches a
connector without a recorded **disposition** and a ledger entry.

## Dispositions (ACS)
`allow / deny / modify / ask / defer` — default **ask**, never fail-open. The policy engine aggregates
built-in policies by precedence: **deny > ask > modify > allow**.

## Built-in policies
- **capability gate** — deny verbs no connector can perform.
- **high-impact guard** — every high-impact verb (`isolate_host`, `disable_user`, `kill_process`,
  `quarantine_file`, `firewall_drop`) → **ask** with **two** required approvers, on *any* asset
  (including unknown assets, which default to `normal`). Nothing high-impact is ever auto-executed.
  For open-ended containment the guard attaches a **TTL** as the *effective* action the approvers run
  — so a `modify`/time-box composes with the human gate, it never replaces it.
- **blast-radius guard** — over the simultaneous-action cap (tracks in-flight actions) → ask.
- **irreversible guard** — other irreversible verbs (e.g. `delete`, `wipe`) → ask.
- **low-impact allow** — reversible, non-high-impact actions on normal assets → allow.

## Maker-checker
`ask` opens an approval, reachable end-to-end via the API (`GET /api/approvals`,
`POST /api/approvals/{id}/approve|deny`, gated by the `approve_response` permission) and the
dashboard's **Approvals** inbox. High-impact actions need **two distinct approvers**; a **proposer
may not approve its own action**; a duplicate approver is rejected; denial blocks execution.
Everything — request, each grant, the final execution — is ledgered.

Write policies in the built-in typed DSL or bring **OPA/Rego**. Asset criticality comes from the
[asset inventory](architecture.md). The Guardian also enforces the **Rule of Two** and treats all
tool/alert content as data.

## Operator notes (honest limits)
- The shipped `responder` role holds both `propose_response` and `approve_response`. Two-person
  control still holds for high-impact actions (two **distinct** principals required), but for a
  multi-analyst SOC, split proposing and approving across roles.
- Distinctness is per principal id. A **human should hold one credential**: two local static tokens
  map to two ids, so one person could satisfy both approvals. OIDC subjects are stable and don't have
  this issue — prefer OIDC for approvers, or issue one token per person.
- On approval the stored action is **re-evaluated** through the Guardian before it runs, so a policy
  change (or tampering that turns it into a denied action) blocks execution. The approvals inbox is
  gated to `approve_response`, since an action target can itself be PII.
- Approval counting is correct for the single-process deployment (status is persisted before the
  connector call; actions carry an idempotency key). A multi-replica/Postgres deployment should add
  row-level locking (`SELECT … FOR UPDATE`) before counting an approval.
