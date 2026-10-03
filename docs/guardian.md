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
