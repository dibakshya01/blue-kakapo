# Guardian & policies

The Guardian is the single gate every state-changing action passes through. No action reaches a
connector without a recorded **disposition** and a ledger entry.

## Dispositions (ACS)
`allow / deny / modify / ask / defer` — default **ask**, never fail-open. The policy engine aggregates
built-in policies by precedence: **deny > ask > modify > allow**.

## Built-in policies
- **capability gate** — deny verbs no connector can perform.
- **crown-jewel guard** — isolate/disable on `critical`/`crown_jewel` assets → **ask** (2 approvals for
  crown jewels). Never auto-isolated.
- **blast-radius guard** — over the simultaneous-action cap → ask.
- **irreversible guard** — irreversible actions (e.g. kill-process) → ask.
- **containment TTL** — open-ended containment is **modified** to auto-expire (time-boxed, reversible).
- **low-impact allow** — reversible, non-high-impact actions on normal assets → allow.

## Maker-checker
`ask` opens an approval. High-impact needs **two distinct approvers**; a duplicate approver is
rejected; denial blocks execution. Everything is ledgered.

Write policies in the built-in typed DSL or bring **OPA/Rego**. Asset criticality comes from the
[asset inventory](architecture.md). The Guardian also enforces the **Rule of Two** and treats all
tool/alert content as data.
