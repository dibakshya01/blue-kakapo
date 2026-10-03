# GDPR & erasure (crypto-shredding)

An append-only, hash-chained ledger and a right-to-erasure look contradictory. blue-kakapo reconciles
them with **crypto-shredding**.

## How it works

Personal data in a case lives on two surfaces, and we handle each honestly:

- **Raw payloads — tokenized at ingest.** Before a case is ever persisted, each raw alert/event
  payload (the free-text bucket where arbitrary PII — SSNs, notes, emails with no normalized home —
  lands) is encrypted with a **per-record AES-256-GCM key** and replaced in the stored case by an
  opaque `{_pii_ref: <token>}` reference. The raw payload is **never persisted in the clear**.
- **Normalized free-text + observables — readable while live, scrubbed on erasure.** The fields triage
  and the UI need (`title`, `message`, `rule_name`, evidence summaries, verdict rationale) and the
  extracted USER/EMAIL observables are kept in the clear *while a case is live* — triage and
  correlation can't reason over ciphertext. We do **not** claim these are PII-free at rest.
- **The ledger carries no PII** — only action strings, dispositions, and tokenized refs — so it keeps
  verifying across an erasure.

**A subject-erasure** (`POST /api/cases/{id}/erase?confirm=true`, admin-gated) walks **every PII-bearing
surface of the stored case**: it crypto-shreds the raw blobs' keys (unrecoverable), redacts the flagged
observables + resolved PII entities, scrubs **known-pattern PII (emails, SSNs, phone numbers) and the
case's own identified PII values** out of all free-text fields (title/message/rule_name/evidence
summaries + queries/verdict rationale/assignee), redacts the case's **approval rows**, **deletes the
kernel checkpoints** (each holds a full case snapshot), and **deletes any memory records derived from
the case**. The hash chain still verifies, and the erasure is recorded once as a `case.erased` ledger
entry (idempotent). *(Verified by `tests/test_attack_suite.py::test_pii_tokenized_at_ingest_and_fully_scrubbed_on_erase`,
`::test_erasure_scrubs_evidence_query_and_approvals`, and `::test_erasure_purges_derived_memory`.)*

**Honest scope of the scrub.** Redaction is pattern- and value-based, not NER: it removes the PII
patterns above and the values the case itself identified as PII (extracted usernames/emails and
resolved entities). Free-text PII that is **neither a recognized pattern nor one of those values** —
e.g. a plain display name like "Jane Roberts" typed into an alert title — is **not** detected. For a
subject whose personal data includes such free text, use the stronger guarantee below.

For that stronger guarantee (remove the record entirely), hard-delete the case document — the PII-free
ledger survives and still verifies on its own.

## Operator responsibilities (honest limits)
- In production, keys belong in **OpenBao/Vault**, not the DB.
- **Key destruction must be irreversible — including backups.** A key-DB backup silently undoes an
  erasure. Set retention/rotation so destroyed keys don't resurrect.
- This module provides the mechanism; **you own the key lifecycle** and your DPA obligations.

Regulatory-clock tracking (DORA/NIS2/GDPR/SEC) is handled by the MGR agent and is an **aid, not legal
advice**.
