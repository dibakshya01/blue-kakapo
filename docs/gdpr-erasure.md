# GDPR & erasure (crypto-shredding)

An append-only, hash-chained ledger and a right-to-erasure look contradictory. blue-kakapo reconciles
them with **crypto-shredding**.

## How it works
- **Raw payloads are tokenized at ingest.** Before a case is ever persisted, each raw alert/event
  payload — the free-text bucket where arbitrary PII (SSNs, notes, emails with no normalized home)
  lands — is encrypted with a **per-record AES-256-GCM key** and replaced in the stored case by an
  opaque `{_pii_ref: <token>}` reference. The case at rest holds a token, not the raw PII. *(Verified
  by `tests/test_attack_suite.py::test_raw_pii_is_tokenized_at_rest_and_erasable`.)*
- **Normalized observables are flagged, then redacted on erasure.** Values we deliberately extract for
  triage, correlation, and entity resolution (usernames, emails) are kept in the clear *while a case
  is live* — triage can't reason over ciphertext — but are flagged `contains_pii`. A subject-erasure
  redacts them (and resolved PII entities) in place.
- **The ledger carries no PII** — only action strings, dispositions, and tokenized refs — so it keeps
  verifying across an erasure.
- **An erasure request** (`POST /api/cases/{id}/erase`, admin-gated) **destroys the raw blobs' keys**
  (crypto-shred, unrecoverable) **and redacts the flagged observables/entities**, while the hash
  chain still verifies. The erasure itself is recorded as a `case.erased` ledger entry.

For a stronger guarantee (remove the case entirely), hard-delete the case document — the PII-free
ledger survives and still verifies on its own.

## Operator responsibilities (honest limits)
- In production, keys belong in **OpenBao/Vault**, not the DB.
- **Key destruction must be irreversible — including backups.** A key-DB backup silently undoes an
  erasure. Set retention/rotation so destroyed keys don't resurrect.
- This module provides the mechanism; **you own the key lifecycle** and your DPA obligations.

Regulatory-clock tracking (DORA/NIS2/GDPR/SEC) is handled by the MGR agent and is an **aid, not legal
advice**.
