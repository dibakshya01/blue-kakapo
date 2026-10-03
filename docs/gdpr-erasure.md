# GDPR & erasure (crypto-shredding)

An append-only, hash-chained ledger and a right-to-erasure look contradictory. blue-kakapo reconciles
them with **crypto-shredding**.

## How it works
- PII (raw alert payloads, tool results) is encrypted with a **per-record AES-256-GCM key** and
  referenced by an opaque token. The ledger and cases store only **tokens/ciphertext** — never raw PII.
- All retained hashes/digests are computed over **ciphertext or tokenized refs**, never plaintext, so
  surviving hashes aren't brute-forceable after an erasure.
- An **erasure request destroys the key**. The ciphertext becomes unrecoverable (crypto-shred), while
  the hash chain still verifies.

## Operator responsibilities (honest limits)
- In production, keys belong in **OpenBao/Vault**, not the DB.
- **Key destruction must be irreversible — including backups.** A key-DB backup silently undoes an
  erasure. Set retention/rotation so destroyed keys don't resurrect.
- This module provides the mechanism; **you own the key lifecycle** and your DPA obligations.

Regulatory-clock tracking (DORA/NIS2/GDPR/SEC) is handled by the MGR agent and is an **aid, not legal
advice**.
