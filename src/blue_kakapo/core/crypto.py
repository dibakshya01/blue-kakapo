"""Crypto-shredding: GDPR-respecting erasure against an append-only ledger.

Every piece of PII (raw alert payloads, tool results) is encrypted with a **per-record AES-256-GCM
key** and referenced by an opaque token. The ledger and cases store only tokens/ciphertext — never
raw PII — so the hash chain stays verifiable. An erasure request **destroys the key**, after which
the ciphertext is unrecoverable (crypto-shred) while the chain still verifies.

Honest limits (see build-plan §8, FR-44): in this dev keystore the key lives in the DB; in production
keys belong in OpenBao, and key destruction must be irreversible *including backups* — a key-DB
backup silently undoes an erasure. This module gives the mechanism; operators own the key lifecycle.
"""

from __future__ import annotations

import datetime as _dt
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..schema.common import new_id
from .store import Store

_KEY_BYTES = 32  # AES-256
_NONCE_BYTES = 12  # GCM standard


class CryptoShredder:
    """Encrypts PII under per-record keys and erases by destroying the key."""

    def __init__(self, store: Store) -> None:
        self.store = store

    def protect(self, tenant_id: str, plaintext: str | bytes) -> str:
        """Encrypt ``plaintext`` under a fresh key; return an opaque token to store in its place."""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        key = AESGCM.generate_key(bit_length=256)
        key_ref = new_id("key")
        token = new_id("pii")
        nonce = os.urandom(_NONCE_BYTES)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, token.encode("utf-8"))  # token as AAD
        self.store.put_key(key_ref, tenant_id, key)
        self.store.put_blob(
            {
                "token": token,
                "tenant_id": tenant_id,
                "key_ref": key_ref,
                "nonce": nonce,
                "ciphertext": ciphertext,
                "created_at": _dt.datetime.now(_dt.UTC),
            }
        )
        return token

    def reveal(self, token: str) -> bytes | None:
        """Decrypt the blob behind ``token``; returns ``None`` if the key was destroyed (erased)."""
        blob = self.store.get_blob(token)
        if blob is None:
            return None
        key = self.store.get_key(blob["key_ref"])
        if key is None:  # crypto-shredded
            return None
        return AESGCM(key).decrypt(blob["nonce"], blob["ciphertext"], token.encode("utf-8"))

    def reveal_text(self, token: str) -> str | None:
        data = self.reveal(token)
        return data.decode("utf-8") if data is not None else None

    def erase(self, token: str) -> bool:
        """Crypto-shred the blob behind ``token`` by destroying its key. Idempotent."""
        blob = self.store.get_blob(token)
        if blob is None:
            return False
        self.store.destroy_key(blob["key_ref"])
        return True
