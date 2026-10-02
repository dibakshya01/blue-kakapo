"""S1: the hash-chained ledger + crypto-shred erasure."""

from __future__ import annotations

from sqlalchemy import update

from blue_kakapo.core import CryptoShredder, Ledger, Store
from blue_kakapo.core.store import ledger as ledger_table


def _store() -> Store:
    return Store.in_memory()


def test_ledger_appends_and_chains() -> None:
    store = _store()
    led = Ledger(store)
    e0 = led.append(tenant_id="t1", action="node.enter:L1", case_id="c1")
    e1 = led.append(tenant_id="t1", action="node.done:L1", case_id="c1")
    assert e0.seq == 0 and e1.seq == 1
    assert e0.prev_hash == "0" * 64
    assert e1.prev_hash == e0.hash
    assert led.verify("t1") is True


def test_ledger_replay_returns_case_entries_in_order() -> None:
    store = _store()
    led = Ledger(store)
    led.append(tenant_id="t1", action="a", case_id="c1")
    led.append(tenant_id="t1", action="b", case_id="c2")
    led.append(tenant_id="t1", action="c", case_id="c1")
    entries = led.replay("t1", case_id="c1")
    assert [e.action for e in entries] == ["a", "c"]


def test_ledger_detects_tampering() -> None:
    store = _store()
    led = Ledger(store)
    e0 = led.append(tenant_id="t1", action="legit", case_id="c1")
    led.append(tenant_id="t1", action="next", case_id="c1")
    # Tamper: rewrite the stored content of entry 0 without recomputing its hash.
    tampered = e0.model_dump(mode="json")
    tampered["action"] = "malicious"
    with store.engine.begin() as conn:
        conn.execute(update(ledger_table).where(ledger_table.c.seq == 0).values(data=tampered))
    assert led.verify("t1") is False


def test_tenants_have_independent_chains() -> None:
    store = _store()
    led = Ledger(store)
    led.append(tenant_id="t1", action="x")
    led.append(tenant_id="t2", action="y")
    assert led.verify("t1") is True and led.verify("t2") is True
    # Each tenant's sequence starts at 0.
    assert led.replay("t1")[0].seq == 0 and led.replay("t2")[0].seq == 0


def test_crypto_shred_roundtrip_and_erasure() -> None:
    store = _store()
    shredder = CryptoShredder(store)
    token = shredder.protect("t1", "jdoe@example.com logged in from 10.0.0.5")
    assert token.startswith("pii_")
    assert shredder.reveal_text(token) == "jdoe@example.com logged in from 10.0.0.5"
    assert shredder.erase(token) is True
    assert shredder.reveal(token) is None  # crypto-shredded: key destroyed
    assert shredder.erase(token) is True  # idempotent (blob still present, key already gone)


def test_erasure_does_not_break_the_ledger_chain() -> None:
    store = _store()
    led = Ledger(store)
    shredder = CryptoShredder(store)
    token = shredder.protect("t1", "sensitive raw alert payload with PII")
    led.append(tenant_id="t1", action="alert.ingest", case_id="c1", inputs_ref=token)
    led.append(tenant_id="t1", action="node.enter:L1", case_id="c1")
    assert led.verify("t1") is True
    # GDPR erasure: destroy the PII key. The chain hashes over the *token ref*, not the PII.
    shredder.erase(token)
    assert shredder.reveal(token) is None
    assert led.verify("t1") is True  # chain still intact
