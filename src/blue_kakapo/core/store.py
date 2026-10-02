"""Persistence layer — one SQLAlchemy Core schema for SQLite (dev) and Postgres (prod).

Document-style tables (indexed columns + a JSON ``data`` blob) keep velocity high while giving us a
tenant boundary, the ledger's monotonic sequence, resumable checkpoints, and the crypto-shred
keystore. The richer relational modeling can come later without changing callers.

Note: the engine is synchronous. On SQLite/localhost this is fine; hot paths that touch the DB from
async code should be wrapped in ``asyncio.to_thread`` by the caller. A fully async store is a later
performance item.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Table,
    UniqueConstraint,
    create_engine,
    delete,
    insert,
    select,
    update,
)
from sqlalchemy.engine import Engine

from ..config import Settings, get_settings

metadata = MetaData()

cases = Table(
    "cases",
    metadata,
    Column("id", String, primary_key=True),
    Column("tenant_id", String, nullable=False, index=True),
    Column("state", String, nullable=False, index=True),
    Column("severity", String, nullable=False),
    Column("title", String, nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    Column("data", JSON, nullable=False),
)

ledger = Table(
    "ledger",
    metadata,
    Column("id", String, primary_key=True),
    Column("tenant_id", String, nullable=False, index=True),
    Column("seq", Integer, nullable=False),
    Column("prev_hash", String, nullable=False),
    Column("hash", String, nullable=False),
    Column("case_id", String, nullable=True, index=True),
    Column("run_id", String, nullable=True, index=True),
    Column("action", String, nullable=False),
    Column("ts", DateTime(timezone=True), nullable=False),
    Column("data", JSON, nullable=False),
    UniqueConstraint("tenant_id", "seq", name="uq_ledger_tenant_seq"),
)

checkpoints = Table(
    "checkpoints",
    metadata,
    Column("run_id", String, primary_key=True),
    Column("tenant_id", String, nullable=False, index=True),
    Column("graph", String, nullable=False),
    Column("node_id", String, nullable=False),
    Column("seq", Integer, nullable=False),
    Column("status", String, nullable=False),
    Column("resume_token", String, nullable=True),
    Column("case_id", String, nullable=True, index=True),
    Column("state_json", JSON, nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)

crypto_keys = Table(
    "crypto_keys",
    metadata,
    Column("key_ref", String, primary_key=True),
    Column("tenant_id", String, nullable=False, index=True),
    Column("key_material", LargeBinary, nullable=True),  # NULL once destroyed (crypto-shred)
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("erased", Boolean, nullable=False, default=False),
)

crypto_blobs = Table(
    "crypto_blobs",
    metadata,
    Column("token", String, primary_key=True),
    Column("tenant_id", String, nullable=False, index=True),
    Column("key_ref", String, nullable=False),
    Column("nonce", LargeBinary, nullable=False),
    Column("ciphertext", LargeBinary, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)


def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.UTC)


class Store:
    """Thin synchronous facade over the SQLAlchemy engine + schema."""

    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    @classmethod
    def from_settings(cls, settings: Settings | None = None) -> Store:
        settings = settings or get_settings()
        url = settings.resolved_database_url()
        connect_args: dict[str, Any] = (
            {"check_same_thread": False, "timeout": 30.0} if url.startswith("sqlite") else {}
        )
        engine = create_engine(url, future=True, connect_args=connect_args)
        store = cls(engine)
        store.create_all()
        return store

    @classmethod
    def in_memory(cls) -> Store:
        """An ephemeral SQLite store for tests.

        Uses a ``StaticPool`` so the single in-memory database is shared across threads — the kernel
        writes the ledger from a worker thread (``asyncio.to_thread``), and without this each thread
        would otherwise get its own empty ``sqlite://`` database.
        """
        from sqlalchemy.pool import StaticPool

        engine = create_engine(
            "sqlite://",
            future=True,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        store = cls(engine)
        store.create_all()
        return store

    def create_all(self) -> None:
        metadata.create_all(self.engine)

    # --- generic row helpers ---

    def insert_row(self, table: Table, values: dict[str, Any]) -> None:
        with self.engine.begin() as conn:
            conn.execute(insert(table).values(**values))

    def upsert_checkpoint(self, values: dict[str, Any]) -> None:
        with self.engine.begin() as conn:
            exists = conn.execute(
                select(checkpoints.c.run_id).where(checkpoints.c.run_id == values["run_id"])
            ).first()
            if exists:
                conn.execute(
                    update(checkpoints)
                    .where(checkpoints.c.run_id == values["run_id"])
                    .values(**values)
                )
            else:
                conn.execute(insert(checkpoints).values(**values))

    def get_checkpoint(self, run_id: str) -> dict[str, Any] | None:
        with self.engine.begin() as conn:
            row = (
                conn.execute(select(checkpoints).where(checkpoints.c.run_id == run_id))
                .mappings()
                .first()
            )
            return dict(row) if row else None

    def upsert_case(self, values: dict[str, Any]) -> None:
        with self.engine.begin() as conn:
            exists = conn.execute(select(cases.c.id).where(cases.c.id == values["id"])).first()
            if exists:
                conn.execute(update(cases).where(cases.c.id == values["id"]).values(**values))
            else:
                conn.execute(insert(cases).values(**values))

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        with self.engine.begin() as conn:
            row = conn.execute(select(cases).where(cases.c.id == case_id)).mappings().first()
            return dict(row) if row else None

    def list_cases(self, tenant_id: str, limit: int = 100) -> list[dict[str, Any]]:
        with self.engine.begin() as conn:
            rows = (
                conn.execute(
                    select(cases)
                    .where(cases.c.tenant_id == tenant_id)
                    .order_by(cases.c.updated_at.desc())
                    .limit(limit)
                )
                .mappings()
                .all()
            )
            return [dict(r) for r in rows]

    # --- ledger-specific ---

    def next_seq(self, tenant_id: str) -> int:
        from sqlalchemy import func

        with self.engine.begin() as conn:
            current = conn.execute(
                select(func.max(ledger.c.seq)).where(ledger.c.tenant_id == tenant_id)
            ).scalar()
            return 0 if current is None else int(current) + 1

    def last_hash(self, tenant_id: str) -> str:
        with self.engine.begin() as conn:
            row = conn.execute(
                select(ledger.c.hash)
                .where(ledger.c.tenant_id == tenant_id)
                .order_by(ledger.c.seq.desc())
                .limit(1)
            ).first()
            return row[0] if row else "0" * 64

    def append_ledger(self, values: dict[str, Any]) -> None:
        self.insert_row(ledger, values)

    def read_ledger(
        self, tenant_id: str, case_id: str | None = None, run_id: str | None = None
    ) -> list[dict[str, Any]]:
        q = select(ledger).where(ledger.c.tenant_id == tenant_id)
        if case_id:
            q = q.where(ledger.c.case_id == case_id)
        if run_id:
            q = q.where(ledger.c.run_id == run_id)
        q = q.order_by(ledger.c.seq.asc())
        with self.engine.begin() as conn:
            return [dict(r) for r in conn.execute(q).mappings().all()]

    # --- crypto keystore + blobs ---

    def put_key(self, key_ref: str, tenant_id: str, key_material: bytes) -> None:
        self.insert_row(
            crypto_keys,
            {
                "key_ref": key_ref,
                "tenant_id": tenant_id,
                "key_material": key_material,
                "created_at": _utcnow(),
                "erased": False,
            },
        )

    def get_key(self, key_ref: str) -> bytes | None:
        with self.engine.begin() as conn:
            row = conn.execute(
                select(crypto_keys.c.key_material, crypto_keys.c.erased).where(
                    crypto_keys.c.key_ref == key_ref
                )
            ).first()
            if not row or row[1]:
                return None
            return row[0]

    def destroy_key(self, key_ref: str) -> None:
        with self.engine.begin() as conn:
            conn.execute(
                update(crypto_keys)
                .where(crypto_keys.c.key_ref == key_ref)
                .values(key_material=None, erased=True)
            )

    def put_blob(self, values: dict[str, Any]) -> None:
        self.insert_row(crypto_blobs, values)

    def get_blob(self, token: str) -> dict[str, Any] | None:
        with self.engine.begin() as conn:
            row = (
                conn.execute(select(crypto_blobs).where(crypto_blobs.c.token == token))
                .mappings()
                .first()
            )
            return dict(row) if row else None

    def delete_blob(self, token: str) -> None:
        with self.engine.begin() as conn:
            conn.execute(delete(crypto_blobs).where(crypto_blobs.c.token == token))
