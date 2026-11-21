"""SQLite storage (WAL). Everything the server keeps is in this one file."""

from __future__ import annotations

import os
import uuid
from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import BigInteger, Boolean, Index, LargeBinary, String, create_engine, event, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

SCHEMA_VERSION = 1


class Base(DeclarativeBase):
    pass


class Meta(Base):
    """Key/value: vault_id, seq (the global change counter), schema_version."""

    __tablename__ = "meta"
    key: Mapped[str] = mapped_column(String(32), primary_key=True)
    value: Mapped[str] = mapped_column(String(64))


class Device(Base):
    __tablename__ = "devices"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(64))
    platform: Mapped[str] = mapped_column(String(16))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[int] = mapped_column(BigInteger)
    last_seen_at: Mapped[int] = mapped_column(BigInteger)
    revoked_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)


class EnrollmentCode(Base):
    __tablename__ = "enrollment_codes"
    code_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[int] = mapped_column(BigInteger)
    expires_at: Mapped[int] = mapped_column(BigInteger)
    used_at: Mapped[int | None] = mapped_column(BigInteger, nullable=True)


class Record(Base):
    __tablename__ = "records"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    seq: Mapped[int] = mapped_column(BigInteger)
    deleted: Mapped[bool] = mapped_column(Boolean)
    blob: Mapped[bytes] = mapped_column(LargeBinary)
    device_id: Mapped[str] = mapped_column(String(36))
    updated_at: Mapped[int] = mapped_column(BigInteger)

    __table_args__ = (Index("ix_records_seq", "seq", unique=True),)


class Keyslot(Base):
    __tablename__ = "keyslot"
    id: Mapped[int] = mapped_column(primary_key=True)  # always 1
    version: Mapped[int] = mapped_column(BigInteger)
    blob: Mapped[bytes] = mapped_column(LargeBinary)
    updated_at: Mapped[int] = mapped_column(BigInteger)


class Database:
    def __init__(self, path: str) -> None:
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
        # hide_parameters: SQL errors must never carry blobs or hashes into logs.
        self.engine = create_engine(
            f"sqlite:///{path}",
            connect_args={"timeout": 30, "check_same_thread": False},
            hide_parameters=True,
        )

        @event.listens_for(self.engine, "connect")
        def _on_connect(dbapi_conn, _record):
            # We issue BEGIN ourselves (below), so stop pysqlite doing it.
            dbapi_conn.isolation_level = None
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            # FULL: an acknowledged push must survive power loss, otherwise seq
            # numbers could be reused and clients would skip changes.
            cur.execute("PRAGMA synchronous=FULL")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

        @event.listens_for(self.engine, "begin")
        def _on_begin(conn):
            # Take the write lock up front: transactions are strictly serialised,
            # which is what makes seq assignment gap-free and ordered.
            conn.exec_driver_sql("BEGIN IMMEDIATE")

        Base.metadata.create_all(self.engine)
        with self.tx() as s:
            defaults = {
                "vault_id": str(uuid.uuid4()),
                "seq": "0",
                "schema_version": str(SCHEMA_VERSION),
            }
            for key, value in defaults.items():
                if s.get(Meta, key) is None:
                    s.add(Meta(key=key, value=value))

    @contextmanager
    def tx(self) -> Iterator[Session]:
        """One serialised transaction; commits on success, rolls back on error."""
        with Session(self.engine, expire_on_commit=False) as s, s.begin():
            yield s

    def close(self) -> None:
        self.engine.dispose()


def get_meta(s: Session, key: str) -> str:
    return s.execute(select(Meta.value).where(Meta.key == key)).scalar_one()


def get_seq(s: Session) -> int:
    return int(get_meta(s, "seq"))


def set_seq(s: Session, seq: int) -> None:
    s.get(Meta, "seq").value = str(seq)
