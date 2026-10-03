"""db/database.py — Database engine and session management.

The database URL comes from configuration (MERKLETRUST_DATABASE_URL, default a
SQLite file in the data directory). SQLite is the tested target; the models use
portable SQLAlchemy types.

The engine is created lazily on first use so that tests (and tools) can point
the application at an isolated database before anything connects.
"""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from sqlalchemy import Engine, create_engine, event, inspect
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from core.config import get_settings

Base = declarative_base()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, expire_on_commit=False)
_engine: Engine | None = None


def _configure_sqlite(dbapi_conn, _record) -> None:
    """Per-connection SQLite settings.

    foreign_keys  enforce declared foreign keys (off by default in SQLite).
    WAL journal   write-ahead logging: commits append to one log file instead of
                  creating and deleting a rollback journal each time (measured: the
                  per-commit journal churn dominated request time), and readers no
                  longer block the writer.
    synchronous   FULL: every commit is flushed to disk, so an acknowledged audit
                  event survives a power failure.
    busy_timeout  wait up to 5 s for a competing writer instead of failing at once.
    """
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA foreign_keys=ON")
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA synchronous=FULL")
    cur.execute("PRAGMA busy_timeout=5000")
    cur.close()


def configure_database(url: str | None = None) -> Engine:
    """(Re)bind the session factory to `url` (default: configured URL)."""
    global _engine
    url = url or get_settings().resolved_database_url
    if _engine is not None:
        _engine.dispose()
    if url.startswith("sqlite:///"):
        Path(url[len("sqlite:///"):]).parent.mkdir(parents=True, exist_ok=True)
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    _engine = create_engine(url, connect_args=connect_args, future=True)
    if url.startswith("sqlite"):
        event.listen(_engine, "connect", _configure_sqlite)
    SessionLocal.configure(bind=_engine)
    return _engine


def get_engine() -> Engine:
    return _engine if _engine is not None else configure_database()


_initialised: set[str] = set()


def init_db() -> None:
    """Make sure the schema exists and is current (idempotent, once per process and URL).

    Empty database: create all tables and stamp them at the latest migration.
    Migrated database: apply pending migrations. Legacy database: refused
    (see db.migrations.upgrade_database).
    """
    from db import models  # noqa: F401  (registers models)
    from db.migrations import stamp_new_database, upgrade_database

    engine = get_engine()
    key = str(engine.url)
    if key in _initialised:
        return
    if not inspect(engine).get_table_names():
        Base.metadata.create_all(bind=engine)
        stamp_new_database(engine)
    else:
        upgrade_database(engine)
    _initialised.add(key)


def get_db() -> Iterator[Session]:
    """FastAPI dependency yielding a session."""
    get_engine()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional scope: commit on success, roll back on any error."""
    get_engine()
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
