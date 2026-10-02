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

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, declarative_base, sessionmaker

from core.config import get_settings

Base = declarative_base()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, expire_on_commit=False)
_engine: Engine | None = None


def _enable_sqlite_foreign_keys(dbapi_conn, _record) -> None:
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA foreign_keys=ON")
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
        event.listen(_engine, "connect", _enable_sqlite_foreign_keys)
    SessionLocal.configure(bind=_engine)
    return _engine


def get_engine() -> Engine:
    return _engine if _engine is not None else configure_database()


def init_db() -> None:
    """Create all tables that do not exist yet."""
    from db import models  # noqa: F401  (registers models)
    Base.metadata.create_all(bind=get_engine())


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
