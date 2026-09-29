"""db/database.py — Database engine and session setup.

Supports SQLite by default for zero-friction local development,
and PostgreSQL via the DATABASE_URL environment variable.
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATA_DIR = os.path.join(os.getcwd(), "data")
os.makedirs(DATA_DIR, exist_ok=True)

DEFAULT_DB_URL = f"sqlite:///{os.path.join(DATA_DIR, 'merkletrust.db')}"
DATABASE_URL = os.environ.get("DATABASE_URL", DEFAULT_DB_URL)

# Connect args needed for SQLite thread concurrency
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    echo=False,
    future=True,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """FastAPI dependency for yielding database sessions."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all tables in the database."""
    from db import models  # noqa: F401
    Base.metadata.create_all(bind=engine)
