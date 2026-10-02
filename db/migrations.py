"""db/migrations.py — Apply Alembic migrations programmatically (used at API startup)."""

from __future__ import annotations

import logging
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, inspect

log = logging.getLogger("merkletrust.db")
ROOT = Path(__file__).resolve().parent.parent


class LegacyDatabaseError(RuntimeError):
    pass


def alembic_config() -> Config:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    return cfg


def upgrade_database(engine: Engine) -> None:
    """Bring the schema to the latest revision.

    A database created before migrations existed (tables present, no alembic_version)
    is refused rather than guessed at: back it up and remove it, or point
    MERKLETRUST_DATABASE_URL at a new database.
    """
    tables = set(inspect(engine).get_table_names())
    if tables and "alembic_version" not in tables:
        raise LegacyDatabaseError(
            f"The database at {engine.url!r} predates schema migrations. Back it up and remove it "
            "(or set MERKLETRUST_DATABASE_URL to a new database), then start again.")
    cfg = alembic_config()
    with engine.begin() as conn:
        cfg.attributes["connection"] = conn
        command.upgrade(cfg, "head")
    log.info("database schema is up to date")


def stamp_new_database(engine: Engine) -> None:
    """Record that a database freshly created from the models is at the latest revision."""
    cfg = alembic_config()
    with engine.begin() as conn:
        cfg.attributes["connection"] = conn
        command.stamp(cfg, "head")
