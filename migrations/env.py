"""Alembic environment: runs migrations against the configured MerkleTrust database."""

from alembic import context
from sqlalchemy import create_engine

from core.config import get_settings
from db import models  # noqa: F401  (registers all tables on Base.metadata)
from db.database import Base

target_metadata = Base.metadata


def run_migrations_online() -> None:
    connection = context.config.attributes.get("connection")
    if connection is not None:  # provided programmatically (db.migrations.upgrade_database)
        _run(connection)
        return
    engine = create_engine(get_settings().resolved_database_url)
    with engine.connect() as conn:
        _run(conn)


def _run(connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata,
                      render_as_batch=connection.dialect.name == "sqlite", compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_offline() -> None:
    context.configure(url=get_settings().resolved_database_url, target_metadata=target_metadata,
                      literal_binds=True, render_as_batch=True)
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
