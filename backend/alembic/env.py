"""Alembic environment configuration for Q-SHIELD SQLite/ORM migrations."""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, event, pool

from backend.app.config import settings
from backend.app.db.base import Base
from backend.app.db import models  # noqa: F401
from backend.app.db.session import configure_sqlite_pragmas

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _get_url() -> str:
    configured = config.get_main_option("sqlalchemy.url")
    if configured:
        return configured
    return settings.resolved_database_url()


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = _get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode with SQLite PRAGMAs enforced."""
    section = config.get_section(config.config_ini_section, {})
    url = _get_url()
    section["sqlalchemy.url"] = url

    connectable = engine_from_config(
        section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    if url.startswith("sqlite"):

        @event.listens_for(connectable, "connect")
        def _on_connect(dbapi_conn, _record) -> None:
            configure_sqlite_pragmas(
                dbapi_conn,
                busy_timeout_ms=settings.sqlite_busy_timeout_ms,
                wal_mode=settings.sqlite_wal_mode,
            )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
