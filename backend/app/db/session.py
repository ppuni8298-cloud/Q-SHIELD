"""SQLite engine, pragma enforcement, health checks, and session management."""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path
import sqlite3
from typing import Any

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from backend.app.config import Settings, settings


class DatabaseIntegrityError(RuntimeError):
    """Raised when the database file is missing required schema or appears corrupt."""


def configure_sqlite_pragmas(
    dbapi_connection: Any,
    *,
    busy_timeout_ms: int = 5000,
    wal_mode: bool = True,
) -> None:
    """Enforce SQLite foreign keys, busy timeout, synchronous mode, and optional WAL."""
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
        cursor.execute("PRAGMA synchronous=FULL")
        if wal_mode:
            cursor.execute("PRAGMA journal_mode=WAL")
    finally:
        cursor.close()


def create_db_engine(
    database_url: str | None = None,
    *,
    busy_timeout_ms: int | None = None,
    wal_mode: bool | None = None,
) -> Engine:
    """Create a configured SQLAlchemy 2 engine for SQLite."""
    resolved_url = database_url or settings.resolved_database_url()
    timeout_ms = busy_timeout_ms if busy_timeout_ms is not None else settings.sqlite_busy_timeout_ms
    use_wal = wal_mode if wal_mode is not None else settings.sqlite_wal_mode

    connect_args: dict[str, Any] = {}
    if resolved_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
        connect_args["timeout"] = timeout_ms / 1000.0

    engine = create_engine(resolved_url, connect_args=connect_args, future=True)

    if resolved_url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def _on_connect(dbapi_conn: Any, _connection_record: Any) -> None:
            configure_sqlite_pragmas(dbapi_conn, busy_timeout_ms=timeout_ms, wal_mode=use_wal)

    return engine


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Build a sessionmaker bound to the provided engine."""
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def verify_database_health(engine: Engine) -> tuple[bool, str]:
    """Run SQLite quick_check and verify core schema presence safely."""
    try:
        with engine.connect() as conn:
            quick = conn.execute(text("PRAGMA quick_check")).scalar()
            if quick != "ok":
                return False, f"SQLite quick_check failed: {quick}"
            tables = {
                row[0]
                for row in conn.execute(
                    text("SELECT name FROM sqlite_master WHERE type='table'")
                ).fetchall()
            }
            required = {"users", "devices", "sessions", "resources", "role_permissions"}
            missing = sorted(required - tables)
            if missing:
                return False, f"Missing required tables: {', '.join(missing)}"
            return True, "ok"
    except (SQLAlchemyError, sqlite3.DatabaseError) as exc:
        return False, f"Database health check failed safely ({type(exc).__name__})"


def validate_sqlite_file_or_raise(db_path: Path) -> None:
    """Detect missing or corrupt SQLite file before attempting operations."""
    if not db_path.exists():
        raise DatabaseIntegrityError(f"Database file does not exist: {db_path}")
    try:
        conn = sqlite3.connect(str(db_path))
        try:
            res = conn.execute("PRAGMA quick_check").fetchone()
            if not res or res[0] != "ok":
                raise DatabaseIntegrityError("SQLite integrity check failed")
        finally:
            conn.close()
    except sqlite3.DatabaseError as exc:
        raise DatabaseIntegrityError("SQLite file is unreadable or corrupt") from exc


_default_engine = create_db_engine(settings.resolved_database_url())
SessionLocal = create_session_factory(_default_engine)


def get_engine(app_settings: Settings | None = None) -> Engine:
    """Return default engine or build one for custom settings."""
    if app_settings is None:
        return _default_engine
    return create_db_engine(
        app_settings.resolved_database_url(),
        busy_timeout_ms=app_settings.sqlite_busy_timeout_ms,
        wal_mode=app_settings.sqlite_wal_mode,
    )


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a database session and closing cleanly."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
