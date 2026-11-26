"""Application configuration using Pydantic Settings (offline-first)."""

from __future__ import annotations

import os
from pathlib import Path
import tempfile

from pydantic_settings import BaseSettings, SettingsConfigDict


def _default_sqlite_path() -> str:
    state_dir = os.environ.get("QSHIELD_STATE_DIR") or os.environ.get("TRACK4_STATE_DIR")
    base = Path(state_dir) if state_dir else Path(tempfile.gettempdir()) / "qshield"
    return str(base / "qshield_control_plane.sqlite3")


def _default_keystore_dir() -> str:
    state_dir = os.environ.get("QSHIELD_STATE_DIR") or os.environ.get("TRACK4_STATE_DIR")
    base = Path(state_dir) if state_dir else Path(tempfile.gettempdir()) / "qshield"
    return str(base / "keystore")


def _default_backup_dir() -> str:
    state_dir = os.environ.get("QSHIELD_STATE_DIR") or os.environ.get("TRACK4_STATE_DIR")
    base = Path(state_dir) if state_dir else Path(tempfile.gettempdir()) / "qshield"
    return str(base / "backups")


def _default_audit_outbox_path() -> str:
    state_dir = os.environ.get("QSHIELD_STATE_DIR") or os.environ.get("TRACK4_STATE_DIR")
    base = Path(state_dir) if state_dir else Path(tempfile.gettempdir()) / "qshield"
    return str(base / "audit_outbox.jsonl")


class Settings(BaseSettings):
    """Q-SHIELD backend configuration with offline-safe defaults."""

    model_config = SettingsConfigDict(env_prefix="QSHIELD_", extra="ignore")

    app_name: str = "Q-SHIELD Control Plane"
    api_prefix: str = "/api/v1"
    demo_mode: bool = True
    offline_mode: bool = True
    db_path: str = _default_sqlite_path()
    database_url: str | None = None
    keystore_dir: str = _default_keystore_dir()
    keystore_secret: str | None = None
    backup_dir: str = _default_backup_dir()
    backup_secret: str | None = None
    audit_outbox_path: str = _default_audit_outbox_path()
    sqlite_busy_timeout_ms: int = 5000
    sqlite_wal_mode: bool = True
    session_ttl_minutes: int = 120
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    def resolved_database_url(self) -> str:
        """Return SQLAlchemy database URL, ensuring parent directory exists for SQLite."""
        if self.database_url:
            return self.database_url
        path = Path(self.db_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        return f"sqlite:///{path.as_posix()}"


settings = Settings()
