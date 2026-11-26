"""Shared pytest fixtures creating isolated Alembic-migrated SQLite databases."""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
import pytest
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from backend.app.backups.service import get_backup_dir
from backend.app.crypto.keystore import LocalEncryptedKeyStore, get_keystore
from backend.app.db.session import create_db_engine, create_session_factory, get_db
from backend.app.main import create_app
from backend.app.services.seed import seed_database

REPO_ROOT = Path(__file__).resolve().parents[2]
ALEMBIC_INI = REPO_ROOT / "backend" / "alembic.ini"


def run_alembic_upgrade(db_path: Path) -> str:
    """Run Alembic migrations on an isolated SQLite database path."""
    url = f"sqlite:///{db_path.as_posix()}"
    cfg = Config(str(ALEMBIC_INI))
    cfg.set_main_option("script_location", str(REPO_ROOT / "backend" / "alembic"))
    cfg.set_main_option("sqlalchemy.url", url)
    command.upgrade(cfg, "head")
    return url


@pytest.fixture()
def isolated_db_path(tmp_path: Path) -> Path:
    return tmp_path / "test_qshield.sqlite3"


@pytest.fixture()
def db_engine(isolated_db_path: Path) -> Generator[Engine, None, None]:
    url = run_alembic_upgrade(isolated_db_path)
    engine = create_db_engine(url, busy_timeout_ms=5000, wal_mode=True)
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture()
def keystore(tmp_path: Path) -> LocalEncryptedKeyStore:
    return LocalEncryptedKeyStore(tmp_path / "keystore")


@pytest.fixture()
def backup_dir(tmp_path: Path) -> Path:
    return tmp_path / "backups"


@pytest.fixture()
def db_session(db_engine: Engine, keystore: LocalEncryptedKeyStore, backup_dir: Path) -> Generator[Session, None, None]:
    factory = create_session_factory(db_engine)
    session = factory()
    try:
        seed_database(session, reset=True, keystore=keystore, backup_dir=backup_dir)
        yield session
    finally:
        session.close()


@pytest.fixture()
def client(db_engine: Engine, keystore: LocalEncryptedKeyStore, backup_dir: Path) -> Generator[TestClient, None, None]:
    factory = create_session_factory(db_engine)
    with factory() as seed_sess:
        seed_database(seed_sess, reset=True, keystore=keystore, backup_dir=backup_dir)

    app = create_app()

    def _override_get_db() -> Generator[Session, None, None]:
        sess = factory()
        try:
            yield sess
        finally:
            sess.close()

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_keystore] = lambda: keystore
    app.dependency_overrides[get_backup_dir] = lambda: backup_dir
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
