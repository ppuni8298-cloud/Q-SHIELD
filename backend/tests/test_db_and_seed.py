"""Tests for Alembic empty-DB migration, SQLite pragmas, corruption safety, rollback, and seed/reset."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from backend.app.db.models import User
from backend.app.db.session import (
    DatabaseIntegrityError,
    create_db_engine,
    create_session_factory,
    validate_sqlite_file_or_raise,
    verify_database_health,
)
from backend.app.services.seed import DEMO_SYNTHETIC_TOKENS, seed_database
from backend.tests.conftest import ALEMBIC_INI, REPO_ROOT, run_alembic_upgrade


def test_alembic_migrates_all_25_tables_from_empty_db(isolated_db_path: Path) -> None:
    assert not isolated_db_path.exists()
    url = run_alembic_upgrade(isolated_db_path)
    engine = create_db_engine(url)
    try:
        ok, detail = verify_database_health(engine)
        assert ok is True, detail
        with engine.connect() as conn:
            fk = conn.execute(text("PRAGMA foreign_keys")).scalar()
            journal = conn.execute(text("PRAGMA journal_mode")).scalar()
            busy = conn.execute(text("PRAGMA busy_timeout")).scalar()
            tables = {
                row[0]
                for row in conn.execute(
                    text("SELECT name FROM sqlite_master WHERE type='table' AND name != 'alembic_version'")
                ).fetchall()
            }
        assert fk == 1
        assert str(journal).lower() == "wal"
        assert int(busy) >= 5000

        expected_tables = {
            # 23 Master Build Prompt Section 12 tables
            "users",
            "devices",
            "sessions",
            "resources",
            "resource_permissions",
            "encrypted_objects",
            "key_metadata",
            "rotation_operations",
            "node_registry",
            "node_acknowledgements",
            "revocation_tombstones",
            "incidents",
            "audit_events",
            "audit_checkpoints",
            "access_requests",
            "messages",
            "sessions_crypto",
            "replay_records",
            "detector_events",
            "alerts",
            "benchmarks",
            "backup_manifests",
            "settings",
            # 2 Phase-2 normalized support tables
            "role_permissions",
            "device_state_history",
            # 2 Phase-4 revocation propagation & node inbox tables
            "revocation_events",
            "node_event_inbox",
            # Phase 5 in-flight transfer continuity table
            "in_flight_transfers",
            # Phase 6 signed audit evidence receipts table
            "audit_evidence_receipts",
            # Phase 7 deterministic detection runs table
            "detection_runs",
            # Phase 8 simulated delivery reliability telemetry table
            "message_deliveries",
        }
        assert tables == expected_tables

        # Verify downgrade -> upgrade cycle cleanly
        cfg = Config(str(ALEMBIC_INI))
        cfg.set_main_option("script_location", str(REPO_ROOT / "backend" / "alembic"))
        cfg.set_main_option("sqlalchemy.url", url)
        command.downgrade(cfg, "base")
        command.upgrade(cfg, "head")
        ok_after, _ = verify_database_health(engine)
        assert ok_after is True
    finally:
        engine.dispose()


def test_seed_idempotency_reset_and_no_plaintext_tokens(db_engine) -> None:
    factory = create_session_factory(db_engine)
    with factory() as db:
        s1 = seed_database(db, reset=False)
        assert s1.users_seeded == 6
        assert s1.devices_seeded == 8
        assert s1.sessions_seeded == 7
        assert s1.resources_seeded == 6

        # Calling seed again without reset must be idempotent
        s2 = seed_database(db, reset=False)
        assert s2 == s1

        # Mutate state and reset
        alex = db.get(User, "user-alex")
        assert alex is not None
        alex.enabled = False
        db.commit()

        s3 = seed_database(db, reset=True)
        assert s3 == s1
        alex_after = db.get(User, "user-alex")
        assert alex_after is not None and alex_after.enabled is True

        # Ensure raw demo tokens are NEVER stored in sessions.token_hash
        rows = db.execute(text("SELECT token_hash FROM sessions")).fetchall()
        hashes = {r[0] for r in rows}
        for raw_token in DEMO_SYNTHETIC_TOKENS.values():
            assert raw_token not in hashes


def test_transaction_rollback_and_foreign_key_enforcement(db_session) -> None:
    # Foreign key constraint rejects device with nonexistent owner
    db_session.execute(
        text(
            "INSERT INTO users (id, display_name, role, enabled, is_synthetic, created_at, updated_at) "
            "VALUES ('temp-user', 'Temp', 'owner', 1, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
        )
    )
    db_session.rollback()
    assert db_session.get(User, "temp-user") is None

    with pytest.raises(IntegrityError):
        db_session.execute(
            text(
                "INSERT INTO devices (id, owner_id, credential_fingerprint, state, state_version, enrolled_at) "
                "VALUES ('bad-dev', 'nonexistent-owner', 'fp-bad', 'PENDING', 1, CURRENT_TIMESTAMP)"
            )
        )
        db_session.commit()
    db_session.rollback()


def test_missing_and_corrupt_sqlite_detection(tmp_path: Path) -> None:
    missing = tmp_path / "does_not_exist.sqlite3"
    with pytest.raises(DatabaseIntegrityError):
        validate_sqlite_file_or_raise(missing)

    corrupt = tmp_path / "corrupt.sqlite3"
    corrupt.write_bytes(b"NOT A SQLITE DATABASE HEADER AT ALL 1234567890")
    with pytest.raises(DatabaseIntegrityError):
        validate_sqlite_file_or_raise(corrupt)

    engine = create_db_engine(f"sqlite:///{corrupt.as_posix()}", wal_mode=False)
    try:
        ok, _ = verify_database_health(engine)
        assert ok is False
    finally:
        engine.dispose()
