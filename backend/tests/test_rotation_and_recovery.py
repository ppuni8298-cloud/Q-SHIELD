"""Independent tests for Phase 5 Key Rotation, Zero-Grace Cutoff, 8-Point Crash Recovery & Subprocess Restart."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from backend.app.auth.dependencies import AuthContext
from backend.app.config import settings
from backend.app.crypto.keystore import LocalEncryptedKeyStore
from backend.app.db.models import (
    Device,
    InFlightTransfer,
    KeyMetadata,
    NodeRegistry,
    Resource,
    RevocationTombstone,
    RotationOperation,
    User,
    UserSession,
)
from backend.app.keys.rotation import (
    CRASH_INJECTION_POINTS,
    RotationError,
    SimulatedCrashError,
    advance_rotation,
    execute_rotation,
    start_in_flight_transfer,
)
from backend.app.nodes.simulator import node_evaluate_access
from backend.app.recovery.manager import recover_rotations
from backend.app.services.seed import DEMO_SYNTHETIC_TOKENS
from backend.app.vault.crypto_vault import CryptoVaultError, decrypt_resource_content, encrypt_resource_content


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _ctx(db: Session, user_id: str = "user-alex", device_id: str = "dev-alex-trusted", session_id: str = "sess-alex-valid") -> AuthContext:
    return AuthContext(
        user=db.get(User, user_id),
        session=db.get(UserSession, session_id),
        device=db.get(Device, device_id),
        correlation_id="corr-phase5-test",
    )


def test_full_phased_rotation_rewraps_vault_and_enforces_zero_grace_cutoff(
    client: TestClient,
    db_engine,
    db_session: Session,
    keystore: LocalEncryptedKeyStore,
    backup_dir: Path,
) -> None:
    alex_tok = DEMO_SYNTHETIC_TOKENS["sess-alex-valid"]
    secops_tok = DEMO_SYNTHETIC_TOKENS["sess-secops-valid"]
    auditor_tok = DEMO_SYNTHETIC_TOKENS["sess-auditor-valid"]

    # 1. Encrypt res-alex-brief under initial active key v1
    secret_text = "Q-SHIELD Phase 5 continuity secret message"
    enc = client.post(
        "/api/v1/resources/res-alex-brief/encrypt",
        json={"plaintext": secret_text},
        headers=_auth(alex_tok),
    )
    assert enc.status_code == 201
    assert enc.json()["crypto_metadata"]["key_version"] == 1

    # RBAC checks: owner denied rotation/recovery; auditor read-only
    assert (
        client.post(
            "/api/v1/keys/rotate",
            json={"purpose": "vault_kek", "reason": "Unauthorized rotate"},
            headers=_auth(alex_tok),
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/v1/keys/rotate",
            json={"purpose": "vault_kek", "reason": "Auditor rotate denied"},
            headers=_auth(auditor_tok),
        ).status_code
        == 403
    )

    # 2. Execute full phased rotation via API (PREPARE -> backup -> DISTRIBUTE -> COMMIT -> RETIRE)
    rot = client.post(
        "/api/v1/keys/rotate",
        json={
            "purpose": "vault_kek",
            "new_key_id": "key-v2-rotated",
            "grace_policy": "ZERO_GRACE",
            "reason": "Scheduled Phase 5 KEK rotation",
            "auto_advance": True,
        },
        headers=_auth(secops_tok),
    )
    assert rot.status_code == 201
    op_data = rot.json()["operation"]
    assert op_data["phase"] == "RETIRE"
    assert op_data["status"] == "COMPLETED"
    assert op_data["committed"] is True
    assert op_data["from_version"] == 1
    assert op_data["to_version"] == 2
    assert op_data["backup_id"] is not None
    assert op_data["grace_policy"] == "ZERO_GRACE"

    # Auditor can read rotation history
    rot_list = client.get("/api/v1/keys/rotations", headers=_auth(auditor_tok))
    assert rot_list.status_code == 200
    assert any(r["operation_id"] == op_data["operation_id"] for r in rot_list.json())

    # 3. Verify resource moved to v2 and decrypts identically to original plaintext
    dec = client.post("/api/v1/resources/res-alex-brief/decrypt", headers=_auth(alex_tok))
    assert dec.status_code == 200
    assert dec.json()["plaintext"] == secret_text
    assert dec.json()["crypto_metadata"]["key_version"] == 2

    # 4. Verify v1 key is RETIRED, v2 is ACTIVE, and every simulated node enforces cutoff_epoch=2
    db_session.expire_all()
    assert db_session.get(KeyMetadata, "key-v1-active").state == "RETIRED"
    assert db_session.get(KeyMetadata, "key-v2-rotated").state == "ACTIVE"
    nodes = list(db_session.scalars(select(NodeRegistry).order_by(NodeRegistry.node_id)).all())
    assert len(nodes) == 3
    for node in nodes:
        assert node.accepted_key_version == 2
        assert node.cutoff_epoch == 2

    # 5. Simulate an old-key (v1) access attempt on every node -> MUST fail closed with DENY_NODE_OLD_KEY_CUTOFF
    legacy_res = Resource(
        id="res-legacy-v1-check",
        owner_id="user-alex",
        type="synthetic_document",
        metadata_json='{"title":"Legacy v1 check"}',
        key_version=1,
        state="ACTIVE",
    )
    db_session.add(legacy_res)
    db_session.commit()
    ctx = _ctx(db_session)
    for node in nodes:
        decision, reason, _req, pt = node_evaluate_access(
            db_session, keystore, node_id=node.node_id, ctx=ctx, resource_id="res-legacy-v1-check", decrypt=False
        )
        assert decision == "DENY"
        assert reason == "DENY_NODE_OLD_KEY_CUTOFF"
        assert pt is None


def test_concurrency_guard_and_controlled_in_flight_transfer_vs_zero_grace(
    client: TestClient,
    db_session: Session,
    keystore: LocalEncryptedKeyStore,
    backup_dir: Path,
) -> None:
    alex_tok = DEMO_SYNTHETIC_TOKENS["sess-alex-valid"]
    secops_tok = DEMO_SYNTHETIC_TOKENS["sess-secops-valid"]

    # Encrypt res-alex-brief on v1
    assert (
        client.post(
            "/api/v1/resources/res-alex-brief/encrypt",
            json={"plaintext": "Transfer continuity body"},
            headers=_auth(alex_tok),
        ).status_code
        == 201
    )

    # Start rotation without auto_advance -> pauses at PREPARE (IN_PROGRESS)
    r1 = client.post(
        "/api/v1/keys/rotate",
        json={"purpose": "vault_kek", "reason": "First lock check", "auto_advance": False},
        headers=_auth(secops_tok),
    )
    assert r1.status_code == 201
    op_id = r1.json()["operation"]["operation_id"]

    # Concurrent second rotation for same purpose MUST be rejected (409)
    r2 = client.post(
        "/api/v1/keys/rotate",
        json={"purpose": "vault_kek", "reason": "Concurrent conflict"},
        headers=_auth(secops_tok),
    )
    assert r2.status_code == 409
    assert r2.json()["error"]["code"] == "ROTATION_ALREADY_IN_PROGRESS"

    # Start an explicit pre-cutoff transfer before finishing DISTRIBUTE/COMMIT under ZERO_GRACE
    tx_zg = client.post(
        "/api/v1/keys/transfers/start",
        json={"resource_id": "res-alex-brief", "allow_post_cutoff": True},
        headers=_auth(alex_tok),
    )
    assert tx_zg.status_code == 201
    tx_zg_id = tx_zg.json()["transfer_id"]

    # Complete first ZERO_GRACE rotation -> aborts tx_zg
    adv = client.post(
        f"/api/v1/keys/rotations/{op_id}/advance",
        json={},
        headers=_auth(secops_tok),
    )
    assert adv.status_code == 200 and adv.json()["operation"]["status"] == "COMPLETED"

    tx_zg_comp = client.post(
        f"/api/v1/keys/transfers/{tx_zg_id}/complete",
        headers=_auth(alex_tok),
    )
    assert tx_zg_comp.status_code in (403, 409)
    assert tx_zg_comp.json()["error"]["code"] in (
        "DENY_OLD_KEY_CUTOFF",
        "TRANSFER_NOT_ACTIVE",
        "DENY_TRANSFER_KEY_REVOKED",
    )

    # Now test CONTROLLED_IN_FLIGHT_ONLY policy on rotation v2 -> v3
    tx_ok = client.post(
        "/api/v1/keys/transfers/start",
        json={"resource_id": "res-alex-brief", "allow_post_cutoff": True},
        headers=_auth(alex_tok),
    )
    assert tx_ok.status_code == 201
    tx_ok_id = tx_ok.json()["transfer_id"]

    rot_ctrl = client.post(
        "/api/v1/keys/rotate",
        json={
            "purpose": "vault_kek",
            "grace_policy": "CONTROLLED_IN_FLIGHT_ONLY",
            "reason": "Continuity policy test",
            "auto_advance": False,
        },
        headers=_auth(secops_tok),
    )
    assert rot_ctrl.status_code == 201
    ctrl_id = rot_ctrl.json()["operation"]["operation_id"]

    # Advance up to COMMIT (before RETIRE)
    adv_commit = client.post(
        f"/api/v1/keys/rotations/{ctrl_id}/advance",
        json={"target_phase": "COMMIT"},
        headers=_auth(secops_tok),
    )
    assert adv_commit.status_code == 200
    assert adv_commit.json()["operation"]["phase"] == "COMMIT"
    assert adv_commit.json()["operation"]["committed"] is True

    # New request without registered transfer_id MUST FAIL CLOSED at cutoff
    db_session.expire_all()
    ctx = _ctx(db_session)
    deny_new, deny_reason, _, _ = node_evaluate_access(
        db_session, keystore, node_id="node-1", ctx=ctx, resource_id="res-alex-brief", decrypt=True
    )
    assert deny_new == "DENY"
    assert deny_reason == "DENY_NODE_OLD_KEY_CUTOFF"

    # Registered pre-cutoff in-flight transfer IS permitted to finish read & complete!
    allow_tx, allow_reason, _, pt = node_evaluate_access(
        db_session,
        keystore,
        node_id="node-1",
        ctx=ctx,
        resource_id="res-alex-brief",
        decrypt=True,
        transfer_id=tx_ok_id,
    )
    assert allow_tx == "ALLOW" and pt == "Transfer continuity body"

    comp_ok = client.post(f"/api/v1/keys/transfers/{tx_ok_id}/complete", headers=_auth(alex_tok))
    assert comp_ok.status_code == 200
    assert comp_ok.json()["decision"] == "ALLOW_IN_FLIGHT_CONTINUITY"

    # Now finish RETIRE -> all resources move to v3 and v2 retires
    adv_retire = client.post(
        f"/api/v1/keys/rotations/{ctrl_id}/advance",
        json={},
        headers=_auth(secops_tok),
    )
    assert adv_retire.status_code == 200
    assert adv_retire.json()["operation"]["status"] == "COMPLETED"


@pytest.mark.parametrize("crash_point", sorted(CRASH_INJECTION_POINTS))
def test_all_8_deterministic_crash_points_and_idempotent_recovery(
    db_session: Session,
    keystore: LocalEncryptedKeyStore,
    backup_dir: Path,
    crash_point: str,
) -> None:
    ctx = _ctx(db_session)
    secret_text = f"Crash matrix payload for {crash_point}"
    encrypt_resource_content(db_session, keystore, ctx=ctx, resource_id="res-alex-brief", plaintext=secret_text)

    with pytest.raises(SimulatedCrashError) as exc_info:
        execute_rotation(
            db_session,
            keystore,
            purpose="vault_kek",
            actor_id="user-secops",
            new_key_id="key-v2-crash",
            reason=f"Crash drill {crash_point}",
            auto_advance=True,
            crash_at=crash_point,
            backup_dir=backup_dir,
        )
    assert exc_info.value.crash_point == crash_point
    op_id = exc_info.value.operation_id

    if crash_point == "AFTER_NODE_1_ACK":
        db_session.expire_all()
        acks = json.loads(db_session.get(RotationOperation, op_id).node_acks_json)
        assert list(acks.values()).count("ACKED") == 1
    elif crash_point == "AFTER_NODE_2_ACK":
        db_session.expire_all()
        acks = json.loads(db_session.get(RotationOperation, op_id).node_acks_json)
        assert list(acks.values()).count("ACKED") == 2

    outcomes = recover_rotations(db_session, keystore, operation_id=op_id)
    assert len(outcomes) == 1
    outcome = outcomes[0]
    assert outcome.idempotent_noop is False

    db_session.expire_all()
    op = db_session.get(RotationOperation, op_id)

    if crash_point in ("AFTER_PREPARE", "AFTER_BACKUP", "AFTER_NODE_1_ACK", "AFTER_NODE_2_ACK", "BEFORE_COMMIT"):
        assert outcome.final_status == "RECOVERED_PRE_COMMIT"
        assert op.committed is False
        assert db_session.get(KeyMetadata, "key-v1-active").state == "ACTIVE"
        assert db_session.get(KeyMetadata, "key-v2-crash").state == "REVOKED"
        assert db_session.get(Resource, "res-alex-brief").key_version == 1
        # Still cleanly decryptable under v1
        pt, _, _ = decrypt_resource_content(db_session, keystore, ctx=ctx, resource_id="res-alex-brief")
        assert pt == secret_text
    elif crash_point in ("AFTER_COMMIT", "DURING_RETIRE"):
        assert outcome.final_status == "RECOVERED_POST_COMMIT"
        assert op.committed is True
        assert db_session.get(KeyMetadata, "key-v1-active").state == "RETIRED"
        assert db_session.get(KeyMetadata, "key-v2-crash").state == "ACTIVE"
        assert db_session.get(Resource, "res-alex-brief").key_version == 2
        for node in db_session.scalars(select(NodeRegistry)).all():
            assert node.accepted_key_version == 2
            assert node.cutoff_epoch == 2
        pt, _, _ = decrypt_resource_content(db_session, keystore, ctx=ctx, resource_id="res-alex-brief")
        assert pt == secret_text
    elif crash_point == "AFTER_REVOCATION_TOMBSTONE":
        # Tombstone precedence: target key MUST remain REVOKED and NEVER be reactivated
        assert outcome.final_status == "FAILED_CLOSED"
        assert db_session.get(KeyMetadata, "key-v2-crash").state == "REVOKED"
        tomb = db_session.scalar(
            select(RevocationTombstone).where(
                RevocationTombstone.target_type == "key",
                RevocationTombstone.target_id == "key-v2-crash",
            )
        )
        assert tomb is not None
        with pytest.raises(CryptoVaultError):
            decrypt_resource_content(db_session, keystore, ctx=ctx, resource_id="res-alex-brief")

    # Idempotency check: second and third recovery runs must be strict no-ops
    second = recover_rotations(db_session, keystore, operation_id=op_id)
    third = recover_rotations(db_session, keystore, operation_id=op_id)
    assert second[0].idempotent_noop is True
    assert third[0].idempotent_noop is True
    assert second[0].final_status == outcome.final_status


def test_journal_corruption_and_demo_mode_crash_guard(
    client: TestClient,
    db_session: Session,
    keystore: LocalEncryptedKeyStore,
    backup_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secops_tok = DEMO_SYNTHETIC_TOKENS["sess-secops-valid"]

    # 1. Crash injection rejected when demo_mode=False
    monkeypatch.setattr(settings, "demo_mode", False)
    denied = client.post(
        "/api/v1/keys/rotate",
        json={"purpose": "vault_kek", "reason": "Prod crash forbidden", "crash_at": "AFTER_PREPARE"},
        headers=_auth(secops_tok),
    )
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "CRASH_INJECTION_DISABLED"
    monkeypatch.setattr(settings, "demo_mode", True)

    # 2. Tamper journal row without updating journal_hash -> recovery fails closed
    with pytest.raises(SimulatedCrashError) as exc_info:
        execute_rotation(
            db_session,
            keystore,
            purpose="vault_kek",
            actor_id="user-secops",
            reason="Journal tamper test",
            crash_at="BEFORE_COMMIT",
            backup_dir=backup_dir,
        )
    op_id = exc_info.value.operation_id
    db_session.execute(
        text("UPDATE rotation_operations SET to_version = 999 WHERE operation_id = :id"),
        {"id": op_id},
    )
    db_session.commit()
    db_session.expire_all()

    res = recover_rotations(db_session, keystore, operation_id=op_id)
    assert res[0].final_status == "FAILED_CLOSED"
    assert res[0].action_taken == "HALTED_JOURNAL_CORRUPTION"


def test_real_subprocess_crash_and_cross_process_recovery(tmp_path: Path) -> None:
    """Real OS process termination (os._exit) mid-rotation followed by fresh-process SQLite recovery."""
    db_path = tmp_path / "proc_crash.sqlite3"
    ks_dir = tmp_path / "keystore"
    bk_dir = tmp_path / "backups"
    repo_root = Path(__file__).resolve().parents[2]
    db_url = f"sqlite:///{db_path.as_posix()}"

    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo_root)
    env["QSHIELD_DEMO_MODE"] = "true"
    env["QSHIELD_KEYSTORE_DIR"] = str(ks_dir)
    env["QSHIELD_BACKUP_DIR"] = str(bk_dir)

    phase1_script = f"""
import os
from pathlib import Path
from alembic import command
from alembic.config import Config
from backend.app.auth.dependencies import AuthContext
from backend.app.crypto.keystore import LocalEncryptedKeyStore
from backend.app.db.models import Device, User, UserSession
from backend.app.db.session import create_db_engine, create_session_factory
from backend.app.keys.rotation import SimulatedCrashError, execute_rotation
from backend.app.services.seed import seed_database
from backend.app.vault.crypto_vault import encrypt_resource_content

cfg = Config(r"{(repo_root / 'backend' / 'alembic.ini')}")
cfg.set_main_option("script_location", r"{(repo_root / 'backend' / 'alembic')}")
cfg.set_main_option("sqlalchemy.url", "{db_url}")
command.upgrade(cfg, "head")

engine = create_db_engine("{db_url}", busy_timeout_ms=5000, wal_mode=True)
ks = LocalEncryptedKeyStore(Path(r"{ks_dir}"))
bk = Path(r"{bk_dir}")
with create_session_factory(engine)() as db:
    seed_database(db, reset=True, keystore=ks, backup_dir=bk)
    ctx = AuthContext(user=db.get(User, "user-alex"), session=db.get(UserSession, "sess-alex-valid"), device=db.get(Device, "dev-alex-trusted"), correlation_id="subproc-1")
    encrypt_resource_content(db, ks, ctx=ctx, resource_id="res-alex-brief", plaintext="Survives hard OS exit")
    try:
        execute_rotation(db, ks, purpose="vault_kek", actor_id="user-secops", new_key_id="key-v2-subproc", reason="Subprocess crash", crash_at="AFTER_COMMIT", backup_dir=bk)
    except SimulatedCrashError:
        engine.dispose()
        os._exit(42)
"""
    p1 = subprocess.run([sys.executable, "-c", phase1_script], env=env, cwd=str(repo_root), capture_output=True, text=True)
    assert p1.returncode == 42, f"Expected hard exit 42, got {p1.returncode}: {p1.stderr}"

    # Process 2: Brand-new Python interpreter opens SQLite DB from disk and recovers cleanly
    phase2_script = f"""
from pathlib import Path
from backend.app.auth.dependencies import AuthContext
from backend.app.crypto.keystore import LocalEncryptedKeyStore
from backend.app.db.models import Device, KeyMetadata, User, UserSession
from backend.app.db.session import create_db_engine, create_session_factory
from backend.app.recovery.manager import recover_rotations
from backend.app.vault.crypto_vault import decrypt_resource_content

engine = create_db_engine("{db_url}", busy_timeout_ms=5000, wal_mode=True)
ks = LocalEncryptedKeyStore(Path(r"{ks_dir}"))
with create_session_factory(engine)() as db:
    outcomes = recover_rotations(db, ks)
    assert len(outcomes) == 1
    assert outcomes[0].final_status == "RECOVERED_POST_COMMIT"
    assert db.get(KeyMetadata, "key-v2-subproc").state == "ACTIVE"
    ctx = AuthContext(user=db.get(User, "user-alex"), session=db.get(UserSession, "sess-alex-valid"), device=db.get(Device, "dev-alex-trusted"), correlation_id="subproc-2")
    pt, _, _ = decrypt_resource_content(db, ks, ctx=ctx, resource_id="res-alex-brief")
    assert pt == "Survives hard OS exit"
print("SUBPROC_RECOVERY_OK")
"""
    p2 = subprocess.run([sys.executable, "-c", phase2_script], env=env, cwd=str(repo_root), capture_output=True, text=True)
    assert p2.returncode == 0, f"Recovery subprocess failed: {p2.stderr}"
    assert "SUBPROC_RECOVERY_OK" in p2.stdout
