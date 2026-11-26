"""Independent tests for Phase 5 Backup Encryption, Signing, Verification & Anti-Rollback Restoration."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient
import pytest
from sqlalchemy.orm import Session

from backend.app.backups.service import (
    BackupError,
    create_backup,
    restore_backup,
    verify_backup,
)
from backend.app.crypto.keystore import LocalEncryptedKeyStore
from backend.app.db.models import BackupManifest, KeyMetadata, User
from backend.app.keys.service import generate_managed_key
from backend.app.revocation.coordinator import issue_revocation_event
from backend.app.services.seed import DEMO_SYNTHETIC_TOKENS


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_backup_create_verify_restore_and_rbac_no_secret_leak(
    client: TestClient,
    db_session: Session,
    keystore: LocalEncryptedKeyStore,
    backup_dir: Path,
) -> None:
    alex_tok = DEMO_SYNTHETIC_TOKENS["sess-alex-valid"]
    secops_tok = DEMO_SYNTHETIC_TOKENS["sess-secops-valid"]
    auditor_tok = DEMO_SYNTHETIC_TOKENS["sess-auditor-valid"]

    # RBAC: owner denied; auditor can list/verify but cannot create/restore
    assert client.get("/api/v1/keys/backups", headers=_auth(alex_tok)).status_code == 403
    assert client.post("/api/v1/keys/backups/create", json={"reason": "Denied"}, headers=_auth(alex_tok)).status_code == 403
    assert client.post("/api/v1/keys/backups/create", json={"reason": "Auditor denied"}, headers=_auth(auditor_tok)).status_code == 403

    # Create authenticated + encrypted backup as security operator
    created = client.post(
        "/api/v1/keys/backups/create",
        json={"reason": "Pre-rotation snapshot"},
        headers=_auth(secops_tok),
    )
    assert created.status_code == 201
    bk = created.json()
    backup_id = bk["backup_id"]
    assert bk["verified"] is True
    assert bk["verification_status"] == "VERIFIED"
    backup_path = Path(bk["backup_path"])
    assert backup_path.exists()

    # Ensure raw keystore secrets / plaintext private keys NEVER appear in backup archive or API response
    raw_file_text = backup_path.read_text(encoding="utf-8")
    raw_kek = keystore.get_secret_bytes("key-v1-active", expected_purpose="vault_kek").hex()
    assert raw_kek not in raw_file_text
    assert "private_key" not in raw_file_text.lower()
    assert "secret" not in json.dumps(bk).lower()

    # Auditor CAN list & verify backups
    assert any(b["backup_id"] == backup_id for b in client.get("/api/v1/keys/backups", headers=_auth(auditor_tok)).json())
    ver = client.post(f"/api/v1/keys/backups/{backup_id}/verify", headers=_auth(auditor_tok))
    assert ver.status_code == 200 and ver.json()["valid"] is True

    # Auditor cannot restore
    assert (
        client.post(
            f"/api/v1/keys/backups/{backup_id}/restore",
            json={"confirmation": True},
            headers=_auth(auditor_tok),
        ).status_code
        == 403
    )

    # Restore without explicit confirmation fails cleanly
    no_conf = client.post(
        f"/api/v1/keys/backups/{backup_id}/restore",
        json={"confirmation": False},
        headers=_auth(secops_tok),
    )
    assert no_conf.status_code == 400

    # Valid restore succeeds idempotently twice in a row (and recovers a removed non-revoked key)
    from sqlalchemy import delete as sa_delete

    gen = client.post(
        "/api/v1/keys/generate",
        json={"key_id": "key-ephemeral-bk-test", "purpose": "kem", "version": 7, "activate_immediately": False, "reason": "Ephemeral restore verification key"},
        headers=_auth(secops_tok),
    )
    assert gen.status_code == 201
    bkp_with_extra = client.post(
        "/api/v1/keys/backups/create",
        json={"reason": "Snapshot before deletion"},
        headers=_auth(secops_tok),
    ).json()["backup_id"]
    db_session.execute(sa_delete(KeyMetadata).where(KeyMetadata.key_id == "key-ephemeral-bk-test"))
    db_session.commit()

    rest1 = client.post(
        f"/api/v1/keys/backups/{bkp_with_extra}/restore",
        json={"confirmation": True},
        headers=_auth(secops_tok),
    )
    assert rest1.status_code == 200 and rest1.json()["restored_keys_count"] >= 1
    db_session.expire_all()
    assert db_session.get(KeyMetadata, "key-ephemeral-bk-test") is not None

    rest2 = client.post(
        f"/api/v1/keys/backups/{bkp_with_extra}/restore",
        json={"confirmation": True},
        headers=_auth(secops_tok),
    )
    assert rest2.status_code == 200 and rest2.json()["restored_keys_count"] == 0


def test_backup_tamper_wrong_secret_missing_unsupported_and_incomplete_fail_closed(
    db_session: Session,
    keystore: LocalEncryptedKeyStore,
    backup_dir: Path,
) -> None:
    manifest = create_backup(
        db_session,
        keystore,
        actor_id="user-secops",
        backup_dir=backup_dir,
        backup_secret_override="correct-backup-secret-1",
    )
    backup_file = Path(manifest.backup_path)
    original_raw = backup_file.read_text(encoding="utf-8")

    # 1. Wrong backup secret -> AEAD decryption fails closed
    vr_secret = verify_backup(db_session, keystore, manifest.backup_id, backup_secret_override="wrong-backup-secret")
    assert vr_secret.valid is False and vr_secret.status == "DECRYPT_AUTH_FAILED"
    with pytest.raises(BackupError) as exc_secret:
        restore_backup(db_session, keystore, manifest.backup_id, confirmation=True, backup_secret_override="wrong-backup-secret")
    assert exc_secret.value.code == "BACKUP_DECRYPT_AUTH_FAILED"

    # 2. Tampered ciphertext -> payload digest & AEAD fail closed
    envelope = json.loads(original_raw)
    ct_chars = list(envelope["payload_ciphertext_b64"])
    ct_chars[4] = "A" if ct_chars[4] != "A" else "B"
    envelope["payload_ciphertext_b64"] = "".join(ct_chars)
    backup_file.write_text(json.dumps(envelope), encoding="utf-8")
    vr_ct = verify_backup(db_session, keystore, manifest.backup_id, backup_secret_override="correct-backup-secret-1")
    assert vr_ct.valid is False and vr_ct.status in ("TAMPERED_PAYLOAD", "TAMPERED_MANIFEST", "DECRYPT_AUTH_FAILED")
    with pytest.raises(BackupError):
        restore_backup(db_session, keystore, manifest.backup_id, confirmation=True, backup_secret_override="correct-backup-secret-1")

    # 3. Tampered signature -> ML-DSA-65 verification fails closed
    envelope = json.loads(original_raw)
    sig_chars = list(envelope["signature_b64"])
    sig_chars[3] = "C" if sig_chars[3] != "C" else "D"
    envelope["signature_b64"] = "".join(sig_chars)
    backup_file.write_text(json.dumps(envelope), encoding="utf-8")
    vr_sig = verify_backup(db_session, keystore, manifest.backup_id, backup_secret_override="correct-backup-secret-1")
    assert vr_sig.valid is False and vr_sig.status == "INVALID_SIGNATURE"
    with pytest.raises(BackupError) as exc_sig:
        restore_backup(db_session, keystore, manifest.backup_id, confirmation=True, backup_secret_override="correct-backup-secret-1")
    assert exc_sig.value.code == "BACKUP_INVALID_SIGNATURE"

    # 4. Unsupported schema version -> fails closed
    envelope = json.loads(original_raw)
    envelope["schema_version"] = "qshield.backup.v999"
    backup_file.write_text(json.dumps(envelope), encoding="utf-8")
    vr_ver = verify_backup(db_session, keystore, manifest.backup_id, backup_secret_override="correct-backup-secret-1")
    assert vr_ver.valid is False and vr_ver.status == "UNSUPPORTED_VERSION"
    with pytest.raises(BackupError) as exc_ver:
        restore_backup(db_session, keystore, manifest.backup_id, confirmation=True, backup_secret_override="correct-backup-secret-1")
    assert exc_ver.value.code == "BACKUP_UNSUPPORTED_VERSION"

    # 5. Incomplete / corrupt manifest fields -> fails closed
    backup_file.write_text('{"schema_version": "qshield.backup.v1"}', encoding="utf-8")
    vr_inc = verify_backup(db_session, keystore, manifest.backup_id, backup_secret_override="correct-backup-secret-1")
    assert vr_inc.valid is False and vr_inc.status == "INCOMPLETE_BACKUP"
    with pytest.raises(BackupError) as exc_inc:
        restore_backup(db_session, keystore, manifest.backup_id, confirmation=True, backup_secret_override="correct-backup-secret-1")
    assert exc_inc.value.code == "BACKUP_INCOMPLETE_BACKUP"

    # 6. Missing backup file -> fails closed
    backup_file.unlink()
    vr_miss = verify_backup(db_session, keystore, manifest.backup_id, backup_secret_override="correct-backup-secret-1")
    assert vr_miss.valid is False and vr_miss.status == "MISSING_FILE"
    with pytest.raises(BackupError) as exc_miss:
        restore_backup(db_session, keystore, manifest.backup_id, confirmation=True, backup_secret_override="correct-backup-secret-1")
    assert exc_miss.value.code == "BACKUP_MISSING_FILE"


def test_stale_backup_anti_rollback_blocks_undoing_newer_revocation_tombstones(
    db_session: Session,
    keystore: LocalEncryptedKeyStore,
    backup_dir: Path,
) -> None:
    # Generate an extra key, include it in backup at epoch 0
    generate_managed_key(
        db_session,
        keystore,
        key_id="key-backup-target",
        purpose="kem",
        version=5,
        activate_immediately=True,
    )
    stale_manifest = create_backup(db_session, keystore, actor_id="user-secops", backup_dir=backup_dir)
    assert stale_manifest.active_epoch == 0
    assert stale_manifest.max_revocation_epoch >= 1

    # Later, revoke the key (creating RevocationTombstone + RevocationEvent epoch 1)
    secops_user = db_session.get(User, "user-secops")
    issue_revocation_event(
        db_session,
        keystore,
        subject_type="key",
        subject_id="key-backup-target",
        reason="Key compromised post-backup — propagate epoch 1",
        confirmation=True,
        acting_user=secops_user,
        correlation_id="corr-antirob",
        sim_clock_ms=100,
    )

    # Verification and restoration of the stale backup MUST FAIL CLOSED with STALE_ANTI_ROLLBACK
    vr_stale = verify_backup(db_session, keystore, stale_manifest.backup_id)
    assert vr_stale.valid is False
    assert vr_stale.status == "STALE_ANTI_ROLLBACK"

    with pytest.raises(BackupError) as exc_res:
        restore_backup(db_session, keystore, stale_manifest.backup_id, confirmation=True)
    assert exc_res.value.code == "BACKUP_STALE_ANTI_ROLLBACK"

    # Verify revoked key stayed REVOKED and was NEVER reactivated
    db_session.expire_all()
    assert db_session.get(KeyMetadata, "key-backup-target").state == "REVOKED"
    refreshed = db_session.get(BackupManifest, stale_manifest.backup_id)
    assert refreshed.verified_status == "STALE_ANTI_ROLLBACK"
    assert refreshed.verified is False
