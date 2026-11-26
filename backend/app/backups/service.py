"""Authenticated & encrypted backup manager (AES-256-GCM payload + ML-DSA-65 signed manifest).

Never writes plaintext private keys into backup archives or logs.
Rejects tampered bytes, invalid AEAD tags, invalid ML-DSA-65 signatures,
wrong backup secrets, unsupported versions, incomplete manifests, and stale
backups that would undo newer revocation tombstones.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from datetime import datetime
import json
import os
from pathlib import Path
import secrets
import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.audit.ledger import append_audit_event, audit_write_lock
from backend.app.config import settings
from backend.app.crypto.aead import AEADError, AES256GCMProvider
from backend.app.crypto.hmac_hash import sha256_hex
from backend.app.crypto.kdf import derive_key_hkdf_sha256
from backend.app.crypto.keystore import KeyStoreError, LocalEncryptedKeyStore
from backend.app.crypto.mldsa import MLDSA65Provider
from backend.app.db.models import (
    BackupManifest,
    KeyMetadata,
    RevocationEvent,
    RevocationTombstone,
    SettingEntry,
    utc_now,
)

BACKUP_SCHEMA_VERSION = "qshield.backup.v1"
BACKUP_SEED_FILENAME = "qshield_backup_master.seed"


class BackupError(Exception):
    """Sanitized backup error; never exposes keys or secret material."""

    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


@dataclass(frozen=True)
class BackupVerificationResult:
    backup_id: str
    valid: bool
    status: str
    reason: str
    manifest_sha256: str
    max_revocation_epoch: int
    active_epoch: int


def _restrict_permissions(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _resolve_backup_key(
    keystore: LocalEncryptedKeyStore,
    *,
    backup_secret_override: str | None = None,
    create_seed_if_missing: bool = False,
) -> bytes:
    secret_str = backup_secret_override if backup_secret_override is not None else settings.backup_secret
    if secret_str:
        ikm = secret_str.encode("utf-8")
        salt = b"qshield-backup-env-salt-v1"
    else:
        seed_path = keystore.keystore_dir / BACKUP_SEED_FILENAME
        if not seed_path.exists():
            if not create_seed_if_missing:
                raise BackupError(409, "BACKUP_KEY_MISSING", "Backup master key seed is missing.")
            keystore.keystore_dir.mkdir(parents=True, exist_ok=True)
            seed_path.write_bytes(secrets.token_bytes(32))
            _restrict_permissions(seed_path)
        ikm = seed_path.read_bytes()
        if len(ikm) != 32:
            raise BackupError(409, "BACKUP_KEY_CORRUPT", "Backup master key seed is corrupt.")
        salt = b"qshield-backup-local-seed-salt-v1"

    return derive_key_hkdf_sha256(
        ikm,
        salt=salt,
        purpose="vault_kek",
        context={"domain": "qshield-backup-v1"},
        length=32,
    )


def _backup_aad_bytes(
    *,
    backup_id: str,
    schema_version: str,
    created_at_iso: str,
    active_epoch: int,
    max_revocation_epoch: int,
) -> bytes:
    return json.dumps(
        {
            "backup_id": backup_id,
            "schema_version": schema_version,
            "created_at": created_at_iso,
            "active_epoch": active_epoch,
            "max_revocation_epoch": max_revocation_epoch,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _canonical_manifest_hash(envelope: dict) -> str:
    body = {k: v for k, v in envelope.items() if k not in ("manifest_sha256", "signature_b64")}
    return sha256_hex(json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def get_backup_dir() -> Path:
    """FastAPI dependency returning active backup directory."""
    return Path(settings.backup_dir)


def create_backup(
    db: Session,
    keystore: LocalEncryptedKeyStore,
    *,
    actor_id: str,
    backup_dir: Path | None = None,
    backup_secret_override: str | None = None,
    version_tag: int | None = None,
) -> BackupManifest:
    """Create an AES-256-GCM encrypted + ML-DSA-65 signed backup archive."""
    target_dir = backup_dir if backup_dir is not None else get_backup_dir()
    target_dir.mkdir(parents=True, exist_ok=True)

    now = utc_now()
    created_at_iso = now.isoformat()
    backup_id = f"bkp-{uuid.uuid4().hex[:16]}"

    keys = list(db.scalars(select(KeyMetadata).order_by(KeyMetadata.version.asc(), KeyMetadata.key_id.asc())).all())
    tombstones = list(
        db.scalars(select(RevocationTombstone).order_by(RevocationTombstone.id.asc())).all()
    )
    active_epoch = int(db.scalar(select(func.coalesce(func.max(RevocationEvent.sequence_number), 0))) or 0)
    max_rev_epoch = max([t.revocation_epoch for t in tombstones], default=0)
    max_key_ver = max([k.version for k in keys if k.version < 100], default=1)
    chosen_version = version_tag if version_tag is not None else max_key_ver

    try:
        keystore_entries = keystore.export_snapshot()
        signer_sk = keystore.get_secret_bytes("key-revocation-signer-v1", expected_purpose="signing")
    except KeyStoreError as exc:
        raise BackupError(503, "KEYSTORE_UNAVAILABLE", "Cannot access keystore to build backup.") from exc

    key_meta_list = [
        {
            "key_id": k.key_id,
            "purpose": k.purpose,
            "algorithm": k.algorithm,
            "version": k.version,
            "state": k.state,
            "created_at": k.created_at.isoformat(),
            "activated_at": k.activated_at.isoformat() if k.activated_at else None,
            "revoked_at": k.revoked_at.isoformat() if k.revoked_at else None,
        }
        for k in keys
    ]
    tombstone_list = [
        {
            "target_type": t.target_type,
            "target_id": t.target_id,
            "revocation_epoch": t.revocation_epoch,
            "reason": t.reason,
        }
        for t in tombstones
    ]

    secret_payload = json.dumps(
        {
            "key_metadata": key_meta_list,
            "tombstones": tombstone_list,
            "keystore_entries": keystore_entries,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

    backup_key = _resolve_backup_key(
        keystore, backup_secret_override=backup_secret_override, create_seed_if_missing=True
    )
    aad = _backup_aad_bytes(
        backup_id=backup_id,
        schema_version=BACKUP_SCHEMA_VERSION,
        created_at_iso=created_at_iso,
        active_epoch=active_epoch,
        max_revocation_epoch=max_rev_epoch,
    )
    aead = AES256GCMProvider()
    nonce, ciphertext = aead.encrypt(backup_key, secret_payload, aad)

    payload_nonce_b64 = base64.b64encode(nonce).decode("ascii")
    payload_ct_b64 = base64.b64encode(ciphertext).decode("ascii")
    payload_sha256 = sha256_hex(ciphertext)

    envelope: dict[str, object] = {
        "backup_id": backup_id,
        "schema_version": BACKUP_SCHEMA_VERSION,
        "created_at": created_at_iso,
        "created_by": actor_id,
        "active_epoch": active_epoch,
        "max_revocation_epoch": max_rev_epoch,
        "tombstone_count": len(tombstones),
        "key_ids_versions": [
            {"key_id": k.key_id, "purpose": k.purpose, "version": k.version, "state": k.state}
            for k in keys
        ],
        "payload_nonce_b64": payload_nonce_b64,
        "payload_ciphertext_b64": payload_ct_b64,
        "payload_sha256": payload_sha256,
    }
    manifest_sha256 = _canonical_manifest_hash(envelope)
    sig_bytes = MLDSA65Provider.sign(signer_sk, manifest_sha256.encode("utf-8"))
    signature_b64 = base64.b64encode(sig_bytes).decode("ascii")
    envelope["manifest_sha256"] = manifest_sha256
    envelope["signature_b64"] = signature_b64

    backup_file = target_dir / f"{backup_id}.qsbak.json"
    tmp_file = backup_file.with_suffix(".tmp")
    tmp_file.write_text(json.dumps(envelope, separators=(",", ":"), sort_keys=True), encoding="utf-8")
    try:
        fd = os.open(tmp_file, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass
    os.replace(tmp_file, backup_file)
    _restrict_permissions(backup_file)

    manifest_row = BackupManifest(
        backup_id=backup_id,
        schema_version=BACKUP_SCHEMA_VERSION,
        version=chosen_version,
        active_epoch=active_epoch,
        max_revocation_epoch=max_rev_epoch,
        tombstone_count=len(tombstones),
        backup_path=str(backup_file),
        integrity_auth_data=json.dumps({"payload_sha256": payload_sha256, "key_count": len(keys)}),
        manifest_sha256=manifest_sha256,
        signature_b64=signature_b64,
        verified_status="VERIFIED",
        created_by=actor_id,
        created_at=now,
    )
    with audit_write_lock():
        db.add(manifest_row)
        append_audit_event(
            db,
            event_type="BACKUP_CREATED",
            event_category="BACKUP",
            actor_id=actor_id,
            action="create_backup",
            target_type="backup",
            target_id=backup_id,
            outcome="ALLOW",
            reason_code="BACKUP_CREATED_VERIFIED",
            correlation_id=f"corr-bkp-{backup_id}",
            source_component="backup_manager",
            payload={
                "version": chosen_version,
                "active_epoch": active_epoch,
                "max_revocation_epoch": max_rev_epoch,
                "tombstone_count": len(tombstones),
                "manifest_sha256": manifest_sha256,
            },
            commit=False,
        )
        db.commit()
    db.refresh(manifest_row)
    return manifest_row


def _load_and_verify_backup_file(
    db: Session,
    keystore: LocalEncryptedKeyStore,
    manifest_row: BackupManifest,
    *,
    backup_secret_override: str | None = None,
) -> tuple[BackupVerificationResult, dict | None]:
    path = Path(manifest_row.backup_path)
    if not path.is_file():
        return (
            BackupVerificationResult(
                backup_id=manifest_row.backup_id,
                valid=False,
                status="MISSING_FILE",
                reason="Backup archive file does not exist.",
                manifest_sha256=manifest_row.manifest_sha256,
                max_revocation_epoch=manifest_row.max_revocation_epoch,
                active_epoch=manifest_row.active_epoch,
            ),
            None,
        )

    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return (
            BackupVerificationResult(
                backup_id=manifest_row.backup_id,
                valid=False,
                status="CORRUPT_JSON",
                reason="Backup archive is not valid JSON.",
                manifest_sha256=manifest_row.manifest_sha256,
                max_revocation_epoch=manifest_row.max_revocation_epoch,
                active_epoch=manifest_row.active_epoch,
            ),
            None,
        )

    required_fields = {
        "backup_id",
        "schema_version",
        "created_at",
        "active_epoch",
        "max_revocation_epoch",
        "key_ids_versions",
        "payload_nonce_b64",
        "payload_ciphertext_b64",
        "payload_sha256",
        "manifest_sha256",
        "signature_b64",
    }
    if not isinstance(envelope, dict) or not required_fields.issubset(envelope.keys()):
        return (
            BackupVerificationResult(
                backup_id=manifest_row.backup_id,
                valid=False,
                status="INCOMPLETE_BACKUP",
                reason="Backup manifest is missing required fields.",
                manifest_sha256=manifest_row.manifest_sha256,
                max_revocation_epoch=manifest_row.max_revocation_epoch,
                active_epoch=manifest_row.active_epoch,
            ),
            None,
        )

    if envelope.get("schema_version") != BACKUP_SCHEMA_VERSION:
        return (
            BackupVerificationResult(
                backup_id=manifest_row.backup_id,
                valid=False,
                status="UNSUPPORTED_VERSION",
                reason=f"Unsupported backup schema_version: {envelope.get('schema_version')}",
                manifest_sha256=manifest_row.manifest_sha256,
                max_revocation_epoch=manifest_row.max_revocation_epoch,
                active_epoch=manifest_row.active_epoch,
            ),
            None,
        )

    computed_manifest_sha = _canonical_manifest_hash(envelope)
    if computed_manifest_sha != envelope.get("manifest_sha256") or computed_manifest_sha != manifest_row.manifest_sha256:
        return (
            BackupVerificationResult(
                backup_id=manifest_row.backup_id,
                valid=False,
                status="TAMPERED_MANIFEST",
                reason="Backup manifest SHA-256 checksum mismatch.",
                manifest_sha256=computed_manifest_sha,
                max_revocation_epoch=manifest_row.max_revocation_epoch,
                active_epoch=manifest_row.active_epoch,
            ),
            None,
        )

    pk_entry = db.get(SettingEntry, "revocation_signer_public_key_b64")
    if pk_entry is None:
        return (
            BackupVerificationResult(
                backup_id=manifest_row.backup_id,
                valid=False,
                status="MISSING_SIGNER_KEY",
                reason="Control-plane public verification key unavailable.",
                manifest_sha256=computed_manifest_sha,
                max_revocation_epoch=manifest_row.max_revocation_epoch,
                active_epoch=manifest_row.active_epoch,
            ),
            None,
        )

    try:
        pk_bytes = base64.b64decode(pk_entry.value, validate=True)
        sig_bytes = base64.b64decode(str(envelope["signature_b64"]), validate=True)
        if not MLDSA65Provider.verify(pk_bytes, computed_manifest_sha.encode("utf-8"), sig_bytes):
            return (
                BackupVerificationResult(
                    backup_id=manifest_row.backup_id,
                    valid=False,
                    status="INVALID_SIGNATURE",
                    reason="ML-DSA-65 manifest signature verification failed.",
                    manifest_sha256=computed_manifest_sha,
                    max_revocation_epoch=manifest_row.max_revocation_epoch,
                    active_epoch=manifest_row.active_epoch,
                ),
                None,
            )

        nonce = base64.b64decode(str(envelope["payload_nonce_b64"]), validate=True)
        ciphertext = base64.b64decode(str(envelope["payload_ciphertext_b64"]), validate=True)
    except (binascii.Error, ValueError):
        return (
            BackupVerificationResult(
                backup_id=manifest_row.backup_id,
                valid=False,
                status="MALFORMED_ENCODING",
                reason="Backup cryptographic encoding is malformed.",
                manifest_sha256=computed_manifest_sha,
                max_revocation_epoch=manifest_row.max_revocation_epoch,
                active_epoch=manifest_row.active_epoch,
            ),
            None,
        )

    if sha256_hex(ciphertext) != envelope.get("payload_sha256"):
        return (
            BackupVerificationResult(
                backup_id=manifest_row.backup_id,
                valid=False,
                status="TAMPERED_PAYLOAD",
                reason="Encrypted backup payload checksum mismatch.",
                manifest_sha256=computed_manifest_sha,
                max_revocation_epoch=manifest_row.max_revocation_epoch,
                active_epoch=manifest_row.active_epoch,
            ),
            None,
        )

    try:
        backup_key = _resolve_backup_key(
            keystore, backup_secret_override=backup_secret_override, create_seed_if_missing=False
        )
        aad = _backup_aad_bytes(
            backup_id=str(envelope["backup_id"]),
            schema_version=str(envelope["schema_version"]),
            created_at_iso=str(envelope["created_at"]),
            active_epoch=int(envelope["active_epoch"]),
            max_revocation_epoch=int(envelope["max_revocation_epoch"]),
        )
        pt = AES256GCMProvider().decrypt(backup_key, nonce, ciphertext, aad)
        decrypted_payload = json.loads(pt.decode("utf-8"))
    except (AEADError, BackupError, ValueError, UnicodeDecodeError):
        return (
            BackupVerificationResult(
                backup_id=manifest_row.backup_id,
                valid=False,
                status="DECRYPT_AUTH_FAILED",
                reason="Backup AEAD tag authentication or backup secret failed.",
                manifest_sha256=computed_manifest_sha,
                max_revocation_epoch=manifest_row.max_revocation_epoch,
                active_epoch=manifest_row.active_epoch,
            ),
            None,
        )

    if not isinstance(decrypted_payload, dict) or not {"key_metadata", "tombstones", "keystore_entries"}.issubset(
        decrypted_payload.keys()
    ):
        return (
            BackupVerificationResult(
                backup_id=manifest_row.backup_id,
                valid=False,
                status="INCOMPLETE_PAYLOAD",
                reason="Decrypted backup payload is incomplete.",
                manifest_sha256=computed_manifest_sha,
                max_revocation_epoch=manifest_row.max_revocation_epoch,
                active_epoch=manifest_row.active_epoch,
            ),
            None,
        )

    # Anti-rollback check: stale backup MUST NOT overwrite newer revocations or reactivate revoked/compromised keys.
    current_max_tombstone = int(
        db.scalar(select(func.coalesce(func.max(RevocationTombstone.revocation_epoch), 0))) or 0
    )
    current_max_event = int(
        db.scalar(select(func.coalesce(func.max(RevocationEvent.sequence_number), 0))) or 0
    )
    bk_rev_epoch = int(envelope["max_revocation_epoch"])
    bk_active_epoch = int(envelope["active_epoch"])
    if bk_rev_epoch < current_max_tombstone or bk_active_epoch < current_max_event:
        return (
            BackupVerificationResult(
                backup_id=manifest_row.backup_id,
                valid=False,
                status="STALE_ANTI_ROLLBACK",
                reason=(
                    f"Backup epochs (active={bk_active_epoch}, tombstone={bk_rev_epoch}) are older than live "
                    f"revocation state (events={current_max_event}, tombstones={current_max_tombstone})."
                ),
                manifest_sha256=computed_manifest_sha,
                max_revocation_epoch=bk_rev_epoch,
                active_epoch=bk_active_epoch,
            ),
            None,
        )

    revoked_key_ids = set(
        db.scalars(
            select(KeyMetadata.key_id).where(KeyMetadata.state.in_(("REVOKED", "COMPROMISED")))
        ).all()
    )
    tombstoned_key_ids = set(
        db.scalars(
            select(RevocationTombstone.target_id).where(RevocationTombstone.target_type == "key")
        ).all()
    )
    protected_revoked = revoked_key_ids | tombstoned_key_ids
    for item in decrypted_payload["key_metadata"]:
        kid = str(item["key_id"])
        if kid in protected_revoked and item.get("state") not in ("REVOKED", "COMPROMISED"):
            return (
                BackupVerificationResult(
                    backup_id=manifest_row.backup_id,
                    valid=False,
                    status="STALE_ANTI_ROLLBACK",
                    reason=f"Backup would restore revoked/compromised key '{kid}' to '{item.get('state')}'.",
                    manifest_sha256=computed_manifest_sha,
                    max_revocation_epoch=bk_rev_epoch,
                    active_epoch=bk_active_epoch,
                ),
                None,
            )

    return (
        BackupVerificationResult(
            backup_id=manifest_row.backup_id,
            valid=True,
            status="VERIFIED",
            reason="Manifest signature, checksums, anti-rollback checks, and AES-256-GCM payload verified.",
            manifest_sha256=computed_manifest_sha,
            max_revocation_epoch=bk_rev_epoch,
            active_epoch=bk_active_epoch,
        ),
        decrypted_payload,
    )


def verify_backup(
    db: Session,
    keystore: LocalEncryptedKeyStore,
    backup_id: str,
    *,
    backup_secret_override: str | None = None,
    actor_id: str = "system",
) -> BackupVerificationResult:
    """Verify backup integrity, ML-DSA-65 manifest signature, and AEAD decryption."""
    manifest_row = db.get(BackupManifest, backup_id)
    if manifest_row is None:
        raise BackupError(404, "BACKUP_NOT_FOUND", f"Backup '{backup_id}' does not exist.")

    res, _payload = _load_and_verify_backup_file(
        db, keystore, manifest_row, backup_secret_override=backup_secret_override
    )
    with audit_write_lock():
        manifest_row.verified_status = res.status
        append_audit_event(
            db,
            event_type="BACKUP_VERIFIED",
            event_category="BACKUP",
            actor_id=actor_id,
            action="verify_backup",
            target_type="backup",
            target_id=backup_id,
            outcome="ALLOW" if res.valid else "DENY",
            reason_code=f"BACKUP_{res.status}",
            correlation_id=f"corr-bkp-ver-{backup_id}",
            source_component="backup_manager",
            payload={"valid": res.valid, "status": res.status, "max_revocation_epoch": res.max_revocation_epoch},
            commit=False,
        )
        db.commit()
    return res


def restore_backup(
    db: Session,
    keystore: LocalEncryptedKeyStore,
    backup_id: str,
    *,
    confirmation: bool,
    backup_secret_override: str | None = None,
    actor_id: str = "system",
) -> tuple[BackupVerificationResult, int]:
    """Restore verified backup idempotently; reject tampered or stale backups that undo revocations."""
    if not confirmation:
        raise BackupError(400, "CONFIRMATION_REQUIRED", "Explicit confirmation is required to restore backup.")

    manifest_row = db.get(BackupManifest, backup_id)
    if manifest_row is None:
        raise BackupError(404, "BACKUP_NOT_FOUND", f"Backup '{backup_id}' does not exist.")

    res, payload = _load_and_verify_backup_file(
        db, keystore, manifest_row, backup_secret_override=backup_secret_override
    )
    if not res.valid or payload is None:
        with audit_write_lock():
            manifest_row.verified_status = res.status
            append_audit_event(
                db,
                event_type="BACKUP_RESTORE_REJECTED",
                event_category="BACKUP",
                actor_id=actor_id,
                action="restore_backup",
                target_type="backup",
                target_id=backup_id,
                outcome="DENY",
                reason_code=f"BACKUP_{res.status}",
                correlation_id=f"corr-bkp-rest-{backup_id}",
                source_component="backup_manager",
                payload={"status": res.status},
                commit=False,
            )
            db.commit()
        raise BackupError(409, f"BACKUP_{res.status}", res.reason)

    # Anti-rollback check: stale backup MUST NOT overwrite newer revocations or reactivate revoked/compromised keys.
    current_max_tombstone = int(
        db.scalar(select(func.coalesce(func.max(RevocationTombstone.revocation_epoch), 0))) or 0
    )
    if res.max_revocation_epoch < current_max_tombstone:
        raise BackupError(
            409,
            "STALE_BACKUP_REVOCATION_CONFLICT",
            f"Backup revocation epoch {res.max_revocation_epoch} is older than current tombstones ({current_max_tombstone}).",
        )

    revoked_key_ids = set(
        db.scalars(
            select(KeyMetadata.key_id).where(KeyMetadata.state.in_(("REVOKED", "COMPROMISED")))
        ).all()
    )
    tombstoned_key_ids = set(
        db.scalars(
            select(RevocationTombstone.target_id).where(RevocationTombstone.target_type == "key")
        ).all()
    )
    protected_revoked = revoked_key_ids | tombstoned_key_ids

    for item in payload["key_metadata"]:
        kid = str(item["key_id"])
        if kid in protected_revoked and item.get("state") not in ("REVOKED", "COMPROMISED"):
            raise BackupError(
                409,
                "STALE_BACKUP_KEY_REACTIVATION_BLOCKED",
                f"Backup would restore revoked/compromised key '{kid}' to '{item.get('state')}'.",
            )

    # Apply idempotent restore: preserve any newer tombstones/revoked keys and restore missing/valid keys
    keystore.import_snapshot(payload["keystore_entries"], preserve_keys=protected_revoked)

    restored_count = 0
    for item in payload["key_metadata"]:
        kid = str(item["key_id"])
        existing = db.get(KeyMetadata, kid)
        if existing is None:
            db.add(
                KeyMetadata(
                    key_id=kid,
                    purpose=str(item["purpose"]),
                    algorithm=str(item["algorithm"]),
                    version=int(item["version"]),
                    state=str(item["state"]),
                    created_at=datetime.fromisoformat(item["created_at"]),
                    activated_at=datetime.fromisoformat(item["activated_at"]) if item.get("activated_at") else None,
                    revoked_at=datetime.fromisoformat(item["revoked_at"]) if item.get("revoked_at") else None,
                )
            )
            restored_count += 1
        else:
            if existing.state not in ("REVOKED", "COMPROMISED") and existing.state != item["state"]:
                existing.state = str(item["state"])
                restored_count += 1

    with audit_write_lock():
        manifest_row.verified_status = "VERIFIED"
        append_audit_event(
            db,
            event_type="BACKUP_RESTORED",
            event_category="BACKUP",
            actor_id=actor_id,
            action="restore_backup",
            target_type="backup",
            target_id=backup_id,
            outcome="ALLOW",
            reason_code="BACKUP_RESTORE_COMPLETED",
            correlation_id=f"corr-bkp-rest-{backup_id}",
            source_component="backup_manager",
            payload={"restored_keys_count": restored_count, "max_revocation_epoch": res.max_revocation_epoch},
            commit=False,
        )
        db.commit()
    return res, restored_count


def list_backups(db: Session) -> list[BackupManifest]:
    return list(db.scalars(select(BackupManifest).order_by(BackupManifest.created_at.desc())).all())
