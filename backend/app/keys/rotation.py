"""Phase 5 Key Rotation State Machine (PREPARE -> DISTRIBUTE -> COMMIT -> RETIRE).

Supports:
- Strict single-active-rotation concurrency per key purpose (DB partial unique index + pre-check)
- Automatic pre-rotation encrypted/signed backup creation
- Pre-commit DEK re-wrapping & node staging without breaking pre-cutoff decrypts
- Atomic COMMIT with zero-grace old-key cutoff (or explicit pre-cutoff in-flight transfer continuity)
- 8 deterministic crash injection points (demo_mode only) for crash-recovery testing
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import json
from pathlib import Path
import sqlite3
import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.app.audit.ledger import append_audit_event, audit_write_lock
from backend.app.backups.service import BackupError, create_backup
from backend.app.config import settings
from backend.app.crypto.aead import AES256GCMProvider, build_resource_aad_bytes
from backend.app.crypto.hmac_hash import sha256_hex
from backend.app.crypto.keystore import KeyStoreError, LocalEncryptedKeyStore
from backend.app.crypto.mldsa import MLDSA65Provider
from backend.app.crypto.mlkem import MLKEM768Provider
from backend.app.db.models import (
    EncryptedObject,
    InFlightTransfer,
    KeyMetadata,
    Resource,
    RevocationEvent,
    RevocationTombstone,
    RotationOperation,
    utc_now,
)
from backend.app.keys.lifecycle import (
    TERMINAL_KEY_STATES,
    KeyLifecycleError,
    validate_key_purpose,
    validate_key_transition,
)
from backend.app.nodes.simulator import commit_cutoff_on_nodes, stage_key_on_nodes
from backend.app.vault.crypto_vault import _dek_keystore_id, _derive_kek_wrapping_key

VALID_GRACE_POLICIES = frozenset({"ZERO_GRACE", "CONTROLLED_IN_FLIGHT_ONLY"})
CRASH_INJECTION_POINTS = frozenset(
    {
        "AFTER_PREPARE",
        "AFTER_BACKUP",
        "AFTER_NODE_1_ACK",
        "AFTER_NODE_2_ACK",
        "BEFORE_COMMIT",
        "AFTER_COMMIT",
        "DURING_RETIRE",
        "AFTER_REVOCATION_TOMBSTONE",
    }
)

_aead = AES256GCMProvider()


class RotationError(Exception):
    """Domain error for key rotation, concurrency, or transfer policy failures."""

    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


class SimulatedCrashError(Exception):
    """Deterministic crash error raised ONLY in demo_mode after persisting checkpoint state."""

    def __init__(self, crash_point: str, operation_id: str, phase: str) -> None:
        super().__init__(f"Simulated crash injected at {crash_point} during {phase} ({operation_id})")
        self.crash_point = crash_point
        self.operation_id = operation_id
        self.phase = phase


def compute_journal_hash(op: RotationOperation) -> str:
    """Compute canonical SHA-256 digest over durable rotation journal state."""
    payload = {
        "operation_id": op.operation_id,
        "purpose": op.purpose,
        "from_key_id": op.from_key_id,
        "to_key_id": op.to_key_id,
        "from_version": op.from_version,
        "to_version": op.to_version,
        "phase": op.phase,
        "grace_policy": op.grace_policy,
        "actor_id": op.actor_id,
        "backup_id": op.backup_id,
        "committed": bool(op.committed),
        "node_acks_json": op.node_acks_json,
    }
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return sha256_hex(canonical)


def _check_crash_allowed(crash_at: str | None) -> None:
    if crash_at is None:
        return
    if not settings.demo_mode:
        raise RotationError(403, "CRASH_INJECTION_DISABLED", "Crash injection is allowed only when demo_mode=true.")
    if crash_at not in CRASH_INJECTION_POINTS:
        raise RotationError(400, "INVALID_CRASH_POINT", f"Unknown crash injection point: {crash_at}")


def _maybe_crash(crash_at: str | None, expected: str, op: RotationOperation) -> None:
    if crash_at == expected:
        raise SimulatedCrashError(expected, op.operation_id, op.phase)


def _has_tombstone(db: Session, key_id: str) -> bool:
    return (
        db.scalar(
            select(RevocationTombstone.id).where(
                RevocationTombstone.target_type == "key",
                RevocationTombstone.target_id == key_id,
            )
        )
        is not None
    )


def _generate_key_bytes(purpose: str) -> bytes:
    if purpose == "kem":
        _pk, sk = MLKEM768Provider.generate_keypair()
        return sk
    if purpose in ("signing", "audit"):
        _pk, sk = MLDSA65Provider.generate_keypair()
        return sk
    import secrets

    return secrets.token_bytes(32)


def _transition_key(db: Session, key: KeyMetadata, target_state: str, *, reason: str | None = None) -> None:
    validate_key_transition(key.state, target_state)
    now = utc_now()
    key.state = target_state
    if target_state in ("ACTIVE", "ACTIVE_NEW") and key.activated_at is None:
        key.activated_at = now
    if target_state in TERMINAL_KEY_STATES:
        key.revoked_at = now
        if not _has_tombstone(db, key.key_id):
            max_epoch = db.scalar(select(RevocationEvent.sequence_number).order_by(RevocationEvent.sequence_number.desc())) or 1
            db.add(
                RevocationTombstone(
                    target_type="key",
                    target_id=key.key_id,
                    revocation_epoch=max(1, int(max_epoch)),
                    reason=reason or f"Rotation tombstone ({target_state})",
                    created_at=now,
                )
            )
    db.flush()


def _prestage_vault_objects_for_new_kek(
    db: Session,
    keystore: LocalEncryptedKeyStore,
    *,
    from_key: KeyMetadata,
    to_key: KeyMetadata,
) -> int:
    """Re-wrap DEKs & pre-stage EncryptedObject rows under to_version WITHOUT flipping Resource.key_version yet.

    Pre-commit decrypts still succeed using from_version because Resource.key_version and the
    from_version EncryptedObject rows remain untouched until COMMIT.
    """
    from_kek_bytes = keystore.get_secret_bytes(from_key.key_id, expected_purpose="vault_kek")
    to_kek_bytes = keystore.get_secret_bytes(to_key.key_id, expected_purpose="vault_kek")

    resources = list(
        db.scalars(
            select(Resource).where(Resource.key_version == from_key.version).order_by(Resource.id)
        ).all()
    )
    staged_count = 0
    for res in resources:
        old_enc = db.scalar(
            select(EncryptedObject)
            .where(EncryptedObject.resource_id == res.id, EncryptedObject.version == from_key.version)
            .order_by(EncryptedObject.id.desc())
        )
        if old_enc is None:
            continue

        envelope = json.loads(old_enc.aead_envelope)
        aad_bytes = build_resource_aad_bytes(
            resource_id=str(envelope["resource_id"]),
            owner_id=str(envelope["owner_id"]),
            resource_type=str(envelope["resource_type"]),
            key_version=int(envelope["key_version"]),
            timestamp_utc=str(envelope["timestamp_utc"]),
            algorithm=str(envelope["algorithm"]),
            schema_version=str(envelope["schema_version"]),
            expires_at_utc=envelope.get("expires_at_utc"),
        )
        old_wrapped_blob = json.loads(
            keystore.get_secret_bytes(_dek_keystore_id(res.id, from_key.version), expected_purpose="vault_dek").decode("utf-8")
        )
        old_wrap_nonce = base64.b64decode(old_wrapped_blob["wrap_nonce_b64"], validate=True)
        old_wrapped_dek = base64.b64decode(old_wrapped_blob["wrapped_dek_b64"], validate=True)
        old_wrap_key = _derive_kek_wrapping_key(from_kek_bytes, resource_id=res.id, key_version=from_key.version)
        dek = _aead.decrypt(old_wrap_key, old_wrap_nonce, old_wrapped_dek, aad_bytes)

        # Decrypt payload with DEK and re-encrypt under new timestamp + to_version AAD so new-version metadata is authentic
        old_ct = base64.b64decode(old_enc.ciphertext_ref, validate=True)
        old_nonce = base64.b64decode(old_enc.nonce, validate=True)
        plaintext_bytes = _aead.decrypt(dek, old_nonce, old_ct, aad_bytes)

        new_ts = utc_now().isoformat()
        new_aad = build_resource_aad_bytes(
            resource_id=res.id,
            owner_id=res.owner_id,
            resource_type=res.type,
            key_version=to_key.version,
            timestamp_utc=new_ts,
            expires_at_utc=envelope.get("expires_at_utc"),
        )
        new_content_nonce, new_content_ct = _aead.encrypt(dek, plaintext_bytes, new_aad)
        new_wrap_key = _derive_kek_wrapping_key(to_kek_bytes, resource_id=res.id, key_version=to_key.version)
        new_wrap_nonce, new_wrapped_dek = _aead.encrypt(new_wrap_key, dek, new_aad)

        keystore.put_secret_bytes(
            _dek_keystore_id(res.id, to_key.version),
            purpose="vault_dek",
            secret_bytes=json.dumps(
                {
                    "kek_id": to_key.key_id,
                    "key_version": to_key.version,
                    "wrap_nonce_b64": base64.b64encode(new_wrap_nonce).decode("ascii"),
                    "wrapped_dek_b64": base64.b64encode(new_wrapped_dek).decode("ascii"),
                },
                separators=(",", ":"),
            ).encode("utf-8"),
        )

        ct_b64 = base64.b64encode(new_content_ct).decode("ascii")
        nonce_b64 = base64.b64encode(new_content_nonce).decode("ascii")
        new_envelope_meta = {
            "schema_version": "qshield.vault.aad.v1",
            "algorithm": "AES-256-GCM",
            "resource_id": res.id,
            "owner_id": res.owner_id,
            "resource_type": res.type,
            "key_version": to_key.version,
            "kek_id": to_key.key_id,
            "timestamp_utc": new_ts,
            "expires_at_utc": envelope.get("expires_at_utc"),
        }
        new_envelope_json = json.dumps(new_envelope_meta, separators=(",", ":"), sort_keys=True)
        integrity = sha256_hex((nonce_b64 + ":" + ct_b64 + ":" + new_envelope_json).encode("utf-8"))

        existing_new = db.scalar(
            select(EncryptedObject).where(
                EncryptedObject.resource_id == res.id,
                EncryptedObject.version == to_key.version,
            )
        )
        if existing_new is None:
            db.add(
                EncryptedObject(
                    resource_id=res.id,
                    ciphertext_ref=ct_b64,
                    nonce=nonce_b64,
                    aead_envelope=new_envelope_json,
                    version=to_key.version,
                    integrity=integrity,
                )
            )
        else:
            existing_new.ciphertext_ref = ct_b64
            existing_new.nonce = nonce_b64
            existing_new.aead_envelope = new_envelope_json
            existing_new.integrity = integrity
        staged_count += 1

    db.flush()
    return staged_count


def _cutover_resources_at_commit(db: Session, *, from_version: int, to_version: int, grace_policy: str) -> None:
    """Switch Resource.key_version to to_version, sparing only authorized pre-cutoff in-flight transfers."""
    in_flight_resource_ids: set[str] = set()
    if grace_policy == "CONTROLLED_IN_FLIGHT_ONLY":
        rows = list(
            db.scalars(
                select(InFlightTransfer).where(
                    InFlightTransfer.key_version == from_version,
                    InFlightTransfer.state == "STARTED",
                    InFlightTransfer.allow_post_cutoff.is_(True),
                )
            ).all()
        )
        in_flight_resource_ids = {r.resource_id for r in rows}

    # Abort any un-authorized started transfers on from_version
    now = utc_now()
    other_transfers = list(
        db.scalars(
            select(InFlightTransfer).where(
                InFlightTransfer.key_version == from_version,
                InFlightTransfer.state == "STARTED",
            )
        ).all()
    )
    for tx in other_transfers:
        if tx.resource_id not in in_flight_resource_ids or grace_policy == "ZERO_GRACE":
            tx.state = "ABORTED"
            tx.allow_post_cutoff = False
            tx.completed_at = now

    resources = list(db.scalars(select(Resource).where(Resource.key_version == from_version)).all())
    for res in resources:
        if res.id in in_flight_resource_ids:
            continue
        res.key_version = to_version
        res.updated_at = now
    db.flush()


def _finalize_all_resources_at_retire(db: Session, *, from_version: int, to_version: int) -> None:
    """Upgrade any deferred resources and abort lingering transfers on final RETIRE."""
    now = utc_now()
    lingering = list(
        db.scalars(
            select(InFlightTransfer).where(
                InFlightTransfer.key_version == from_version,
                InFlightTransfer.state == "STARTED",
            )
        ).all()
    )
    for tx in lingering:
        tx.state = "ABORTED"
        tx.allow_post_cutoff = False
        tx.completed_at = now

    resources = list(db.scalars(select(Resource).where(Resource.key_version == from_version)).all())
    for res in resources:
        res.key_version = to_version
        res.updated_at = now
    db.flush()


def execute_rotation(
    db: Session,
    keystore: LocalEncryptedKeyStore,
    *,
    purpose: str = "vault_kek",
    actor_id: str,
    reason: str,
    grace_policy: str = "ZERO_GRACE",
    new_key_id: str | None = None,
    correlation_id: str | None = None,
    auto_advance: bool = True,
    crash_at: str | None = None,
    backup_dir: Path | None = None,
) -> RotationOperation:
    """Start a phased key rotation and optionally advance cleanly through RETIRE."""
    _check_crash_allowed(crash_at)
    algorithm = validate_key_purpose(purpose)
    if grace_policy not in VALID_GRACE_POLICIES:
        raise RotationError(400, "INVALID_GRACE_POLICY", f"Unsupported grace policy: {grace_policy}")

    active_rot = db.scalar(
        select(RotationOperation).where(
            RotationOperation.purpose == purpose,
            RotationOperation.status == "IN_PROGRESS",
        )
    )
    if active_rot is not None:
        raise RotationError(409, "ROTATION_ALREADY_IN_PROGRESS", f"Active rotation '{active_rot.operation_id}' already exists for '{purpose}'.")

    from_key = db.scalar(
        select(KeyMetadata)
        .where(KeyMetadata.purpose == purpose, KeyMetadata.state == "ACTIVE")
        .order_by(KeyMetadata.version.desc())
    )
    if from_key is None:
        raise RotationError(409, "NO_ACTIVE_KEY", f"No ACTIVE key available for purpose '{purpose}'.")
    if _has_tombstone(db, from_key.key_id):
        raise RotationError(409, "KEY_TOMBSTONED", f"Source key '{from_key.key_id}' is tombstoned and cannot rotate.")

    to_version = from_key.version + 1
    target_key_id = new_key_id or f"key-{purpose.replace('_', '-')}-v{to_version}-{uuid.uuid4().hex[:6]}"
    if db.get(KeyMetadata, target_key_id) is not None or _has_tombstone(db, target_key_id):
        raise RotationError(409, "KEY_CONFLICT", f"Target key ID '{target_key_id}' cannot be used.")
    if db.scalar(select(KeyMetadata).where(KeyMetadata.purpose == purpose, KeyMetadata.version == to_version)) is not None:
        raise RotationError(409, "KEY_VERSION_CONFLICT", f"Key version {to_version} already exists for '{purpose}'.")

    # --- PHASE 1: PREPARE ---
    secret_bytes = _generate_key_bytes(purpose)
    try:
        keystore.put_secret_bytes(target_key_id, purpose=purpose, secret_bytes=secret_bytes)
    except KeyStoreError as exc:
        raise RotationError(503, "KEYSTORE_UNAVAILABLE", str(exc)) from None

    now = utc_now()
    to_key = KeyMetadata(
        key_id=target_key_id,
        purpose=purpose,
        algorithm=algorithm,
        version=to_version,
        state="PREPARED",
        created_at=now,
    )
    db.add(to_key)
    db.flush()

    _transition_key(db, from_key, "ROTATING")

    op_id = f"rot-{purpose}-{uuid.uuid4().hex[:10]}"
    corr = correlation_id or f"corr-rot-{uuid.uuid4().hex[:8]}"
    op = RotationOperation(
        operation_id=op_id,
        purpose=purpose,
        from_key_id=from_key.key_id,
        to_key_id=to_key.key_id,
        from_version=from_key.version,
        to_version=to_version,
        phase="PREPARE",
        status="IN_PROGRESS",
        grace_policy=grace_policy,
        actor_id=actor_id,
        reason=reason,
        correlation_id=corr,
        backup_id=None,
        committed=False,
        commit_at=None,
        node_acks_json="{}",
        journal_hash="",
        created_at=now,
        updated_at=now,
    )
    op.journal_hash = compute_journal_hash(op)
    with audit_write_lock():
        db.add(op)
        append_audit_event(
            db,
            event_type="KEY_ROTATION_STAGE",
            event_category="CRYPTO",
            actor_id=actor_id,
            action="rotation_prepare",
            target_type="rotation",
            target_id=op.operation_id,
            outcome="ALLOW",
            reason_code="ROTATION_PREPARE_OK",
            correlation_id=corr,
            source_component="key_rotation",
            payload={"purpose": purpose, "from_key_id": from_key.key_id, "to_key_id": to_key.key_id, "from_version": from_key.version, "to_version": to_version, "grace_policy": grace_policy},
            commit=False,
        )
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise RotationError(409, "ROTATION_ALREADY_IN_PROGRESS", f"Concurrent rotation detected for '{purpose}'.") from None
    db.refresh(op)

    _maybe_crash(crash_at, "AFTER_PREPARE", op)

    # Pre-rotation backup checkpoint
    try:
        manifest = create_backup(
            db,
            keystore,
            actor_id=actor_id,
            backup_dir=backup_dir,
            version_tag=from_key.version,
        )
    except BackupError as exc:
        raise RotationError(exc.status_code, exc.code, exc.message) from None

    op.backup_id = manifest.backup_id
    op.updated_at = utc_now()
    op.journal_hash = compute_journal_hash(op)
    db.commit()
    db.refresh(op)

    _maybe_crash(crash_at, "AFTER_BACKUP", op)

    if not auto_advance:
        return op

    return advance_rotation(
        db,
        keystore,
        operation_id=op.operation_id,
        actor_id=actor_id,
        crash_at=crash_at,
    )


def advance_rotation(
    db: Session,
    keystore: LocalEncryptedKeyStore,
    *,
    operation_id: str,
    actor_id: str,
    target_phase: str | None = None,
    crash_at: str | None = None,
) -> RotationOperation:
    """Advance an active rotation through DISTRIBUTE -> COMMIT -> RETIRE."""
    _check_crash_allowed(crash_at)
    op = db.get(RotationOperation, operation_id)
    if op is None:
        raise RotationError(404, "ROTATION_NOT_FOUND", f"Rotation operation '{operation_id}' does not exist.")
    if op.status != "IN_PROGRESS":
        raise RotationError(409, "ROTATION_NOT_ACTIVE", f"Rotation '{operation_id}' has terminal status '{op.status}'.")

    from_key = db.get(KeyMetadata, op.from_key_id)
    to_key = db.get(KeyMetadata, op.to_key_id)
    if from_key is None or to_key is None:
        raise RotationError(409, "KEY_MISSING", "Rotation key metadata missing.")

    if _has_tombstone(db, to_key.key_id) or to_key.state in TERMINAL_KEY_STATES:
        with audit_write_lock():
            op.status = "FAILED_CLOSED"
            op.failure_info = "Target key is revoked/compromised before completion."
            append_audit_event(
                db,
                event_type="KEY_ROTATION_FAILED",
                event_category="CRYPTO",
                actor_id=actor_id,
                action="rotation_advance",
                target_type="rotation",
                target_id=op.operation_id,
                outcome="DENY",
                reason_code="KEY_TOMBSTONED",
                correlation_id=op.correlation_id,
                source_component="key_rotation",
                payload={"to_key_id": to_key.key_id, "phase": op.phase},
                commit=False,
            )
            db.commit()
        raise RotationError(409, "KEY_TOMBSTONED", "Target key is tombstoned; rotation halted.")

    # Step DISTRIBUTE
    if op.phase == "PREPARE":
        if op.purpose == "vault_kek":
            try:
                _prestage_vault_objects_for_new_kek(db, keystore, from_key=from_key, to_key=to_key)
            except (KeyStoreError, Exception) as exc:
                raise RotationError(500, "PRESTAGE_FAILED", f"Failed to pre-stage encrypted vault objects: {exc}") from None

        if crash_at == "AFTER_NODE_1_ACK":
            with audit_write_lock():
                acks = stage_key_on_nodes(db, operation_id=op.operation_id, target_version=op.to_version, max_ack_nodes=1)
                op.phase = "DISTRIBUTE"
                op.node_acks_json = json.dumps(acks, separators=(",", ":"), sort_keys=True)
                op.updated_at = utc_now()
                op.journal_hash = compute_journal_hash(op)
                append_audit_event(
                    db,
                    event_type="KEY_ROTATION_STAGE",
                    event_category="CRYPTO",
                    actor_id=actor_id,
                    action="rotation_distribute_partial",
                    target_type="rotation",
                    target_id=op.operation_id,
                    outcome="ALLOW",
                    reason_code="ROTATION_DISTRIBUTE_ACK_1",
                    correlation_id=op.correlation_id,
                    source_component="key_rotation",
                    payload={"phase": "DISTRIBUTE", "acks": acks},
                    commit=False,
                )
                db.commit()
            _maybe_crash(crash_at, "AFTER_NODE_1_ACK", op)

        if crash_at == "AFTER_NODE_2_ACK":
            with audit_write_lock():
                acks = stage_key_on_nodes(db, operation_id=op.operation_id, target_version=op.to_version, max_ack_nodes=2)
                op.phase = "DISTRIBUTE"
                op.node_acks_json = json.dumps(acks, separators=(",", ":"), sort_keys=True)
                op.updated_at = utc_now()
                op.journal_hash = compute_journal_hash(op)
                append_audit_event(
                    db,
                    event_type="KEY_ROTATION_STAGE",
                    event_category="CRYPTO",
                    actor_id=actor_id,
                    action="rotation_distribute_partial",
                    target_type="rotation",
                    target_id=op.operation_id,
                    outcome="ALLOW",
                    reason_code="ROTATION_DISTRIBUTE_ACK_2",
                    correlation_id=op.correlation_id,
                    source_component="key_rotation",
                    payload={"phase": "DISTRIBUTE", "acks": acks},
                    commit=False,
                )
                db.commit()
            _maybe_crash(crash_at, "AFTER_NODE_2_ACK", op)

        with audit_write_lock():
            acks = stage_key_on_nodes(db, operation_id=op.operation_id, target_version=op.to_version, max_ack_nodes=None)
            op.phase = "DISTRIBUTE"
            op.node_acks_json = json.dumps(acks, separators=(",", ":"), sort_keys=True)
            op.updated_at = utc_now()
            op.journal_hash = compute_journal_hash(op)
            append_audit_event(
                db,
                event_type="KEY_ROTATION_STAGE",
                event_category="CRYPTO",
                actor_id=actor_id,
                action="rotation_distribute",
                target_type="rotation",
                target_id=op.operation_id,
                outcome="ALLOW",
                reason_code="ROTATION_DISTRIBUTE_OK",
                correlation_id=op.correlation_id,
                source_component="key_rotation",
                payload={"phase": "DISTRIBUTE", "to_version": op.to_version, "acks": acks},
                commit=False,
            )
            db.commit()
        db.refresh(op)

        _maybe_crash(crash_at, "BEFORE_COMMIT", op)
        if target_phase == "DISTRIBUTE":
            return op

    # Step COMMIT
    if op.phase == "DISTRIBUTE":
        with audit_write_lock():
            if op.purpose == "vault_kek":
                _cutover_resources_at_commit(
                    db,
                    from_version=op.from_version,
                    to_version=op.to_version,
                    grace_policy=op.grace_policy,
                )

            _transition_key(db, to_key, "ACTIVE_NEW")
            node_acks = commit_cutoff_on_nodes(
                db,
                operation_id=op.operation_id,
                new_version=op.to_version,
                cutoff_epoch=op.to_version,
            )
            now = utc_now()
            op.phase = "COMMIT"
            op.committed = True
            op.commit_at = now
            op.node_acks_json = json.dumps(node_acks, separators=(",", ":"), sort_keys=True)
            op.updated_at = now
            op.journal_hash = compute_journal_hash(op)
            append_audit_event(
                db,
                event_type="KEY_ROTATION_STAGE",
                event_category="CRYPTO",
                actor_id=actor_id,
                action="rotation_commit",
                target_type="rotation",
                target_id=op.operation_id,
                outcome="ALLOW",
                reason_code="ROTATION_COMMIT_CUTOFF",
                correlation_id=op.correlation_id,
                source_component="key_rotation",
                payload={"phase": "COMMIT", "from_version": op.from_version, "to_version": op.to_version, "grace_policy": op.grace_policy},
                commit=False,
            )
            db.commit()
        db.refresh(op)

        if crash_at == "AFTER_REVOCATION_TOMBSTONE":
            with audit_write_lock():
                _transition_key(db, to_key, "REVOKED", reason="Simulated tombstone crash injection")
                op.updated_at = utc_now()
                op.journal_hash = compute_journal_hash(op)
                append_audit_event(
                    db,
                    event_type="KEY_REVOKED",
                    event_category="CRYPTO",
                    actor_id=actor_id,
                    action="rotation_tombstone",
                    target_type="key",
                    target_id=to_key.key_id,
                    outcome="ALLOW",
                    reason_code="KEY_TOMBSTONED_MID_ROTATION",
                    correlation_id=op.correlation_id,
                    source_component="key_rotation",
                    payload={"operation_id": op.operation_id},
                    commit=False,
                )
                db.commit()
            _maybe_crash(crash_at, "AFTER_REVOCATION_TOMBSTONE", op)

        _maybe_crash(crash_at, "AFTER_COMMIT", op)
        if target_phase == "COMMIT":
            return op

    # Step RETIRE
    if op.phase == "COMMIT":
        with audit_write_lock():
            if op.purpose == "vault_kek":
                _finalize_all_resources_at_retire(db, from_version=op.from_version, to_version=op.to_version)

            _transition_key(db, from_key, "RETIRED")
            op.phase = "RETIRE"
            op.updated_at = utc_now()
            op.journal_hash = compute_journal_hash(op)
            append_audit_event(
                db,
                event_type="KEY_ROTATION_STAGE",
                event_category="CRYPTO",
                actor_id=actor_id,
                action="rotation_retire_begin",
                target_type="rotation",
                target_id=op.operation_id,
                outcome="ALLOW",
                reason_code="OLD_KEY_RETIRED",
                correlation_id=op.correlation_id,
                source_component="key_rotation",
                payload={"phase": "RETIRE", "retired_key_id": from_key.key_id},
                commit=False,
            )
            db.commit()

        _maybe_crash(crash_at, "DURING_RETIRE", op)

        if _has_tombstone(db, to_key.key_id):
            with audit_write_lock():
                op.status = "FAILED_CLOSED"
                op.failure_info = "Target key tombstoned prior to RETIRE completion."
                append_audit_event(
                    db,
                    event_type="KEY_ROTATION_FAILED",
                    event_category="CRYPTO",
                    actor_id=actor_id,
                    action="rotation_retire_complete",
                    target_type="rotation",
                    target_id=op.operation_id,
                    outcome="DENY",
                    reason_code="KEY_TOMBSTONED",
                    correlation_id=op.correlation_id,
                    source_component="key_rotation",
                    payload={"to_key_id": to_key.key_id},
                    commit=False,
                )
                db.commit()
            raise RotationError(409, "KEY_TOMBSTONED", "Target key tombstoned before RETIRE completion.")

        with audit_write_lock():
            _transition_key(db, to_key, "ACTIVE")
            op.status = "COMPLETED"
            op.updated_at = utc_now()
            op.journal_hash = compute_journal_hash(op)
            append_audit_event(
                db,
                event_type="KEY_ROTATION_STAGE",
                event_category="CRYPTO",
                actor_id=actor_id,
                action="rotation_completed",
                target_type="rotation",
                target_id=op.operation_id,
                outcome="ALLOW",
                reason_code="ROTATION_COMPLETED",
                correlation_id=op.correlation_id,
                source_component="key_rotation",
                payload={"phase": "RETIRE", "active_key_id": to_key.key_id, "to_version": op.to_version},
                commit=False,
            )
            db.commit()
        db.refresh(op)

    return op


def start_in_flight_transfer(
    db: Session,
    *,
    actor_id: str,
    resource_id: str,
    allow_post_cutoff: bool = True,
) -> InFlightTransfer:
    """Register an explicit pre-cutoff transfer before rotation commit."""
    res = db.get(Resource, resource_id)
    if res is None:
        raise RotationError(404, "RESOURCE_NOT_FOUND", f"Resource '{resource_id}' not found.")
    tx = InFlightTransfer(
        transfer_id=f"tx-{uuid.uuid4().hex[:10]}",
        actor_id=actor_id,
        resource_id=resource_id,
        key_version=res.key_version,
        state="STARTED",
        allow_post_cutoff=allow_post_cutoff,
        started_at=utc_now(),
    )
    db.add(tx)
    db.commit()
    db.refresh(tx)
    return tx


def complete_in_flight_transfer(
    db: Session,
    *,
    transfer_id: str,
    actor_id: str,
) -> tuple[InFlightTransfer, str]:
    """Complete an in-flight transfer respecting zero-grace cutoff & key revocation."""
    tx = db.get(InFlightTransfer, transfer_id)
    if tx is None:
        raise RotationError(404, "TRANSFER_NOT_FOUND", f"Transfer '{transfer_id}' not found.")
    if tx.actor_id != actor_id:
        raise RotationError(403, "FORBIDDEN_TRANSFER", "Transfer belongs to a different actor.")
    if tx.state != "STARTED":
        raise RotationError(409, "TRANSFER_NOT_ACTIVE", f"Transfer '{transfer_id}' is already {tx.state}.")

    res = db.get(Resource, tx.resource_id)
    if res is None:
        raise RotationError(404, "RESOURCE_NOT_FOUND", "Resource no longer exists.")

    key = db.scalar(
        select(KeyMetadata).where(KeyMetadata.purpose == "vault_kek", KeyMetadata.version == tx.key_version)
    )
    if key is None or key.state in TERMINAL_KEY_STATES or _has_tombstone(db, key.key_id):
        tx.state = "ABORTED"
        tx.allow_post_cutoff = False
        tx.completed_at = utc_now()
        db.commit()
        raise RotationError(403, "DENY_TRANSFER_KEY_REVOKED", "Old key is revoked/compromised; transfer aborted.")

    # Check if latest rotation enforced ZERO_GRACE past tx.key_version
    latest_rot = db.scalar(
        select(RotationOperation)
        .where(RotationOperation.purpose == "vault_kek")
        .order_by(RotationOperation.created_at.desc())
    )
    if latest_rot is not None and latest_rot.committed and latest_rot.to_version > tx.key_version:
        if latest_rot.grace_policy == "ZERO_GRACE" or not tx.allow_post_cutoff or latest_rot.status == "COMPLETED":
            tx.state = "ABORTED"
            tx.allow_post_cutoff = False
            tx.completed_at = utc_now()
            db.commit()
            raise RotationError(403, "DENY_OLD_KEY_CUTOFF", "Old-key cutoff enforced; transfer aborted under zero-grace policy.")

    tx.state = "COMPLETED"
    tx.completed_at = utc_now()
    db.commit()
    db.refresh(tx)
    return tx, "ALLOW_IN_FLIGHT_CONTINUITY"


def get_rotation_or_raise(db: Session, operation_id: str) -> RotationOperation:
    op = db.get(RotationOperation, operation_id)
    if op is None:
        raise RotationError(404, "ROTATION_NOT_FOUND", f"Rotation '{operation_id}' does not exist.")
    return op


def list_rotations(db: Session, *, limit: int = 50, offset: int = 0) -> list[RotationOperation]:
    return list(
        db.scalars(
            select(RotationOperation)
            .order_by(RotationOperation.created_at.desc())
            .limit(limit)
            .offset(offset)
        ).all()
    )
