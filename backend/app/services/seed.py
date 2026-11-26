"""Reproducible synthetic seed and reset utility for Q-SHIELD Phase 2.

All identities, devices, tokens, and resources are synthetic demo records.
Sessions store SHA-256 hashes of documented demo tokens; plaintext tokens are
never stored in the database.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
from datetime import timedelta
import json
from pathlib import Path
import secrets
import sys

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from backend.app.auth.rate_limit import login_rate_limiter
from backend.app.auth.tokens import hash_token
from backend.app.config import settings
from backend.app.crypto.keystore import LocalEncryptedKeyStore
from backend.app.crypto.mldsa import MLDSA65Provider
from backend.app.db.models import (
    AccessRequest,
    AlertRecord,
    AuditCheckpoint,
    AuditEvent,
    AuditEvidenceReceipt,
    BackupManifest,
    BenchmarkRun,
    CryptoSession,
    DetectionRun,
    DetectorEvent,
    Device,
    DeviceStateHistory,
    EncryptedObject,
    InFlightTransfer,
    Incident,
    KeyMetadata,
    MessageDelivery,
    MessageRecord,
    NodeAcknowledgement,
    NodeEventInbox,
    NodeRegistry,
    ReplayRecord,
    Resource,
    ResourcePermission,
    RevocationEvent,
    RevocationTombstone,
    RolePermission,
    RotationOperation,
    SettingEntry,
    User,
    UserSession,
    utc_now,
)
from backend.app.db.session import SessionLocal, verify_database_health, _default_engine
from backend.app.identity.roles import ROLE_PERMISSION_DEFINITIONS

# Documented synthetic bearer tokens for offline demo/testing (hashed before DB insert).
DEMO_SYNTHETIC_TOKENS: dict[str, str] = {
    "sess-alex-valid": "qshield-demo-token-user-alex",
    "sess-alex-expired": "qshield-demo-token-user-alex-expired",
    "sess-alex-revoked": "qshield-demo-token-user-alex-revoked",
    "sess-blair-valid": "qshield-demo-token-user-blair",
    "sess-secops-valid": "qshield-demo-token-user-secops",
    "sess-admin-valid": "qshield-demo-token-user-admin",
    "sess-auditor-valid": "qshield-demo-token-user-auditor",
}


@dataclass(frozen=True)
class SeedSummary:
    users_seeded: int
    devices_seeded: int
    sessions_seeded: int
    resources_seeded: int


def _clear_all_tables(db: Session) -> None:
    """Delete rows in FK-safe child-to-parent order inside an active transaction."""
    for model in (
        AccessRequest,
        AuditEvidenceReceipt,
        AuditEvent,
        AuditCheckpoint,
        AlertRecord,
        DetectionRun,
        DetectorEvent,
        ReplayRecord,
        MessageDelivery,
        MessageRecord,
        CryptoSession,
        NodeAcknowledgement,
        NodeEventInbox,
        RevocationEvent,
        NodeRegistry,
        RotationOperation,
        BackupManifest,
        InFlightTransfer,
        EncryptedObject,
        ResourcePermission,
        Resource,
        DeviceStateHistory,
        UserSession,
        Device,
        RevocationTombstone,
        Incident,
        KeyMetadata,
        RolePermission,
        SettingEntry,
        User,
        BenchmarkRun,
    ):
        db.execute(delete(model))


def seed_database(
    db: Session,
    *,
    reset: bool = False,
    keystore: LocalEncryptedKeyStore | None = None,
    backup_dir: Path | None = None,
) -> SeedSummary:
    """Populate database with reproducible synthetic Phase 2/3 seed data."""
    if not reset and db.scalar(select(User.id).limit(1)) is not None:
        return SeedSummary(
            users_seeded=db.query(User).count(),
            devices_seeded=db.query(Device).count(),
            sessions_seeded=db.query(UserSession).count(),
            resources_seeded=db.query(Resource).count(),
        )

    active_keystore = keystore or LocalEncryptedKeyStore(Path(settings.keystore_dir), settings.keystore_secret)
    active_backup_dir = backup_dir if backup_dir is not None else Path(settings.backup_dir)

    if reset:
        login_rate_limiter.reset_all()
        _clear_all_tables(db)
        db.flush()
        active_keystore.reset()
        if active_backup_dir.exists():
            for bfile in active_backup_dir.iterdir():
                if bfile.is_file() and bfile.suffix in (".qsbak", ".json", ".seed"):
                    bfile.unlink(missing_ok=True)

    now = utc_now()

    users = [
        User(id="user-alex", display_name="Alex Mercer (Synthetic Owner)", role="owner", enabled=True, is_synthetic=True),
        User(id="user-blair", display_name="Blair Vance (Synthetic Peer Owner)", role="owner", enabled=True, is_synthetic=True),
        User(id="user-secops", display_name="Morgan Chen (Synthetic Security Operator)", role="security_operator", enabled=True, is_synthetic=True),
        User(id="user-admin", display_name="Jordan Patel (Synthetic Admin)", role="admin", enabled=True, is_synthetic=True),
        User(id="user-auditor", display_name="Sam Rivera (Synthetic Auditor)", role="auditor", enabled=True, is_synthetic=True),
        User(id="user-disabled", display_name="Casey Disabled (Synthetic Disabled)", role="owner", enabled=False, is_synthetic=True),
    ]
    db.add_all(users)

    for role_name, perm_list in ROLE_PERMISSION_DEFINITIONS.items():
        for action, scope, desc in perm_list:
            db.add(RolePermission(role=role_name, action=action, scope=scope, description=desc))

    devices = [
        Device(id="dev-alex-trusted", owner_id="user-alex", credential_fingerprint="fp-synth-alex-trusted-01", state="TRUSTED", state_version=1, enrolled_at=now, reason="Seeded trusted owner device"),
        Device(id="dev-alex-pending", owner_id="user-alex", credential_fingerprint="fp-synth-alex-pending-02", state="PENDING", state_version=1, enrolled_at=now, reason="Seeded pending approval device"),
        Device(id="dev-alex-suspended", owner_id="user-alex", credential_fingerprint="fp-synth-alex-suspended-03", state="SUSPENDED", state_version=2, enrolled_at=now, reason="Seeded suspended device"),
        Device(id="dev-alex-revoked", owner_id="user-alex", credential_fingerprint="fp-synth-alex-revoked-04", state="REVOKED", state_version=2, enrolled_at=now, revoked_at=now, reason="Seeded lost-device revocation"),
        Device(id="dev-blair-trusted", owner_id="user-blair", credential_fingerprint="fp-synth-blair-trusted-01", state="TRUSTED", state_version=1, enrolled_at=now, reason="Seeded peer trusted device"),
        Device(id="dev-secops-trusted", owner_id="user-secops", credential_fingerprint="fp-synth-secops-trusted-01", state="TRUSTED", state_version=1, enrolled_at=now, reason="Seeded operator workstation"),
        Device(id="dev-admin-trusted", owner_id="user-admin", credential_fingerprint="fp-synth-admin-trusted-01", state="TRUSTED", state_version=1, enrolled_at=now, reason="Seeded admin workstation"),
        Device(id="dev-auditor-trusted", owner_id="user-auditor", credential_fingerprint="fp-synth-auditor-trusted-01", state="TRUSTED", state_version=1, enrolled_at=now, reason="Seeded auditor workstation"),
    ]
    db.add_all(devices)
    db.flush()

    for dev in devices:
        db.add(
            DeviceStateHistory(
                device_id=dev.id,
                from_state=None,
                to_state=dev.state,
                state_version=dev.state_version,
                changed_by="seed",
                reason=dev.reason or "Initial synthetic seed",
                correlation_id="corr-seed-init",
                created_at=now,
            )
        )

    db.add(
        RevocationTombstone(
            target_type="device",
            target_id="dev-alex-revoked",
            revocation_epoch=1,
            reason="Seeded lost-device revocation tombstone",
            created_at=now,
        )
    )

    sessions = [
        UserSession(id="sess-alex-valid", token_hash=hash_token(DEMO_SYNTHETIC_TOKENS["sess-alex-valid"]), actor_id="user-alex", device_id="dev-alex-trusted", state="ACTIVE", issued_at=now, expires_at=now + timedelta(hours=8)),
        UserSession(id="sess-alex-expired", token_hash=hash_token(DEMO_SYNTHETIC_TOKENS["sess-alex-expired"]), actor_id="user-alex", device_id="dev-alex-trusted", state="ACTIVE", issued_at=now - timedelta(hours=10), expires_at=now - timedelta(hours=1)),
        UserSession(id="sess-alex-revoked", token_hash=hash_token(DEMO_SYNTHETIC_TOKENS["sess-alex-revoked"]), actor_id="user-alex", device_id="dev-alex-trusted", state="REVOKED", issued_at=now - timedelta(hours=2), expires_at=now + timedelta(hours=6), revoked_at=now, revoke_reason="Seeded revoked session"),
        UserSession(id="sess-blair-valid", token_hash=hash_token(DEMO_SYNTHETIC_TOKENS["sess-blair-valid"]), actor_id="user-blair", device_id="dev-blair-trusted", state="ACTIVE", issued_at=now, expires_at=now + timedelta(hours=8)),
        UserSession(id="sess-secops-valid", token_hash=hash_token(DEMO_SYNTHETIC_TOKENS["sess-secops-valid"]), actor_id="user-secops", device_id="dev-secops-trusted", state="ACTIVE", issued_at=now, expires_at=now + timedelta(hours=8)),
        UserSession(id="sess-admin-valid", token_hash=hash_token(DEMO_SYNTHETIC_TOKENS["sess-admin-valid"]), actor_id="user-admin", device_id="dev-admin-trusted", state="ACTIVE", issued_at=now, expires_at=now + timedelta(hours=8)),
        UserSession(id="sess-auditor-valid", token_hash=hash_token(DEMO_SYNTHETIC_TOKENS["sess-auditor-valid"]), actor_id="user-auditor", device_id="dev-auditor-trusted", state="ACTIVE", issued_at=now, expires_at=now + timedelta(hours=8)),
    ]
    db.add_all(sessions)

    db.add_all(
        [
            KeyMetadata(key_id="key-v1-active", purpose="vault_kek", algorithm="HKDF-SHA-256+AES-256-GCM", version=1, state="ACTIVE", created_at=now, activated_at=now),
            KeyMetadata(key_id="key-v0-revoked", purpose="vault_kek", algorithm="HKDF-SHA-256+AES-256-GCM", version=0, state="REVOKED", created_at=now - timedelta(days=2), activated_at=now - timedelta(days=2), revoked_at=now - timedelta(days=1)),
            KeyMetadata(key_id="key-revocation-signer-v1", purpose="signing", algorithm="ML-DSA-65", version=100, state="ACTIVE", created_at=now, activated_at=now),
            KeyMetadata(key_id="key-audit-signer-v1", purpose="audit", algorithm="ML-DSA-65", version=1, state="ACTIVE", created_at=now, activated_at=now),
            KeyMetadata(key_id="key-messaging-v1", purpose="messaging", algorithm="ML-KEM-768+HKDF-SHA-256+AES-256-GCM", version=1, state="ACTIVE", created_at=now, activated_at=now),
        ]
    )
    if not active_keystore.has_key("key-v1-active"):
        active_keystore.put_secret_bytes("key-v1-active", purpose="vault_kek", secret_bytes=secrets.token_bytes(32))

    signer_pk, signer_sk = MLDSA65Provider.generate_keypair()
    if not active_keystore.has_key("key-revocation-signer-v1"):
        active_keystore.put_secret_bytes("key-revocation-signer-v1", purpose="signing", secret_bytes=signer_sk)
    signer_pk_b64 = base64.b64encode(signer_pk).decode("ascii")

    audit_pk, audit_sk = MLDSA65Provider.generate_keypair()
    if not active_keystore.has_key("key-audit-signer-v1"):
        active_keystore.put_secret_bytes("key-audit-signer-v1", purpose="audit", secret_bytes=audit_sk)
    audit_pk_b64 = base64.b64encode(audit_pk).decode("ascii")

    resources = [
        Resource(id="res-alex-brief", owner_id="user-alex", type="synthetic_document", metadata_json=json.dumps({"classification": "synthetic-restricted", "title": "Alex Synthetic Brief"}), key_version=1, state="ACTIVE"),
        Resource(id="res-blair-ledger", owner_id="user-blair", type="synthetic_document", metadata_json=json.dumps({"classification": "synthetic-restricted", "title": "Blair Synthetic Ledger"}), key_version=1, state="ACTIVE"),
        Resource(id="res-disabled-archive", owner_id="user-alex", type="synthetic_archive", metadata_json=json.dumps({"classification": "synthetic-archived", "title": "Disabled Archive"}), key_version=1, state="DISABLED"),
        Resource(id="res-revoked-key-doc", owner_id="user-alex", type="synthetic_document", metadata_json=json.dumps({"classification": "synthetic-legacy", "title": "Revoked Key Version Document"}), key_version=0, state="ACTIVE"),
        Resource(id="res-incident-locked", owner_id="user-alex", type="synthetic_document", metadata_json=json.dumps({"classification": "synthetic-quarantined", "title": "Incident Locked Resource"}), key_version=1, state="ACTIVE"),
        Resource(id="res-shared-policy", owner_id="user-admin", type="synthetic_policy", metadata_json=json.dumps({"classification": "synthetic-shared", "title": "Shared Security Guidelines"}), key_version=1, state="ACTIVE"),
    ]
    db.add_all(resources)
    db.flush()

    db.add(
        ResourcePermission(
            resource_id="res-shared-policy",
            subject_type="actor",
            subject_id="user-alex",
            permission="read",
            granted_by="user-admin",
            created_at=now,
        )
    )

    db.add(
        Incident(
            id="inc-seed-block-01",
            type="quarantine_hold",
            severity="HIGH",
            state="OPEN",
            actor_or_target="res-incident-locked",
            blocks_access=True,
            reason="Synthetic incident lock for zero-trust Step 9 verification",
            created_at=now,
        )
    )

    db.add_all(
        [
            NodeRegistry(node_id="node-1", service="portal-gateway", health="HEALTHY", available=True, current_epoch=0, accepted_key_version=1, staged_key_version=None, cutoff_epoch=0, latency_profile="nominal", latency_ms=10, last_event_seq=0, sync_status="CONVERGED", fault_mode="NONE", last_heartbeat=now),
            NodeRegistry(node_id="node-2", service="reports-node-a", health="HEALTHY", available=True, current_epoch=0, accepted_key_version=1, staged_key_version=None, cutoff_epoch=0, latency_profile="nominal", latency_ms=25, last_event_seq=0, sync_status="CONVERGED", fault_mode="NONE", last_heartbeat=now),
            NodeRegistry(node_id="node-3", service="reports-node-b", health="HEALTHY", available=True, current_epoch=0, accepted_key_version=1, staged_key_version=None, cutoff_epoch=0, latency_profile="elevated", latency_ms=45, last_event_seq=0, sync_status="CONVERGED", fault_mode="NONE", last_heartbeat=now),
        ]
    )

    db.add_all(
        [
            SettingEntry(key="demo_mode", value="true", updated_at=now),
            SettingEntry(key="offline_mode", value="true", updated_at=now),
            SettingEntry(key="revocation_signer_public_key_b64", value=signer_pk_b64, updated_at=now),
            SettingEntry(key="audit_signer_public_key_b64", value=audit_pk_b64, updated_at=now),
        ]
    )

    db.commit()
    return SeedSummary(
        users_seeded=len(users),
        devices_seeded=len(devices),
        sessions_seeded=len(sessions),
        resources_seeded=len(resources),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Seed or reset the Q-SHIELD synthetic SQLite database.")
    parser.add_argument("--reset", action="store_true", help="Clear and reseed all tables cleanly.")
    args = parser.parse_args(argv)

    ok, detail = verify_database_health(_default_engine)
    if not ok:
        print(f"Database not ready ({detail}). Run 'alembic -c backend/alembic.ini upgrade head' first.", file=sys.stderr)
        return 1

    with SessionLocal() as db:
        summary = seed_database(db, reset=args.reset)
    print(
        f"Seed complete (reset={args.reset}): users={summary.users_seeded}, "
        f"devices={summary.devices_seeded}, sessions={summary.sessions_seeded}, resources={summary.resources_seeded}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
