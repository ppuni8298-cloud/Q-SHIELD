"""Key metadata persistence, generation in local encrypted keystore, and state transitions."""

from __future__ import annotations

import secrets

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.audit.ledger import append_audit_event, audit_write_lock
from backend.app.crypto.keystore import KeyStoreError, LocalEncryptedKeyStore
from backend.app.crypto.mlkem import MLKEM768Provider
from backend.app.crypto.mldsa import MLDSA65Provider
from backend.app.db.models import InFlightTransfer, KeyMetadata, RevocationTombstone, RotationOperation, utc_now
from backend.app.keys.lifecycle import (
    KEY_PURPOSES,
    KeyLifecycleError,
    validate_key_purpose,
    validate_key_transition,
)


def list_keys(db: Session, *, limit: int = 50, offset: int = 0) -> tuple[list[KeyMetadata], int]:
    total = db.scalar(select(func.count()).select_from(KeyMetadata)) or 0
    items = list(
        db.scalars(
            select(KeyMetadata).order_by(KeyMetadata.version.desc(), KeyMetadata.key_id).limit(limit).offset(offset)
        ).all()
    )
    return items, int(total)


def get_key_or_raise(db: Session, key_id: str) -> KeyMetadata:
    rec = db.get(KeyMetadata, key_id)
    if rec is None:
        raise KeyLifecycleError(404, "KEY_NOT_FOUND", "Requested key metadata does not exist.")
    return rec


def generate_managed_key(
    db: Session,
    keystore: LocalEncryptedKeyStore,
    *,
    key_id: str,
    purpose: str,
    version: int,
    activate_immediately: bool = False,
) -> KeyMetadata:
    """Generate vetted cryptographic key material into encrypted keystore and persist metadata."""
    algorithm = validate_key_purpose(purpose)
    if db.get(KeyMetadata, key_id) is not None:
        raise KeyLifecycleError(409, "KEY_ALREADY_EXISTS", "Key ID already exists.")
    dup_pv = db.scalar(
        select(KeyMetadata).where(KeyMetadata.purpose == purpose, KeyMetadata.version == version)
    )
    if dup_pv is not None:
        raise KeyLifecycleError(
            409, "KEY_VERSION_CONFLICT", f"Key version {version} already exists for purpose '{purpose}'."
        )

    # Generate purpose-specific material via vetted providers; never return or log raw secrets.
    if purpose == "kem":
        _pk, sk = MLKEM768Provider.generate_keypair()
        secret_bytes = sk
    elif purpose in ("signing", "audit"):
        _pk, sk = MLDSA65Provider.generate_keypair()
        secret_bytes = sk
    else:
        secret_bytes = secrets.token_bytes(32)

    try:
        keystore.put_secret_bytes(key_id, purpose=purpose, secret_bytes=secret_bytes)
    except KeyStoreError as exc:
        raise KeyLifecycleError(503, "KEYSTORE_UNAVAILABLE", str(exc)) from None

    now = utc_now()
    state = "ACTIVE" if activate_immediately else "PREPARED"
    meta = KeyMetadata(
        key_id=key_id,
        purpose=purpose,
        algorithm=algorithm,
        version=version,
        state=state,
        created_at=now,
        activated_at=now if activate_immediately else None,
    )
    with audit_write_lock():
        db.add(meta)
        append_audit_event(
            db,
            event_type="KEY_GENERATED",
            event_category="CRYPTO",
            actor_id="system",
            action="generate_key",
            target_type="key",
            target_id=key_id,
            outcome="ALLOW",
            reason_code=f"KEY_CREATED_{state}",
            correlation_id="corr-key-generate",
            source_component="key_service",
            payload={"purpose": purpose, "algorithm": algorithm, "version": version, "state": state},
            commit=False,
        )
        db.commit()
    db.refresh(meta)
    return meta


def transition_key_state(
    db: Session,
    *,
    key_id: str,
    target_state: str,
    reason: str,
    confirmation: bool,
) -> KeyMetadata:
    """Enforce valid lifecycle transitions and durable tombstones for revoked/compromised keys."""
    if not confirmation:
        raise KeyLifecycleError(400, "CONFIRMATION_REQUIRED", "Explicit confirmation is required.")

    rec = get_key_or_raise(db, key_id)
    validate_key_transition(rec.state, target_state)

    prev_state = rec.state
    now = utc_now()
    rec.state = target_state
    if target_state in ("ACTIVE", "ACTIVE_NEW") and rec.activated_at is None:
        rec.activated_at = now
    if target_state in ("REVOKED", "COMPROMISED"):
        rec.revoked_at = now
        existing_tombstone = db.scalar(
            select(RevocationTombstone).where(
                RevocationTombstone.target_type == "key",
                RevocationTombstone.target_id == rec.key_id,
            )
        )
        if existing_tombstone is None:
            db.add(
                RevocationTombstone(
                    target_type="key",
                    target_id=rec.key_id,
                    revocation_epoch=1,
                    reason=reason,
                    created_at=now,
                )
            )

    with audit_write_lock():
        append_audit_event(
            db,
            event_type=f"KEY_{target_state}",
            event_category="CRYPTO",
            actor_id="system",
            action="transition_key",
            target_type="key",
            target_id=rec.key_id,
            outcome="ALLOW",
            reason_code=f"KEY_TRANSITION_{target_state}",
            correlation_id="corr-key-transition",
            source_component="key_service",
            payload={"from_state": prev_state, "to_state": target_state, "version": rec.version, "reason": reason},
            commit=False,
        )
        db.commit()
    db.refresh(rec)
    return rec


def get_active_kek_metadata(db: Session, key_version: int) -> KeyMetadata:
    """Retrieve active vault_kek metadata for envelope operations; fail closed otherwise."""
    rec = db.scalar(
        select(KeyMetadata).where(
            KeyMetadata.purpose == "vault_kek",
            KeyMetadata.version == key_version,
        )
    )
    if rec is None:
        raise KeyLifecycleError(404, "KEY_NOT_FOUND", f"No vault_kek registered for version {key_version}.")
    if rec.state in ("REVOKED", "COMPROMISED"):
        raise KeyLifecycleError(403, "KEY_REVOKED", f"Key version {key_version} is {rec.state}.")
    if rec.state == "ROTATING":
        in_flight_rot = db.scalar(
            select(RotationOperation).where(
                RotationOperation.from_key_id == rec.key_id,
                RotationOperation.status == "IN_PROGRESS",
            )
        )
        allowed_pre_commit = in_flight_rot is not None and not in_flight_rot.committed
        allowed_transfer = (
            in_flight_rot is not None
            and in_flight_rot.committed
            and in_flight_rot.grace_policy == "CONTROLLED_IN_FLIGHT_ONLY"
            and db.scalar(
                select(InFlightTransfer.transfer_id).where(
                    InFlightTransfer.key_version == key_version,
                    InFlightTransfer.state == "STARTED",
                    InFlightTransfer.allow_post_cutoff.is_(True),
                )
            )
            is not None
        )
        if not allowed_pre_commit and not allowed_transfer:
            raise KeyLifecycleError(409, "KEY_NOT_ACTIVE", f"Key version {key_version} is rotating past cutoff.")
    elif rec.state not in ("ACTIVE", "ACTIVE_NEW"):
        raise KeyLifecycleError(409, "KEY_NOT_ACTIVE", f"Key version {key_version} is not ACTIVE (state: {rec.state}).")
    if rec.purpose not in KEY_PURPOSES:
        raise KeyLifecycleError(500, "INVALID_KEY_PURPOSE", "Unsupported key purpose.")
    return rec
