"""Authorized revocation event coordinator, central enforcement, and node broadcast."""

from __future__ import annotations

import base64
import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.audit.ledger import append_audit_event, audit_write_lock
from backend.app.crypto.keystore import KeyStoreError, LocalEncryptedKeyStore
from backend.app.crypto.mldsa import MLDSA65Provider
from backend.app.db.models import (
    Device,
    DeviceStateHistory,
    KeyMetadata,
    NodeEventInbox,
    RevocationEvent,
    RevocationTombstone,
    User,
    UserSession,
    utc_now,
)
from backend.app.keys.lifecycle import validate_key_transition
from backend.app.nodes.simulator import (
    MIN_NODE_COUNT,
    NodeSimulatorError,
    compute_canonical_event_digest,
    list_nodes,
    measure_event_convergence,
    propagate_pending_events,
)
from backend.app.schemas.nodes import ConvergenceReportOut


def _sign_event_digest(keystore: LocalEncryptedKeyStore, digest_hex: str) -> str:
    try:
        sk_bytes = keystore.get_secret_bytes("key-revocation-signer-v1", expected_purpose="signing")
        sig_bytes = MLDSA65Provider.sign(sk_bytes, digest_hex.encode("utf-8"))
        return base64.b64encode(sig_bytes).decode("ascii")
    except KeyStoreError as exc:
        raise NodeSimulatorError(503, "SIGNING_KEY_UNAVAILABLE", "Control-plane signing key unavailable.") from exc


def issue_revocation_event(
    db: Session,
    keystore: LocalEncryptedKeyStore,
    *,
    subject_type: str,
    subject_id: str,
    reason: str,
    confirmation: bool,
    acting_user: User,
    correlation_id: str,
    sim_clock_ms: int | None = None,
    auto_propagate: bool = True,
) -> tuple[RevocationEvent, ConvergenceReportOut]:
    """Apply atomic central revocation + tombstone, emit signed RevocationEvent, and broadcast to nodes."""
    if not confirmation:
        raise NodeSimulatorError(400, "CONFIRMATION_REQUIRED", "Explicit confirmation is required to issue revocation.")

    nodes = list_nodes(db)
    if len(nodes) < MIN_NODE_COUNT:
        raise NodeSimulatorError(409, "INSUFFICIENT_NODES", "At least 3 simulated nodes must be registered.")

    now = utc_now()

    # 1. Validate target and apply immediate central revocation inside DB transaction
    if subject_type == "actor":
        target_user = db.get(User, subject_id)
        if target_user is None:
            raise NodeSimulatorError(404, "SUBJECT_NOT_FOUND", f"Identity '{subject_id}' does not exist.")
        target_user.enabled = False
        for sess in db.scalars(
            select(UserSession).where(UserSession.actor_id == subject_id, UserSession.state == "ACTIVE")
        ).all():
            sess.state = "REVOKED"
            sess.revoked_at = now
            sess.revoke_reason = f"Actor revoked: {reason}"

    elif subject_type == "device":
        target_device = db.get(Device, subject_id)
        if target_device is None:
            raise NodeSimulatorError(404, "SUBJECT_NOT_FOUND", f"Device '{subject_id}' does not exist.")
        if target_device.state != "REVOKED":
            prev = target_device.state
            target_device.state = "REVOKED"
            target_device.state_version += 1
            target_device.revoked_at = now
            target_device.reason = reason
            db.add(
                DeviceStateHistory(
                    device_id=target_device.id,
                    from_state=prev,
                    to_state="REVOKED",
                    state_version=target_device.state_version,
                    changed_by=acting_user.id,
                    reason=reason,
                    correlation_id=correlation_id,
                    created_at=now,
                )
            )
        for sess in db.scalars(
            select(UserSession).where(UserSession.device_id == subject_id, UserSession.state == "ACTIVE")
        ).all():
            sess.state = "REVOKED"
            sess.revoked_at = now
            sess.revoke_reason = f"Device revoked: {reason}"

    elif subject_type == "key":
        target_key = db.get(KeyMetadata, subject_id)
        if target_key is None:
            raise NodeSimulatorError(404, "SUBJECT_NOT_FOUND", f"Key '{subject_id}' does not exist.")
        if target_key.state not in ("REVOKED", "COMPROMISED"):
            validate_key_transition(target_key.state, "REVOKED")
            target_key.state = "REVOKED"
            target_key.revoked_at = now

    elif subject_type == "session":
        target_sess = db.get(UserSession, subject_id)
        if target_sess is None:
            raise NodeSimulatorError(404, "SUBJECT_NOT_FOUND", f"Session '{subject_id}' does not exist.")
        if target_sess.state != "REVOKED":
            target_sess.state = "REVOKED"
            target_sess.revoked_at = now
            target_sess.revoke_reason = reason
    else:
        raise NodeSimulatorError(400, "INVALID_SUBJECT_TYPE", f"Unsupported revocation subject_type: {subject_type}")

    # 1b. Immediately invalidate active/suspended E2E messaging sessions for revoked actor/device/key
    from backend.app.messaging.session_manager import invalidate_messaging_sessions_for_subject

    invalidate_messaging_sessions_for_subject(
        db,
        keystore,
        subject_type=subject_type,
        subject_id=subject_id,
        reason=reason,
    )

    # 2. Write / increment durable RevocationTombstone
    next_seq = int(db.scalar(select(func.coalesce(func.max(RevocationEvent.sequence_number), 0))) or 0) + 1
    existing_tombstone = db.scalar(
        select(RevocationTombstone).where(
            RevocationTombstone.target_type == subject_type,
            RevocationTombstone.target_id == subject_id,
        )
    )
    if existing_tombstone is None:
        db.add(
            RevocationTombstone(
                target_type=subject_type,
                target_id=subject_id,
                revocation_epoch=next_seq,
                reason=reason,
                created_at=now,
            )
        )
    else:
        existing_tombstone.revocation_epoch = next_seq
        existing_tombstone.reason = reason

    # 3. Create durable signed RevocationEvent
    last_clock = int(db.scalar(select(func.coalesce(func.max(RevocationEvent.sim_clock_ms), 0))) or 0)
    chosen_clock = sim_clock_ms if sim_clock_ms is not None else (last_clock + 1000)

    event = RevocationEvent(
        event_id=f"rev-evt-{next_seq:04d}-{uuid.uuid4().hex[:8]}",
        sequence_number=next_seq,
        event_type="REVOCATION_ISSUED",
        subject_type=subject_type,
        subject_id=subject_id,
        reason=reason,
        issued_by=acting_user.id,
        correlation_id=correlation_id,
        sim_clock_ms=chosen_clock,
        created_at=now,
        integrity_sha256="",
        signature_b64="",
    )
    event.integrity_sha256 = compute_canonical_event_digest(event)
    event.signature_b64 = _sign_event_digest(keystore, event.integrity_sha256)
    db.add(event)
    db.flush()

    # 4. Enqueue event into each node's independent inbox
    for node in nodes:
        node.sync_status = "UNSYNCHRONIZED"
        db.add(
            NodeEventInbox(
                node_id=node.node_id,
                event_id=event.event_id,
                sequence_number=event.sequence_number,
                delivery_status="QUEUED",
                enqueued_at_ms=chosen_clock,
                detail="Queued for node propagation",
            )
        )

    with audit_write_lock():
        append_audit_event(
            db,
            event_type="REVOCATION_ISSUED",
            event_category="NODE",
            actor_id=acting_user.id,
            action="issue_revocation",
            target_type=subject_type,
            target_id=subject_id,
            outcome="ALLOW",
            reason_code="REVOCATION_BROADCAST_QUEUED",
            correlation_id=correlation_id,
            source_component="revocation_coordinator",
            payload={"event_id": event.event_id, "sequence_number": event.sequence_number, "reason": reason},
            commit=False,
        )
        db.commit()
    db.refresh(event)

    if auto_propagate:
        propagate_pending_events(db, sim_clock_ms=chosen_clock)

    convergence = measure_event_convergence(db, event.event_id, correlation_id=correlation_id)
    append_audit_event(
        db,
        event_type="REVOCATION_CONVERGENCE",
        event_category="NODE",
        actor_id=acting_user.id,
        action="measure_convergence",
        target_type="revocation_event",
        target_id=event.event_id,
        outcome="ALLOW" if convergence.converged else "PARTIAL",
        reason_code="CONVERGENCE_COMPLETE" if convergence.converged else "CONVERGENCE_PARTIAL",
        correlation_id=correlation_id,
        source_component="revocation_coordinator",
        payload={
            "converged": convergence.converged,
            "convergence_time_ms": convergence.convergence_time_ms,
            "total_nodes": convergence.total_nodes,
            "converged_nodes": convergence.converged_nodes,
        },
        commit=True,
    )
    return event, convergence
