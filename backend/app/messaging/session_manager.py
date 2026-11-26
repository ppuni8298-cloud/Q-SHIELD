"""Explicit E2E CryptoSession state machine, establishment, suspension, resumption & revocation."""

from __future__ import annotations

from datetime import timedelta
import json
import secrets
import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.audit.ledger import append_audit_event, audit_write_lock
from backend.app.auth.tokens import ensure_utc, hash_token, verify_token_hash
from backend.app.crypto.hmac_hash import sha256_hex
from backend.app.crypto.keystore import KeyStoreError, LocalEncryptedKeyStore
from backend.app.db.models import (
    CryptoSession,
    Device,
    KeyMetadata,
    NodeRegistry,
    RevocationTombstone,
    User,
    utc_now,
)
from backend.app.messaging.crypto_channel import (
    MessagingError,
    create_resumption_token,
    derive_session_generation_keys,
    parse_and_verify_resumption_token,
    run_ephemeral_mlkem768_exchange,
)
from backend.app.nodes.simulator import parse_local_revocations

SESSION_STATES = (
    "NEW",
    "NEGOTIATING",
    "ESTABLISHED",
    "SUSPENDED",
    "RESUMING",
    "EXPIRED",
    "REVOKED",
    "COMPROMISED",
)

SESSION_ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    "NEW": frozenset({"NEGOTIATING", "REVOKED", "COMPROMISED"}),
    "NEGOTIATING": frozenset({"ESTABLISHED", "EXPIRED", "REVOKED", "COMPROMISED"}),
    "ESTABLISHED": frozenset({"SUSPENDED", "EXPIRED", "REVOKED", "COMPROMISED"}),
    "SUSPENDED": frozenset({"RESUMING", "EXPIRED", "REVOKED", "COMPROMISED"}),
    "RESUMING": frozenset({"ESTABLISHED", "SUSPENDED", "EXPIRED", "REVOKED", "COMPROMISED"}),
    "EXPIRED": frozenset({"REVOKED", "COMPROMISED"}),
    "REVOKED": frozenset(),
    "COMPROMISED": frozenset(),
}


def chain_keystore_id(session_id: str, generation: int) -> str:
    return f"msg-chain:{session_id}:gen{generation}"


def resumption_mac_keystore_id(session_id: str) -> str:
    return f"msg-resmac:{session_id}"


def msg_key_keystore_id(message_id: str) -> str:
    return f"msg-key:{message_id}"


def validate_session_transition(current_state: str, target_state: str) -> None:
    if current_state not in SESSION_ALLOWED_TRANSITIONS:
        raise MessagingError(409, "INVALID_SESSION_STATE", f"Unknown session state '{current_state}'.")
    if target_state not in SESSION_ALLOWED_TRANSITIONS[current_state]:
        raise MessagingError(
            409,
            "ILLEGAL_SESSION_TRANSITION",
            f"Cannot transition messaging session from '{current_state}' to '{target_state}'.",
        )


def resolve_active_messaging_key(db: Session, requested_version: int | None = None) -> KeyMetadata:
    """Resolve and verify an active, unrevoked messaging key version."""
    if requested_version is not None:
        row = db.scalar(
            select(KeyMetadata).where(
                KeyMetadata.purpose == "messaging",
                KeyMetadata.version == requested_version,
            )
        )
    else:
        row = db.scalar(
            select(KeyMetadata)
            .where(KeyMetadata.purpose == "messaging", KeyMetadata.state.in_(("ACTIVE", "ACTIVE_NEW")))
            .order_by(KeyMetadata.version.desc())
        )
        if row is None:
            # Bootstrap messaging v1 metadata safely ONLY if no messaging keys exist yet
            existing_any = db.scalar(select(KeyMetadata).where(KeyMetadata.purpose == "messaging").order_by(KeyMetadata.version.desc()))
            if existing_any is None:
                now = utc_now()
                row = KeyMetadata(
                    key_id="key-messaging-v1",
                    purpose="messaging",
                    algorithm="ML-KEM-768+HKDF-SHA-256+AES-256-GCM",
                    version=1,
                    state="ACTIVE",
                    created_at=now,
                    activated_at=now,
                )
                db.add(row)
                db.flush()
            else:
                row = existing_any

    if row is None:
        raise MessagingError(403, "DENY_KEY_NOT_FOUND", "Requested messaging key version does not exist.")
    tomb = db.scalar(
        select(RevocationTombstone).where(
            RevocationTombstone.target_type == "key",
            RevocationTombstone.target_id == row.key_id,
        )
    )
    if tomb is not None or row.state not in ("ACTIVE", "ACTIVE_NEW"):
        raise MessagingError(403, "DENY_KEY_REVOKED_OR_INACTIVE", f"Messaging key '{row.key_id}' is not active ({row.state}).")
    return row


def verify_messaging_peers_and_trust(
    db: Session,
    *,
    initiator_id: str,
    initiator_device_id: str,
    recipient_id: str,
    recipient_device_id: str,
    key_version: int,
) -> KeyMetadata:
    """Enforce zero-trust checks across both peers, devices, tombstones, key metadata, and simulated nodes."""
    if initiator_id == recipient_id:
        raise MessagingError(400, "INVALID_PEER_PAIR", "Sender and recipient must be distinct identities.")

    for role_label, uid, did in (
        ("initiator", initiator_id, initiator_device_id),
        ("recipient", recipient_id, recipient_device_id),
    ):
        user = db.get(User, uid)
        if user is None or not user.enabled:
            raise MessagingError(403, "DENY_IDENTITY_DISABLED", f"{role_label.capitalize()} identity '{uid}' is missing or disabled.")
        actor_tomb = db.scalar(
            select(RevocationTombstone).where(RevocationTombstone.target_type == "actor", RevocationTombstone.target_id == uid)
        )
        if actor_tomb is not None:
            raise MessagingError(403, "DENY_IDENTITY_REVOKED", f"{role_label.capitalize()} identity '{uid}' has an active revocation tombstone.")

        device = db.get(Device, did)
        if device is None or device.owner_id != uid:
            raise MessagingError(403, "DENY_DEVICE_UNOWNED", f"Device '{did}' does not belong to {role_label} '{uid}'.")
        dev_tomb = db.scalar(
            select(RevocationTombstone).where(RevocationTombstone.target_type == "device", RevocationTombstone.target_id == did)
        )
        if dev_tomb is not None or device.state != "TRUSTED":
            raise MessagingError(403, "DENY_DEVICE_NOT_TRUSTED", f"Device '{did}' is in state '{device.state}' (must be TRUSTED).")

    key_row = resolve_active_messaging_key(db, requested_version=key_version)

    # Check converged simulated nodes for any local revocation tombstone on either peer, device, or key
    for node in db.scalars(select(NodeRegistry)).all():
        local_rev = parse_local_revocations(node.local_revocations_json)
        if initiator_id in local_rev["actor"] or recipient_id in local_rev["actor"]:
            raise MessagingError(403, "DENY_NODE_REVOKED_ACTOR", f"Simulated node '{node.node_id}' reports actor revocation.")
        if initiator_device_id in local_rev["device"] or recipient_device_id in local_rev["device"]:
            raise MessagingError(403, "DENY_NODE_REVOKED_DEVICE", f"Simulated node '{node.node_id}' reports device revocation.")
        if key_row.key_id in local_rev["key"]:
            raise MessagingError(403, "DENY_NODE_REVOKED_KEY", f"Simulated node '{node.node_id}' reports messaging key revocation.")

    return key_row


def establish_messaging_session(
    db: Session,
    keystore: LocalEncryptedKeyStore,
    *,
    initiator_id: str,
    initiator_device_id: str,
    recipient_id: str,
    recipient_device_id: str,
    ttl_seconds: int = 3600,
    recipient_kem_public_key_b64: str | None = None,
    correlation_id: str,
) -> tuple[CryptoSession, str, str]:
    """Execute ML-KEM-768 key establishment, HKDF derivation, state transitions, and initial resumption token."""
    key_row = resolve_active_messaging_key(db)
    verify_messaging_peers_and_trust(
        db,
        initiator_id=initiator_id,
        initiator_device_id=initiator_device_id,
        recipient_id=recipient_id,
        recipient_device_id=recipient_device_id,
        key_version=key_row.version,
    )

    now = utc_now()
    expires_at = now + timedelta(seconds=ttl_seconds)
    session_id = f"csess-{uuid.uuid4().hex[:16]}"
    peer_binding = f"{initiator_id}:{initiator_device_id}<->{recipient_id}:{recipient_device_id}"

    sess = CryptoSession(
        id=session_id,
        initiator_id=initiator_id,
        recipient_id=recipient_id,
        initiator_device_id=initiator_device_id,
        recipient_device_id=recipient_device_id,
        peer_binding=peer_binding,
        state="NEW",
        key_version=key_row.version,
        generation=1,
        send_sequence=0,
        recv_expected_sequence=1,
        kem_algorithm="ML-KEM-768",
        aead_algorithm="AES-256-GCM",
        kdf_algorithm="HKDF-SHA-256",
        resumption_token_hash="",
        resumption_counter=0,
        ephemeral_key_erased=True,
        forward_secrecy_status="PARTIAL_LOCAL_KEYSTORE",
        expires_at=expires_at,
        created_at=now,
        updated_at=now,
    )

    validate_session_transition(sess.state, "NEGOTIATING")
    sess.state = "NEGOTIATING"

    shared_secret, kem_ct_b64, transcript_hash = run_ephemeral_mlkem768_exchange(recipient_kem_public_key_b64)
    chain_key, res_mac_key = derive_session_generation_keys(
        shared_secret=shared_secret,
        session_id=session_id,
        initiator_id=initiator_id,
        recipient_id=recipient_id,
        key_version=key_row.version,
        generation=1,
    )
    # Erase raw shared_secret immediately after HKDF key separation
    del shared_secret

    try:
        keystore.put_secret_bytes(chain_keystore_id(session_id, 1), purpose="messaging", secret_bytes=chain_key)
        keystore.put_secret_bytes(resumption_mac_keystore_id(session_id), purpose="session", secret_bytes=res_mac_key)
    except KeyStoreError as exc:
        raise MessagingError(503, "KEYSTORE_UNAVAILABLE", str(exc)) from exc
    finally:
        del chain_key

    token_nonce = secrets.token_hex(16)
    res_token = create_resumption_token(
        mac_key=res_mac_key,
        session_id=session_id,
        initiator_id=initiator_id,
        recipient_id=recipient_id,
        initiator_device_id=initiator_device_id,
        recipient_device_id=recipient_device_id,
        generation=1,
        key_version=key_row.version,
        nonce_hex=token_nonce,
        issued_at_utc=now.isoformat(),
        expires_at_utc=expires_at.isoformat(),
    )
    del res_mac_key

    validate_session_transition(sess.state, "ESTABLISHED")
    sess.state = "ESTABLISHED"
    sess.resumption_token_hash = hash_token(res_token)
    sess.protocol_state_metadata = json.dumps(
        {
            "kem_transcript_sha256": transcript_hash.decode("utf-8"),
            "kem_ciphertext_bytes": len(kem_ct_b64),
            "key_id": key_row.key_id,
            "state_history": ["NEW", "NEGOTIATING", "ESTABLISHED"],
        },
        separators=(",", ":"),
        sort_keys=True,
    )

    with audit_write_lock():
        db.add(sess)
        append_audit_event(
            db,
            event_type="MSG_SESSION_ESTABLISHED",
            event_category="MESSAGING",
            actor_id=initiator_id,
            action="establish_messaging_session",
            target_type="crypto_session",
            target_id=session_id,
            outcome="ALLOW",
            reason_code="SESSION_ESTABLISHED_MLKEM768",
            correlation_id=correlation_id,
            source_component="messaging_service",
            payload={
                "initiator_id": initiator_id,
                "recipient_id": recipient_id,
                "key_version": key_row.version,
                "generation": 1,
                "ephemeral_key_erased": True,
                "forward_secrecy_status": sess.forward_secrecy_status,
            },
            commit=False,
        )
        db.commit()
    db.refresh(sess)
    return sess, res_token, kem_ct_b64


def suspend_messaging_session(
    db: Session,
    *,
    session_id: str,
    actor_id: str,
    reason: str,
    confirmation: bool,
    is_operator: bool,
    correlation_id: str,
) -> CryptoSession:
    if not confirmation:
        raise MessagingError(400, "CONFIRMATION_REQUIRED", "Explicit confirmation is required to suspend a messaging session.")
    sess = db.get(CryptoSession, session_id)
    if sess is None:
        raise MessagingError(404, "SESSION_NOT_FOUND", f"Messaging session '{session_id}' does not exist.")
    if not is_operator and actor_id not in (sess.initiator_id, sess.recipient_id):
        raise MessagingError(403, "DENY_NOT_SESSION_PEER", "Caller is not an authorized peer of this session.")

    validate_session_transition(sess.state, "SUSPENDED")
    now = utc_now()
    sess.state = "SUSPENDED"
    sess.suspended_at = now
    sess.updated_at = now
    with audit_write_lock():
        append_audit_event(
            db,
            event_type="MSG_SESSION_SUSPENDED",
            event_category="MESSAGING",
            actor_id=actor_id,
            action="suspend_messaging_session",
            target_type="crypto_session",
            target_id=session_id,
            outcome="ALLOW",
            reason_code="SESSION_SUSPENDED",
            correlation_id=correlation_id,
            source_component="messaging_service",
            payload={"reason": reason, "generation": sess.generation},
            commit=False,
        )
        db.commit()
    db.refresh(sess)
    return sess


def revoke_messaging_session(
    db: Session,
    keystore: LocalEncryptedKeyStore,
    *,
    session_id: str,
    actor_id: str,
    reason: str,
    confirmation: bool,
    compromised: bool = False,
    is_operator: bool = True,
    correlation_id: str,
) -> CryptoSession:
    if not confirmation:
        raise MessagingError(400, "CONFIRMATION_REQUIRED", "Explicit confirmation is required to revoke a messaging session.")
    sess = db.get(CryptoSession, session_id)
    if sess is None:
        raise MessagingError(404, "SESSION_NOT_FOUND", f"Messaging session '{session_id}' does not exist.")
    if not is_operator and actor_id not in (sess.initiator_id, sess.recipient_id):
        raise MessagingError(403, "DENY_NOT_SESSION_PEER", "Caller is not authorized to revoke this session.")

    target = "COMPROMISED" if compromised else "REVOKED"
    if sess.state != target:
        validate_session_transition(sess.state, target)
    now = utc_now()
    sess.state = target
    sess.revoked_at = now
    sess.updated_at = now
    sess.resumption_token_hash = ""

    # Erase retained chain and resumption MAC secrets cleanly
    keystore.delete_keys_with_prefix(f"msg-chain:{session_id}:")
    keystore.delete_key(resumption_mac_keystore_id(session_id))

    with audit_write_lock():
        append_audit_event(
            db,
            event_type="MSG_SESSION_REVOKED",
            event_category="MESSAGING",
            actor_id=actor_id,
            action="revoke_messaging_session",
            target_type="crypto_session",
            target_id=session_id,
            outcome="ALLOW",
            reason_code=f"SESSION_{target}",
            correlation_id=correlation_id,
            source_component="messaging_service",
            payload={"reason": reason, "target_state": target},
            commit=False,
        )
        db.commit()
    db.refresh(sess)
    return sess


def invalidate_messaging_sessions_for_subject(
    db: Session,
    keystore: LocalEncryptedKeyStore,
    *,
    subject_type: str,
    subject_id: str,
    reason: str,
) -> int:
    """Propagate actor/device/key revocations immediately to active/suspended messaging sessions."""
    q = select(CryptoSession).where(CryptoSession.state.in_(("NEW", "NEGOTIATING", "ESTABLISHED", "SUSPENDED", "RESUMING")))
    if subject_type == "actor":
        q = q.where((CryptoSession.initiator_id == subject_id) | (CryptoSession.recipient_id == subject_id))
    elif subject_type == "device":
        q = q.where((CryptoSession.initiator_device_id == subject_id) | (CryptoSession.recipient_device_id == subject_id))
    elif subject_type == "key":
        krow = db.get(KeyMetadata, subject_id)
        if krow is None or krow.purpose != "messaging":
            return 0
        q = q.where(CryptoSession.key_version == krow.version)
    else:
        return 0

    now = utc_now()
    count = 0
    for sess in db.scalars(q).all():
        sess.state = "REVOKED"
        sess.revoked_at = now
        sess.updated_at = now
        sess.resumption_token_hash = ""
        keystore.delete_keys_with_prefix(f"msg-chain:{sess.id}:")
        keystore.delete_key(resumption_mac_keystore_id(sess.id))
        count += 1
    return count


def resume_messaging_session(
    db: Session,
    keystore: LocalEncryptedKeyStore,
    *,
    session_id: str,
    caller_id: str,
    caller_device_id: str,
    peer_id: str,
    resumption_token: str,
    correlation_id: str,
) -> tuple[CryptoSession, str, str]:
    """Perform peer-bound session resumption verifying all 7 security preconditions."""
    sess = db.get(CryptoSession, session_id)
    if sess is None:
        raise MessagingError(404, "SESSION_NOT_FOUND", f"Messaging session '{session_id}' does not exist.")

    def _deny_resume(status: int, code: str, msg: str) -> None:
        append_audit_event(
            db,
            event_type="MSG_SESSION_RESUME_DENIED",
            event_category="MESSAGING",
            actor_id=caller_id,
            action="resume_messaging_session",
            target_type="crypto_session",
            target_id=session_id,
            outcome="DENY",
            reason_code=code,
            correlation_id=correlation_id,
            source_component="messaging_service",
            payload={"peer_id": peer_id, "session_state": sess.state},
            commit=True,
        )
        raise MessagingError(status, code, msg)

    # 1. Session terminal/revoked/expired status checks
    if sess.state in ("REVOKED", "COMPROMISED"):
        _deny_resume(403, f"DENY_SESSION_{sess.state}", f"Session '{session_id}' is permanently {sess.state} and cannot resume.")
    now = utc_now()
    if sess.state == "EXPIRED" or ensure_utc(sess.expires_at) <= now:
        if sess.state != "EXPIRED":
            sess.state = "EXPIRED"
            sess.updated_at = now
            db.commit()
        _deny_resume(403, "DENY_SESSION_EXPIRED", f"Session '{session_id}' has expired.")
    if sess.state not in ("SUSPENDED", "ESTABLISHED"):
        _deny_resume(409, "INVALID_SESSION_STATE_FOR_RESUME", f"Session '{session_id}' cannot resume from state '{sess.state}'.")

    # 2. Original peer identity & device binding checks
    expected_pair = {(sess.initiator_id, sess.recipient_id), (sess.recipient_id, sess.initiator_id)}
    if (caller_id, peer_id) not in expected_pair:
        _deny_resume(403, "DENY_RESUMPTION_PEER_MISMATCH", "Caller and peer do not match original cryptographically bound session peers.")

    expected_dev = sess.initiator_device_id if caller_id == sess.initiator_id else sess.recipient_device_id
    if caller_device_id != expected_dev:
        _deny_resume(403, "DENY_RESUMPTION_DEVICE_MISMATCH", "Caller device does not match session's bound device.")

    # 3. Fresh zero-trust verification of both identities, devices, key, and simulated nodes
    try:
        verify_messaging_peers_and_trust(
            db,
            initiator_id=sess.initiator_id,
            initiator_device_id=sess.initiator_device_id,
            recipient_id=sess.recipient_id,
            recipient_device_id=sess.recipient_device_id,
            key_version=sess.key_version,
        )
    except MessagingError as exc:
        _deny_resume(exc.status_code, exc.code, exc.message)

    # 4. Single-use anti-replay check on stored hash
    if not sess.resumption_token_hash or not verify_token_hash(resumption_token, sess.resumption_token_hash):
        _deny_resume(409, "RESUMPTION_TOKEN_REPLAYED_OR_INVALID", "Resumption token is invalid, rotated, or already consumed (anti-replay).")

    # 5. Load HMAC verification key & validate resumption token integrity & peer claims
    try:
        res_mac_key = keystore.get_secret_bytes(resumption_mac_keystore_id(session_id), expected_purpose="session")
    except KeyStoreError as exc:
        _deny_resume(403, "RESUMPTION_KEY_MISSING", f"Resumption MAC key unavailable: {exc}")

    try:
        claims = parse_and_verify_resumption_token(res_mac_key, resumption_token)
    except MessagingError as exc:
        _deny_resume(exc.status_code, exc.code, exc.message)

    if (
        claims.get("session_id") != session_id
        or claims.get("initiator_id") != sess.initiator_id
        or claims.get("recipient_id") != sess.recipient_id
        or int(claims.get("generation", -1)) != sess.generation
        or int(claims.get("key_version", -1)) != sess.key_version
    ):
        _deny_resume(403, "RESUMPTION_BINDING_MISMATCH", "Resumption token claims mismatch active session binding.")

    # 6. Transition SUSPENDED -> RESUMING -> ESTABLISHED & perform fresh ML-KEM-768 re-keying
    if sess.state == "SUSPENDED":
        validate_session_transition(sess.state, "RESUMING")
        sess.state = "RESUMING"

    old_gen = sess.generation
    new_gen = old_gen + 1
    shared_secret, kem_ct_b64, transcript_hash = run_ephemeral_mlkem768_exchange()
    new_chain_key, new_res_mac_key = derive_session_generation_keys(
        shared_secret=shared_secret,
        session_id=session_id,
        initiator_id=sess.initiator_id,
        recipient_id=sess.recipient_id,
        key_version=sess.key_version,
        generation=new_gen,
    )
    del shared_secret

    try:
        keystore.put_secret_bytes(chain_keystore_id(session_id, new_gen), purpose="messaging", secret_bytes=new_chain_key)
        keystore.put_secret_bytes(resumption_mac_keystore_id(session_id), purpose="session", secret_bytes=new_res_mac_key)
        keystore.delete_key(chain_keystore_id(session_id, old_gen))
    finally:
        del new_chain_key

    next_token = create_resumption_token(
        mac_key=new_res_mac_key,
        session_id=session_id,
        initiator_id=sess.initiator_id,
        recipient_id=sess.recipient_id,
        initiator_device_id=sess.initiator_device_id,
        recipient_device_id=sess.recipient_device_id,
        generation=new_gen,
        key_version=sess.key_version,
        nonce_hex=secrets.token_hex(16),
        issued_at_utc=now.isoformat(),
        expires_at_utc=ensure_utc(sess.expires_at).isoformat(),
    )
    del new_res_mac_key

    if sess.state == "RESUMING":
        validate_session_transition(sess.state, "ESTABLISHED")
    sess.state = "ESTABLISHED"
    sess.generation = new_gen
    sess.resumption_counter += 1
    sess.resumption_token_hash = hash_token(next_token)
    sess.resumed_at = now
    sess.updated_at = now

    meta = json.loads(sess.protocol_state_metadata) if sess.protocol_state_metadata else {}
    meta["last_resume_kem_sha256"] = transcript_hash.decode("utf-8")
    hist = list(meta.get("state_history", []))
    hist.extend(["RESUMING", "ESTABLISHED"])
    meta["state_history"] = hist[-20:]
    sess.protocol_state_metadata = json.dumps(meta, separators=(",", ":"), sort_keys=True)

    with audit_write_lock():
        append_audit_event(
            db,
            event_type="MSG_SESSION_RESUMED",
            event_category="MESSAGING",
            actor_id=caller_id,
            action="resume_messaging_session",
            target_type="crypto_session",
            target_id=session_id,
            outcome="ALLOW",
            reason_code="SESSION_RESUMED_REKEYED",
            correlation_id=correlation_id,
            source_component="messaging_service",
            payload={"generation": new_gen, "key_version": sess.key_version, "resumption_counter": sess.resumption_counter},
            commit=False,
        )
        db.commit()
    db.refresh(sess)
    return sess, next_token, kem_ct_b64
