"""End-to-end encrypted messaging service: send, envelope verification, replay protection & decrypt."""

from __future__ import annotations

from datetime import timedelta
import json
import threading
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.audit.ledger import append_audit_event, audit_write_lock
from backend.app.auth.tokens import ensure_utc
from backend.app.crypto.hmac_hash import sha256_hex
from backend.app.crypto.keystore import KeyStoreError, LocalEncryptedKeyStore
from backend.app.db.models import CryptoSession, MessageDelivery, MessageRecord, NodeRegistry, ReplayRecord, utc_now
from backend.app.messaging.crypto_channel import (
    MESSAGE_AAD_SCHEMA_VERSION,
    MessagingError,
    build_message_aad_bytes,
    encrypt_message_envelope,
    ratchet_message_key,
    verify_and_decrypt_message_envelope,
)
from backend.app.messaging.session_manager import (
    chain_keystore_id,
    msg_key_keystore_id,
    verify_messaging_peers_and_trust,
)


def _select_relay_node(db: Session, requested_node_id: str | None = None) -> NodeRegistry:
    if requested_node_id:
        node = db.get(NodeRegistry, requested_node_id)
        if node is None:
            raise MessagingError(404, "NODE_NOT_FOUND", f"Relay node '{requested_node_id}' does not exist.")
        if not node.available or node.health in ("OFFLINE", "PARTITIONED"):
            raise MessagingError(503, "NODE_DISCONNECTED", f"Relay node '{node.node_id}' is disconnected ({node.health}).")
        return node
    node = db.scalar(
        select(NodeRegistry)
        .where(NodeRegistry.available.is_(True), NodeRegistry.health == "HEALTHY")
        .order_by(NodeRegistry.latency_ms.asc())
    )
    if node is None:
        raise MessagingError(503, "NO_HEALTHY_RELAY_NODE", "No healthy simulated relay node available.")
    return node


def send_encrypted_message(
    db: Session,
    keystore: LocalEncryptedKeyStore,
    *,
    session_id: str,
    sender_id: str,
    sender_device_id: str,
    plaintext: str,
    ttl_seconds: int = 300,
    explicit_message_id: str | None = None,
    explicit_nonce: bytes | None = None,
    relay_node_id: str | None = None,
    correlation_id: str,
) -> tuple[MessageRecord, MessageDelivery]:
    """Authenticate sender, advance HKDF ratchet, encrypt with AES-256-GCM AAD, and queue delivery."""
    sess = db.get(CryptoSession, session_id)
    if sess is None:
        raise MessagingError(404, "SESSION_NOT_FOUND", f"Messaging session '{session_id}' does not exist.")
    if sess.state != "ESTABLISHED":
        raise MessagingError(403, f"DENY_SESSION_{sess.state}", f"Session '{session_id}' is '{sess.state}' (must be ESTABLISHED).")

    now = utc_now()
    if ensure_utc(sess.expires_at) <= now:
        sess.state = "EXPIRED"
        sess.updated_at = now
        db.commit()
        raise MessagingError(403, "DENY_SESSION_EXPIRED", "Messaging session has expired.")

    if sender_id == sess.initiator_id:
        recipient_id = sess.recipient_id
        expected_sender_dev = sess.initiator_device_id
        recipient_dev = sess.recipient_device_id
    elif sender_id == sess.recipient_id:
        recipient_id = sess.initiator_id
        expected_sender_dev = sess.recipient_device_id
        recipient_dev = sess.initiator_device_id
    else:
        raise MessagingError(403, "DENY_SENDER_NOT_IN_SESSION", "Authenticated caller is not a peer in this session.")

    if sender_device_id != expected_sender_dev:
        raise MessagingError(403, "DENY_SENDER_DEVICE_MISMATCH", "Sender device does not match session binding.")

    verify_messaging_peers_and_trust(
        db,
        initiator_id=sender_id,
        initiator_device_id=sender_device_id,
        recipient_id=recipient_id,
        recipient_device_id=recipient_dev,
        key_version=sess.key_version,
    )

    msg_id = explicit_message_id or f"msg-{uuid.uuid4().hex[:16]}"
    if db.get(MessageRecord, msg_id) is not None:
        raise MessagingError(409, "DUPLICATE_MESSAGE_ID", f"Message ID '{msg_id}' already exists.")

    relay_node = _select_relay_node(db, relay_node_id)
    next_seq = sess.send_sequence + 1
    expires_at = now + timedelta(seconds=ttl_seconds)

    try:
        current_chain_key = keystore.get_secret_bytes(chain_keystore_id(session_id, sess.generation), expected_purpose="messaging")
    except KeyStoreError as exc:
        raise MessagingError(503, "SESSION_CHAIN_KEY_UNAVAILABLE", str(exc)) from exc

    msg_key, next_chain_key = ratchet_message_key(
        chain_key=current_chain_key,
        session_id=session_id,
        sender_id=sender_id,
        recipient_id=recipient_id,
        key_version=sess.key_version,
        generation=sess.generation,
        sequence=next_seq,
    )
    del current_chain_key

    try:
        envelope, nonce_b64 = encrypt_message_envelope(
            message_key=msg_key,
            plaintext=plaintext.encode("utf-8"),
            message_id=msg_id,
            session_id=session_id,
            session_generation=sess.generation,
            sequence=next_seq,
            sender_id=sender_id,
            recipient_id=recipient_id,
            key_version=sess.key_version,
            created_at_utc=now.isoformat(),
            expires_at_utc=expires_at.isoformat(),
            explicit_nonce=explicit_nonce,
        )
        # DB-level nonce uniqueness check inside same session
        dup_nonce = db.scalar(
            select(MessageRecord).where(MessageRecord.session_id == session_id, MessageRecord.nonce_b64 == nonce_b64)
        )
        if dup_nonce is not None:
            raise MessagingError(409, "NONCE_REUSE_REJECTED", "Duplicate nonce detected within session.")

        keystore.put_secret_bytes(chain_keystore_id(session_id, sess.generation), purpose="messaging", secret_bytes=next_chain_key)
        keystore.put_secret_bytes(msg_key_keystore_id(msg_id), purpose="messaging", secret_bytes=msg_key)
    finally:
        del msg_key
        del next_chain_key

    msg_row = MessageRecord(
        message_id=msg_id,
        sender_id=sender_id,
        recipient_id=recipient_id,
        session_id=session_id,
        sequence=next_seq,
        session_generation=sess.generation,
        key_version=sess.key_version,
        nonce_b64=nonce_b64,
        encrypted_envelope=json.dumps(envelope, separators=(",", ":"), sort_keys=True),
        status="QUEUED",
        ack_count=0,
        expires_at=expires_at,
        created_at=now,
    )
    delivery_row = MessageDelivery(
        delivery_id=f"deliv-{uuid.uuid4().hex[:14]}",
        message_id=msg_id,
        session_id=session_id,
        sequence=next_seq,
        relay_node_id=relay_node.node_id,
        simulation_mode="NORMAL",
        status="QUEUED",
        attempt_count=0,
        max_retries=3,
        simulated_delay_ms=relay_node.latency_ms,
        delivery_order_rank=next_seq,
        ack_count=0,
        duplicate_acks_ignored=0,
        detail=f"Encrypted envelope queued via {relay_node.node_id}",
        created_at=now,
        updated_at=now,
    )
    sess.send_sequence = next_seq
    sess.updated_at = now

    with audit_write_lock():
        db.add(msg_row)
        db.flush()
        db.add(delivery_row)
        append_audit_event(
            db,
            event_type="MSG_SENT",
            event_category="MESSAGING",
            actor_id=sender_id,
            action="send_message",
            target_type="message",
            target_id=msg_id,
            outcome="ALLOW",
            reason_code="MESSAGE_ENCRYPTED_QUEUED",
            correlation_id=correlation_id,
            source_component="messaging_service",
            payload={
                "session_id": session_id,
                "recipient_id": recipient_id,
                "sequence": next_seq,
                "generation": sess.generation,
                "key_version": sess.key_version,
                "relay_node_id": relay_node.node_id,
                "ciphertext_sha256": sha256_hex(envelope["ciphertext_b64"].encode("utf-8")),
            },
            commit=False,
        )
        db.commit()
    db.refresh(msg_row)
    db.refresh(delivery_row)
    return msg_row, delivery_row


def verify_message_integrity_only(
    db: Session,
    *,
    message_id: str,
    expected_recipient_id: str | None = None,
) -> dict:
    """Verify envelope metadata, AAD digest, expiry, session & key status, and replay state without decrypting."""
    msg = db.get(MessageRecord, message_id)
    if msg is None:
        raise MessagingError(404, "MESSAGE_NOT_FOUND", f"Message '{message_id}' does not exist.")
    sess = db.get(CryptoSession, msg.session_id)
    env = json.loads(msg.encrypted_envelope)

    reasons: list[str] = []
    aad_valid = False
    try:
        aad_bytes = build_message_aad_bytes(
            schema_version=str(env.get("schema_version", "")),
            sender_id=str(env.get("sender_id", "")),
            recipient_id=str(env.get("recipient_id", "")),
            message_id=str(env.get("message_id", "")),
            session_id=str(env.get("session_id", "")),
            session_generation=int(env.get("session_generation", -1)),
            sequence=int(env.get("sequence", -1)),
            key_version=int(env.get("key_version", -1)),
            algorithm=str(env.get("algorithm", "")),
            nonce_b64=str(env.get("nonce_b64", "")),
            created_at_utc=str(env.get("created_at_utc", "")),
            expires_at_utc=str(env.get("expires_at_utc", "")),
        )
        aad_valid = sha256_hex(aad_bytes) == env.get("aad_sha256")
        if not aad_valid:
            reasons.append("AAD_METADATA_MISMATCH")
    except (ValueError, TypeError):
        reasons.append("MALFORMED_ENVELOPE")

    if env.get("schema_version") != MESSAGE_AAD_SCHEMA_VERSION:
        reasons.append("UNSUPPORTED_SCHEMA")
    if expected_recipient_id and env.get("recipient_id") != expected_recipient_id:
        reasons.append("RECIPIENT_BINDING_MISMATCH")
    if ensure_utc(msg.expires_at) <= utc_now():
        reasons.append("MESSAGE_EXPIRED")
    if sess is None or sess.state in ("REVOKED", "COMPROMISED", "EXPIRED"):
        reasons.append(f"SESSION_INVALID_{sess.state if sess else 'MISSING'}")

    replay_hit = db.scalar(
        select(ReplayRecord).where(
            ReplayRecord.recipient_id == msg.recipient_id,
            ReplayRecord.session_id == msg.session_id,
            ReplayRecord.sequence_or_msg_id == f"msg:{msg.message_id}",
            ReplayRecord.accepted.is_(True),
        )
    )
    return {
        "message_id": msg.message_id,
        "session_id": msg.session_id,
        "sender_id": msg.sender_id,
        "recipient_id": msg.recipient_id,
        "key_version": msg.key_version,
        "sequence": msg.sequence,
        "aad_valid": aad_valid,
        "already_consumed": replay_hit is not None,
        "verified": aad_valid and len(reasons) == 0,
        "failure_reasons": reasons,
    }


def _record_replay_denial(
    db: Session,
    *,
    recipient_id: str,
    session_id: str,
    key_token: str,
    actor_id: str,
    reason_code: str,
    correlation_id: str,
) -> None:
    existing = db.scalar(
        select(ReplayRecord).where(
            ReplayRecord.recipient_id == recipient_id,
            ReplayRecord.session_id == session_id,
            ReplayRecord.sequence_or_msg_id == key_token,
        )
    )
    if existing is not None:
        existing.attempt_count += 1
        existing.recorded_at = utc_now()
    with audit_write_lock():
        append_audit_event(
            db,
            event_type="MSG_REPLAY_REJECTED",
            event_category="MESSAGING",
            actor_id=actor_id,
            action="receive_message",
            target_type="message",
            target_id=key_token,
            outcome="DENY",
            reason_code=reason_code,
            correlation_id=correlation_id,
            source_component="messaging_service",
            payload={"session_id": session_id, "recipient_id": recipient_id, "reason_code": reason_code},
            commit=False,
        )
        db.commit()


_MESSAGE_RECEIVE_LOCK = threading.RLock()


def receive_and_decrypt_message(
    db: Session,
    keystore: LocalEncryptedKeyStore,
    *,
    message_id: str,
    caller_id: str,
    caller_device_id: str,
    correlation_id: str,
) -> tuple[MessageRecord, str]:
    """Enforce recipient binding, expiry, trust, and replay ledger BEFORE AES-GCM decryption & key erasure."""
    with _MESSAGE_RECEIVE_LOCK:
        return _receive_and_decrypt_locked(
            db,
            keystore,
            message_id=message_id,
            caller_id=caller_id,
            caller_device_id=caller_device_id,
            correlation_id=correlation_id,
        )


def _receive_and_decrypt_locked(
    db: Session,
    keystore: LocalEncryptedKeyStore,
    *,
    message_id: str,
    caller_id: str,
    caller_device_id: str,
    correlation_id: str,
) -> tuple[MessageRecord, str]:
    msg = db.get(MessageRecord, message_id)
    if msg is None:
        raise MessagingError(404, "MESSAGE_NOT_FOUND", f"Message '{message_id}' does not exist.")

    sess = db.get(CryptoSession, msg.session_id)
    if sess is None:
        raise MessagingError(404, "SESSION_NOT_FOUND", f"Session '{msg.session_id}' does not exist.")

    # 1. Intended recipient binding check BEFORE touching key material or ciphertext
    if caller_id != msg.recipient_id:
        append_audit_event(
            db,
            event_type="MSG_RECIPIENT_DENIED",
            event_category="MESSAGING",
            actor_id=caller_id,
            action="receive_message",
            target_type="message",
            target_id=message_id,
            outcome="DENY",
            reason_code="DENY_WRONG_RECIPIENT",
            correlation_id=correlation_id,
            source_component="messaging_service",
            payload={"expected_recipient": msg.recipient_id, "session_id": msg.session_id},
            commit=True,
        )
        raise MessagingError(403, "DENY_WRONG_RECIPIENT", "Encrypted message cannot be decrypted by a non-recipient.")

    expected_rec_dev = sess.recipient_device_id if msg.recipient_id == sess.recipient_id else sess.initiator_device_id
    if caller_device_id != expected_rec_dev:
        raise MessagingError(403, "DENY_RECIPIENT_DEVICE_MISMATCH", "Caller device does not match session's recipient device.")

    # 2. Session state & trust checks
    if sess.state != "ESTABLISHED":
        raise MessagingError(403, f"DENY_SESSION_{sess.state}", f"Session '{sess.id}' is '{sess.state}'; cannot receive message.")

    now = utc_now()
    if ensure_utc(sess.expires_at) <= now:
        sess.state = "EXPIRED"
        sess.updated_at = now
        db.commit()
        raise MessagingError(403, "DENY_SESSION_EXPIRED", "Messaging session expired prior to delivery.")

    if ensure_utc(msg.expires_at) <= now:
        msg.status = "EXPIRED"
        db.commit()
        append_audit_event(
            db,
            event_type="MSG_EXPIRED",
            event_category="MESSAGING",
            actor_id=caller_id,
            action="receive_message",
            target_type="message",
            target_id=message_id,
            outcome="DENY",
            reason_code="DENY_MESSAGE_EXPIRED",
            correlation_id=correlation_id,
            source_component="messaging_service",
            payload={"session_id": sess.id},
            commit=True,
        )
        raise MessagingError(403, "DENY_MESSAGE_EXPIRED", "Message TTL expired before delivery; rejected.")

    other_peer = sess.initiator_id if caller_id == sess.recipient_id else sess.recipient_id
    other_dev = sess.initiator_device_id if caller_id == sess.recipient_id else sess.recipient_device_id
    verify_messaging_peers_and_trust(
        db,
        initiator_id=other_peer,
        initiator_device_id=other_dev,
        recipient_id=caller_id,
        recipient_device_id=caller_device_id,
        key_version=sess.key_version,
    )

    # 3. Parse envelope cleanly & check durable replay ledger BEFORE decrypting
    try:
        envelope = json.loads(msg.encrypted_envelope)
    except ValueError as exc:
        raise MessagingError(400, "MALFORMED_ENVELOPE", "Encrypted message envelope JSON is invalid.") from exc

    msg_replay_key = f"msg:{msg.message_id}"
    seq_replay_key = f"seq:{envelope.get('session_generation', msg.session_generation)}:{envelope.get('sequence', msg.sequence)}"

    existing_msg_replay = db.scalar(
        select(ReplayRecord).where(
            ReplayRecord.recipient_id == caller_id,
            ReplayRecord.session_id == sess.id,
            ReplayRecord.sequence_or_msg_id == msg_replay_key,
            ReplayRecord.accepted.is_(True),
        )
    )
    if existing_msg_replay is not None:
        _record_replay_denial(
            db,
            recipient_id=caller_id,
            session_id=sess.id,
            key_token=msg_replay_key,
            actor_id=caller_id,
            reason_code="REPLAY_DETECTED",
            correlation_id=correlation_id,
        )
        raise MessagingError(409, "REPLAY_DETECTED", f"Message '{message_id}' was already accepted and cannot be replayed.")

    existing_seq_replay = db.scalar(
        select(ReplayRecord).where(
            ReplayRecord.recipient_id == caller_id,
            ReplayRecord.session_id == sess.id,
            ReplayRecord.sequence_or_msg_id == seq_replay_key,
            ReplayRecord.accepted.is_(True),
        )
    )
    if existing_seq_replay is not None:
        _record_replay_denial(
            db,
            recipient_id=caller_id,
            session_id=sess.id,
            key_token=seq_replay_key,
            actor_id=caller_id,
            reason_code="REPLAY_DETECTED",
            correlation_id=correlation_id,
        )
        raise MessagingError(409, "REPLAY_DETECTED", f"Sequence '{seq_replay_key}' was already consumed in session '{sess.id}'.")

    # 4. Fetch per-message key, authenticate metadata & decrypt
    try:
        msg_key = keystore.get_secret_bytes(msg_key_keystore_id(msg.message_id), expected_purpose="messaging")
    except KeyStoreError as exc:
        raise MessagingError(403, "MESSAGE_KEY_ERASED_OR_MISSING", "Per-message key is unavailable or already erased.") from exc

    try:
        plaintext_bytes = verify_and_decrypt_message_envelope(
            message_key=msg_key,
            envelope=envelope,
            expected_sender_id=msg.sender_id,
            expected_recipient_id=msg.recipient_id,
            expected_session_id=msg.session_id,
            expected_key_version=sess.key_version,
        )
    except MessagingError as exc:
        del msg_key
        append_audit_event(
            db,
            event_type="MSG_DECRYPT_FAILED",
            event_category="MESSAGING",
            actor_id=caller_id,
            action="receive_message",
            target_type="message",
            target_id=message_id,
            outcome="DENY",
            reason_code=exc.code,
            correlation_id=correlation_id,
            source_component="messaging_service",
            payload={"session_id": sess.id, "error": exc.message},
            commit=True,
        )
        raise
    finally:
        if "msg_key" in locals():
            del msg_key

    # 5. Erase single-use per-message encryption key & persist durable ReplayRecords atomically
    keystore.delete_key(msg_key_keystore_id(msg.message_id))

    msg.status = "DELIVERED"
    msg.delivered_at = now
    deliv = db.scalar(select(MessageDelivery).where(MessageDelivery.message_id == msg.message_id))
    if deliv is not None and deliv.status in ("QUEUED", "IN_TRANSIT", "DELAYED", "REORDERED"):
        deliv.status = "DELIVERED"
        deliv.updated_at = now
        deliv.attempt_count += 1

    if int(envelope.get("sequence", msg.sequence)) >= sess.recv_expected_sequence:
        sess.recv_expected_sequence = int(envelope.get("sequence", msg.sequence)) + 1
    sess.updated_at = now

    with audit_write_lock():
        db.add(
            ReplayRecord(
                recipient_id=caller_id,
                session_id=sess.id,
                sequence_or_msg_id=msg_replay_key,
                accepted=True,
                reason_code="ACCEPTED",
                attempt_count=1,
                recorded_at=now,
                expires_at=ensure_utc(msg.expires_at),
            )
        )
        db.add(
            ReplayRecord(
                recipient_id=caller_id,
                session_id=sess.id,
                sequence_or_msg_id=seq_replay_key,
                accepted=True,
                reason_code="ACCEPTED",
                attempt_count=1,
                recorded_at=now,
                expires_at=ensure_utc(msg.expires_at),
            )
        )
        append_audit_event(
            db,
            event_type="MSG_DELIVERED",
            event_category="MESSAGING",
            actor_id=caller_id,
            action="receive_message",
            target_type="message",
            target_id=message_id,
            outcome="ALLOW",
            reason_code="DECRYPTION_AUTHORIZED",
            correlation_id=correlation_id,
            source_component="messaging_service",
            payload={
                "session_id": sess.id,
                "sequence": msg.sequence,
                "generation": msg.session_generation,
                "per_message_key_erased": True,
            },
            commit=False,
        )
        db.commit()
    db.refresh(msg)
    return msg, plaintext_bytes.decode("utf-8")
