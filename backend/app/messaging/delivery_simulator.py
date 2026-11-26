"""Deterministic delivery reliability simulator reusing the Phase 4 simulated node registry.

Supports configurable packet loss with bounded retries, delay, out-of-order recovery buffering,
duplicate rejection, node disconnection/reconnection, and idempotent acknowledgements.
Does NOT claim guaranteed delivery beyond configured max_retries.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.audit.ledger import append_audit_event, audit_write_lock
from backend.app.crypto.keystore import LocalEncryptedKeyStore
from backend.app.db.models import MessageDelivery, MessageRecord, NodeRegistry, utc_now
from backend.app.messaging.crypto_channel import MessagingError
from backend.app.messaging.message_service import receive_and_decrypt_message, verify_message_integrity_only


def acknowledge_message_delivery(
    db: Session,
    *,
    message_id: str,
    actor_id: str,
    is_operator: bool,
    correlation_id: str,
) -> tuple[MessageRecord, MessageDelivery, bool]:
    """Record delivery acknowledgement idempotently; returns (msg, delivery, was_duplicate_ignored)."""
    msg = db.get(MessageRecord, message_id)
    if msg is None:
        raise MessagingError(404, "MESSAGE_NOT_FOUND", f"Message '{message_id}' does not exist.")
    if not is_operator and actor_id != msg.recipient_id:
        raise MessagingError(403, "DENY_ACK_WRONG_RECIPIENT", "Only the intended recipient or authorized operator can acknowledge delivery.")

    deliv = db.scalar(select(MessageDelivery).where(MessageDelivery.message_id == message_id))
    if deliv is None:
        raise MessagingError(404, "DELIVERY_RECORD_NOT_FOUND", f"No delivery record found for '{message_id}'.")

    now = utc_now()
    if deliv.ack_count >= 1:
        deliv.duplicate_acks_ignored += 1
        deliv.status = "DUPLICATE_ACK_IGNORED"
        deliv.detail = f"Duplicate acknowledgement ignored cleanly (original ack_count={deliv.ack_count})."
        deliv.updated_at = now
        with audit_write_lock():
            append_audit_event(
                db,
                event_type="MSG_DUPLICATE_ACK_IGNORED",
                event_category="MESSAGING",
                actor_id=actor_id,
                action="ack_message",
                target_type="message",
                target_id=message_id,
                outcome="ALLOW",
                reason_code="DUPLICATE_ACK_IGNORED",
                correlation_id=correlation_id,
                source_component="delivery_simulator",
                payload={"duplicate_acks_ignored": deliv.duplicate_acks_ignored},
                commit=False,
            )
            db.commit()
        db.refresh(deliv)
        return msg, deliv, True

    deliv.ack_count = 1
    deliv.acked_at = now
    deliv.status = "ACKED"
    deliv.updated_at = now
    msg.ack_count = 1
    msg.acknowledged_at = now
    msg.status = "ACKED"

    with audit_write_lock():
        append_audit_event(
            db,
            event_type="MSG_DELIVERY_ACKED",
            event_category="MESSAGING",
            actor_id=actor_id,
            action="ack_message",
            target_type="message",
            target_id=message_id,
            outcome="ALLOW",
            reason_code="DELIVERY_ACKNOWLEDGED",
            correlation_id=correlation_id,
            source_component="delivery_simulator",
            payload={"relay_node_id": deliv.relay_node_id, "attempts": deliv.attempt_count},
            commit=False,
        )
        db.commit()
    db.refresh(msg)
    db.refresh(deliv)
    return msg, deliv, False


def simulate_packet_loss_and_retry(
    db: Session,
    *,
    message_id: str,
    drop_attempts: int,
    max_retries: int,
    delay_ms: int = 0,
    disconnect_node_first: bool = False,
    reconnect_after: bool = False,
    actor_id: str,
    correlation_id: str,
) -> MessageDelivery:
    """Deterministically simulate packet loss / node disconnect & bounded retry recovery."""
    deliv = db.scalar(select(MessageDelivery).where(MessageDelivery.message_id == message_id))
    msg = db.get(MessageRecord, message_id)
    if deliv is None or msg is None:
        raise MessagingError(404, "MESSAGE_NOT_FOUND", f"Message '{message_id}' delivery record not found.")

    node = db.get(NodeRegistry, deliv.relay_node_id)
    now = utc_now()
    deliv.max_retries = max_retries
    deliv.simulation_mode = "NODE_DISCONNECT" if disconnect_node_first else ("DELAY" if delay_ms > 0 and drop_attempts == 0 else "PACKET_LOSS")

    if disconnect_node_first and node is not None:
        node.available = False
        node.health = "OFFLINE"
        deliv.attempt_count += 1
        deliv.status = "DISCONNECTED"
        deliv.last_error_code = "NODE_DISCONNECTED"
        deliv.detail = f"Relay node '{node.node_id}' disconnected prior to delivery."
        deliv.updated_at = now
        if reconnect_after:
            node.available = True
            node.health = "HEALTHY"
            deliv.attempt_count += 1
            deliv.simulated_delay_ms += max(node.latency_ms, delay_ms)
            deliv.status = "IN_TRANSIT"
            deliv.last_error_code = None
            deliv.detail = f"Relay node '{node.node_id}' reconnected; message recovered in transit after {deliv.attempt_count} attempts."
    else:
        for attempt_idx in range(drop_attempts):
            if deliv.attempt_count >= max_retries:
                deliv.status = "DEAD_LETTER"
                deliv.last_error_code = "DELIVERY_RETRY_EXHAUSTED"
                deliv.detail = f"Exceeded bounded max_retries={max_retries} after {deliv.attempt_count} dropped attempts."
                msg.status = "DEAD_LETTER"
                deliv.updated_at = now
                break
            deliv.attempt_count += 1
            deliv.status = "DROPPED"
            deliv.last_error_code = "SIMULATED_PACKET_LOSS"
            deliv.detail = f"Simulated packet drop on attempt {deliv.attempt_count}/{max_retries}."
        else:
            # Succeeded after recoverable drops (if retry budget permits)
            if deliv.attempt_count < max_retries:
                deliv.attempt_count += 1
                deliv.simulated_delay_ms += delay_ms
                deliv.status = "DELAYED" if delay_ms > 0 else "IN_TRANSIT"
                deliv.last_error_code = None
                deliv.detail = f"Recovered after {drop_attempts} dropped attempt(s) on attempt {deliv.attempt_count}."
            else:
                deliv.status = "DEAD_LETTER"
                deliv.last_error_code = "DELIVERY_RETRY_EXHAUSTED"
                deliv.detail = f"Retry budget max_retries={max_retries} exhausted."
                msg.status = "DEAD_LETTER"

    deliv.updated_at = now
    with audit_write_lock():
        append_audit_event(
            db,
            event_type="MSG_DELIVERY_SIMULATED",
            event_category="MESSAGING",
            actor_id=actor_id,
            action="simulate_delivery",
            target_type="message",
            target_id=message_id,
            outcome="ALLOW" if deliv.status in ("IN_TRANSIT", "DELAYED", "DELIVERED", "ACKED") else "DENY",
            reason_code=deliv.last_error_code or deliv.status,
            correlation_id=correlation_id,
            source_component="delivery_simulator",
            payload={
                "mode": deliv.simulation_mode,
                "status": deliv.status,
                "attempts": deliv.attempt_count,
                "max_retries": max_retries,
                "simulated_delay_ms": deliv.simulated_delay_ms,
            },
            commit=False,
        )
        db.commit()
    db.refresh(deliv)
    return deliv


def simulate_reordered_delivery_buffer(
    db: Session,
    keystore: LocalEncryptedKeyStore,
    *,
    message_ids_arrival_order: list[str],
    recipient_id: str,
    recipient_device_id: str,
    buffer_capacity: int = 32,
    correlation_id: str,
) -> dict:
    """Buffer out-of-order encrypted messages, validate completeness/integrity, and deliver in sequence order."""
    if len(message_ids_arrival_order) > buffer_capacity:
        raise MessagingError(400, "REORDER_BUFFER_OVERFLOW", f"Bounded reorder buffer limit ({buffer_capacity}) exceeded.")

    accepted_buffer: list[tuple[int, int, int, str]] = []
    discarded: list[dict[str, str]] = []
    seen_in_batch: set[str] = set()

    for rank, mid in enumerate(message_ids_arrival_order, start=1):
        if mid in seen_in_batch:
            discarded.append({"message_id": mid, "reason": "DUPLICATE_IN_ARRIVAL_STREAM"})
            continue
        seen_in_batch.add(mid)

        msg = db.get(MessageRecord, mid)
        if msg is None:
            discarded.append({"message_id": mid, "reason": "MISSING_OR_UNKNOWN_MESSAGE"})
            continue

        ver = verify_message_integrity_only(db, message_id=mid, expected_recipient_id=recipient_id)
        if not ver["verified"]:
            discarded.append({"message_id": mid, "reason": ",".join(ver["failure_reasons"]) or "INTEGRITY_VERIFICATION_FAILED"})
            continue

        deliv = db.scalar(select(MessageDelivery).where(MessageDelivery.message_id == mid))
        if deliv is not None:
            deliv.simulation_mode = "REORDER"
            deliv.delivery_order_rank = rank
            deliv.status = "REORDERED"
            deliv.updated_at = utc_now()
        accepted_buffer.append((msg.session_generation, msg.sequence, rank, mid))

    # Deliver verified buffered entries strictly in canonical (generation, sequence) order
    accepted_buffer.sort(key=lambda item: (item[0], item[1]))
    delivered_ids: list[str] = []
    for _gen, _seq, _rank, mid in accepted_buffer:
        try:
            receive_and_decrypt_message(
                db,
                keystore,
                message_id=mid,
                caller_id=recipient_id,
                caller_device_id=recipient_device_id,
                correlation_id=correlation_id,
            )
            delivered_ids.append(mid)
        except MessagingError as exc:
            discarded.append({"message_id": mid, "reason": exc.code})

    return {
        "arrival_order": message_ids_arrival_order,
        "delivered_order": delivered_ids,
        "discarded": discarded,
    }
