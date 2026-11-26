"""Phase 8 API routes for E2E Secure Messaging, Delivery Simulation & Peer-Bound Session Resumption."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.audit.ledger import record_audit_safe
from backend.app.auth.dependencies import AuthContext, get_auth_context, require_permission
from backend.app.crypto.keystore import LocalEncryptedKeyStore, get_keystore
from backend.app.db.models import CryptoSession, MessageDelivery, MessageRecord, ReplayRecord
from backend.app.db.session import get_db
from backend.app.identity.roles import role_has_permission
from backend.app.messaging.crypto_channel import MessagingError
from backend.app.messaging.delivery_simulator import (
    acknowledge_message_delivery,
    simulate_packet_loss_and_retry,
    simulate_reordered_delivery_buffer,
)
from backend.app.messaging.message_service import (
    receive_and_decrypt_message,
    send_encrypted_message,
    verify_message_integrity_only,
)
from backend.app.messaging.session_manager import (
    establish_messaging_session,
    resume_messaging_session,
    revoke_messaging_session,
    suspend_messaging_session,
)
from backend.app.schemas.common import PaginatedResponse
from backend.app.schemas.messaging import (
    CryptoSessionOut,
    MessageAckResponse,
    MessageDeliveryOut,
    MessageMetadataOut,
    MessageReceiveRequest,
    MessageReceiveResponse,
    MessageSendRequest,
    MessageSendResponse,
    MessageVerifyOut,
    ReplayRecordOut,
    SessionEstablishRequest,
    SessionEstablishResponse,
    SessionResumeRequest,
    SessionResumeResponse,
    SessionTransitionRequest,
    SimulateLossRequest,
    SimulateReorderRequest,
    SimulateReorderResponse,
)

router = APIRouter(prefix="/messages", tags=["messaging"])


def _err(exc: MessagingError, corr_id: str) -> HTTPException:
    return HTTPException(
        status_code=exc.status_code,
        detail={"code": exc.code, "message": exc.message, "correlation_id": corr_id},
    )


def _require_any_permission(*permissions: str):
    def _checker(
        ctx: AuthContext = Depends(get_auth_context),
        db: Session = Depends(get_db),
    ) -> AuthContext:
        if not any(role_has_permission(ctx.user.role, p) for p in permissions):
            record_audit_safe(
                db,
                event_type="AUTHORIZATION_DENIED",
                event_category="AUTHORIZATION",
                actor_id=ctx.user.id,
                action=f"require:{'|'.join(permissions)}",
                target_type="rbac_permission",
                target_id="|".join(permissions),
                outcome="DENY",
                reason_code="FORBIDDEN_ROLE_PERMISSION",
                correlation_id=ctx.correlation_id,
                source_component="rbac_guard",
                payload={"role": ctx.user.role, "permissions": list(permissions)},
                commit=True,
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "FORBIDDEN_ROLE_PERMISSION",
                    "message": f"Role '{ctx.user.role}' lacks required messaging permissions.",
                    "correlation_id": ctx.correlation_id,
                },
            )
        return ctx

    return _checker


def _session_out(row: CryptoSession) -> CryptoSessionOut:
    return CryptoSessionOut(
        id=row.id,
        initiator_id=row.initiator_id,
        recipient_id=row.recipient_id,
        initiator_device_id=row.initiator_device_id,
        recipient_device_id=row.recipient_device_id,
        peer_binding=row.peer_binding,
        state=row.state,
        key_version=row.key_version,
        generation=row.generation,
        send_sequence=row.send_sequence,
        recv_expected_sequence=row.recv_expected_sequence,
        kem_algorithm=row.kem_algorithm,
        aead_algorithm=row.aead_algorithm,
        kdf_algorithm=row.kdf_algorithm,
        resumption_counter=row.resumption_counter,
        ephemeral_key_erased=row.ephemeral_key_erased,
        forward_secrecy_status=row.forward_secrecy_status,
        expires_at=row.expires_at,
        suspended_at=row.suspended_at,
        resumed_at=row.resumed_at,
        revoked_at=row.revoked_at,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _message_out(row: MessageRecord) -> MessageMetadataOut:
    return MessageMetadataOut(
        message_id=row.message_id,
        sender_id=row.sender_id,
        recipient_id=row.recipient_id,
        session_id=row.session_id,
        sequence=row.sequence,
        session_generation=row.session_generation,
        key_version=row.key_version,
        nonce_b64=row.nonce_b64,
        status=row.status,
        ack_count=row.ack_count,
        encrypted_envelope=json.loads(row.encrypted_envelope) if row.encrypted_envelope else {},
        expires_at=row.expires_at,
        created_at=row.created_at,
        delivered_at=row.delivered_at,
        acknowledged_at=row.acknowledged_at,
    )


def _delivery_out(row: MessageDelivery) -> MessageDeliveryOut:
    return MessageDeliveryOut(
        delivery_id=row.delivery_id,
        message_id=row.message_id,
        session_id=row.session_id,
        sequence=row.sequence,
        relay_node_id=row.relay_node_id,
        simulation_mode=row.simulation_mode,
        status=row.status,
        attempt_count=row.attempt_count,
        max_retries=row.max_retries,
        simulated_delay_ms=row.simulated_delay_ms,
        delivery_order_rank=row.delivery_order_rank,
        ack_count=row.ack_count,
        duplicate_acks_ignored=row.duplicate_acks_ignored,
        last_error_code=row.last_error_code,
        detail=row.detail,
        created_at=row.created_at,
        updated_at=row.updated_at,
        acked_at=row.acked_at,
    )


def _ensure_read_access(ctx: AuthContext, *, participants: tuple[str, ...]) -> None:
    if role_has_permission(ctx.user.role, "messaging:read_all"):
        return
    if ctx.user.id in participants and role_has_permission(ctx.user.role, "messaging:use"):
        return
    raise HTTPException(
        status_code=403,
        detail={
            "code": "FORBIDDEN_MESSAGING_ACCESS",
            "message": "Caller is not authorized to access this messaging record.",
            "correlation_id": ctx.correlation_id,
        },
    )


@router.post("/sessions", response_model=SessionEstablishResponse)
def post_establish_session(
    payload: SessionEstablishRequest,
    ctx: AuthContext = Depends(_require_any_permission("messaging:use")),
    db: Session = Depends(get_db),
    keystore: LocalEncryptedKeyStore = Depends(get_keystore),
) -> SessionEstablishResponse:
    try:
        sess, res_token, kem_ct_b64 = establish_messaging_session(
            db,
            keystore,
            initiator_id=ctx.user.id,
            initiator_device_id=ctx.device.id,
            recipient_id=payload.recipient_id,
            recipient_device_id=payload.recipient_device_id,
            ttl_seconds=payload.ttl_seconds,
            recipient_kem_public_key_b64=payload.recipient_kem_public_key_b64,
            correlation_id=ctx.correlation_id,
        )
    except MessagingError as exc:
        raise _err(exc, ctx.correlation_id) from None
    return SessionEstablishResponse(
        session=_session_out(sess),
        resumption_token=res_token,
        kem_ciphertext_b64=kem_ct_b64,
        forward_secrecy_note=(
            "Ephemeral ML-KEM-768 secret key & shared secret erased immediately after HKDF key separation; "
            "PARTIAL prototype limitation applies because active session chain state resides in server LocalEncryptedKeyStore."
        ),
        correlation_id=ctx.correlation_id,
    )


@router.get("/sessions", response_model=PaginatedResponse[CryptoSessionOut])
def get_messaging_sessions(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    ctx: AuthContext = Depends(_require_any_permission("messaging:use", "messaging:read_all")),
    db: Session = Depends(get_db),
) -> PaginatedResponse[CryptoSessionOut]:
    query = select(CryptoSession)
    count_q = select(func.count()).select_from(CryptoSession)
    if not role_has_permission(ctx.user.role, "messaging:read_all"):
        filt = (CryptoSession.initiator_id == ctx.user.id) | (CryptoSession.recipient_id == ctx.user.id)
        query = query.where(filt)
        count_q = count_q.where(filt)
    total = int(db.scalar(count_q) or 0)
    rows = list(db.scalars(query.order_by(CryptoSession.created_at.desc()).limit(limit).offset(offset)).all())
    return PaginatedResponse[CryptoSessionOut](
        items=[_session_out(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
        correlation_id=ctx.correlation_id,
    )


@router.get("/sessions/{session_id}", response_model=CryptoSessionOut)
def get_messaging_session_status(
    session_id: str,
    ctx: AuthContext = Depends(_require_any_permission("messaging:use", "messaging:read_all")),
    db: Session = Depends(get_db),
) -> CryptoSessionOut:
    row = db.get(CryptoSession, session_id)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "SESSION_NOT_FOUND", "message": f"Session '{session_id}' not found.", "correlation_id": ctx.correlation_id},
        )
    _ensure_read_access(ctx, participants=(row.initiator_id, row.recipient_id))
    return _session_out(row)


@router.post("/sessions/{session_id}/suspend", response_model=CryptoSessionOut)
def post_suspend_session(
    session_id: str,
    payload: SessionTransitionRequest,
    ctx: AuthContext = Depends(_require_any_permission("messaging:use", "messaging:manage")),
    db: Session = Depends(get_db),
) -> CryptoSessionOut:
    is_op = role_has_permission(ctx.user.role, "messaging:manage")
    try:
        sess = suspend_messaging_session(
            db,
            session_id=session_id,
            actor_id=ctx.user.id,
            reason=payload.reason,
            confirmation=payload.confirmation,
            is_operator=is_op,
            correlation_id=ctx.correlation_id,
        )
    except MessagingError as exc:
        raise _err(exc, ctx.correlation_id) from None
    return _session_out(sess)


@router.post("/sessions/{session_id}/resume", response_model=SessionResumeResponse)
def post_resume_session(
    session_id: str,
    payload: SessionResumeRequest,
    ctx: AuthContext = Depends(_require_any_permission("messaging:use")),
    db: Session = Depends(get_db),
    keystore: LocalEncryptedKeyStore = Depends(get_keystore),
) -> SessionResumeResponse:
    try:
        sess, next_tok, kem_ct_b64 = resume_messaging_session(
            db,
            keystore,
            session_id=session_id,
            caller_id=ctx.user.id,
            caller_device_id=ctx.device.id,
            peer_id=payload.peer_id,
            resumption_token=payload.resumption_token,
            correlation_id=ctx.correlation_id,
        )
    except MessagingError as exc:
        raise _err(exc, ctx.correlation_id) from None
    return SessionResumeResponse(
        session=_session_out(sess),
        next_resumption_token=next_tok,
        kem_ciphertext_b64=kem_ct_b64,
        correlation_id=ctx.correlation_id,
    )


@router.post("/sessions/{session_id}/revoke", response_model=CryptoSessionOut)
def post_revoke_session(
    session_id: str,
    payload: SessionTransitionRequest,
    ctx: AuthContext = Depends(_require_any_permission("messaging:use", "messaging:manage")),
    db: Session = Depends(get_db),
    keystore: LocalEncryptedKeyStore = Depends(get_keystore),
) -> CryptoSessionOut:
    is_op = role_has_permission(ctx.user.role, "messaging:manage")
    try:
        sess = revoke_messaging_session(
            db,
            keystore,
            session_id=session_id,
            actor_id=ctx.user.id,
            reason=payload.reason,
            confirmation=payload.confirmation,
            compromised=payload.compromised,
            is_operator=is_op,
            correlation_id=ctx.correlation_id,
        )
    except MessagingError as exc:
        raise _err(exc, ctx.correlation_id) from None
    return _session_out(sess)


@router.post("/send", response_model=MessageSendResponse)
def post_send_message(
    payload: MessageSendRequest,
    ctx: AuthContext = Depends(_require_any_permission("messaging:use")),
    db: Session = Depends(get_db),
    keystore: LocalEncryptedKeyStore = Depends(get_keystore),
) -> MessageSendResponse:
    try:
        msg, deliv = send_encrypted_message(
            db,
            keystore,
            session_id=payload.session_id,
            sender_id=ctx.user.id,
            sender_device_id=ctx.device.id,
            plaintext=payload.plaintext,
            ttl_seconds=payload.ttl_seconds,
            relay_node_id=payload.relay_node_id,
            correlation_id=ctx.correlation_id,
        )
    except MessagingError as exc:
        raise _err(exc, ctx.correlation_id) from None
    return MessageSendResponse(
        message=_message_out(msg),
        delivery=_delivery_out(deliv),
        correlation_id=ctx.correlation_id,
    )


@router.post("/receive", response_model=MessageReceiveResponse)
def post_receive_message(
    payload: MessageReceiveRequest,
    ctx: AuthContext = Depends(_require_any_permission("messaging:use")),
    db: Session = Depends(get_db),
    keystore: LocalEncryptedKeyStore = Depends(get_keystore),
) -> MessageReceiveResponse:
    try:
        msg, plaintext = receive_and_decrypt_message(
            db,
            keystore,
            message_id=payload.message_id,
            caller_id=ctx.user.id,
            caller_device_id=ctx.device.id,
            correlation_id=ctx.correlation_id,
        )
    except MessagingError as exc:
        raise _err(exc, ctx.correlation_id) from None
    return MessageReceiveResponse(
        message=_message_out(msg),
        plaintext=plaintext,
        per_message_key_erased=True,
        correlation_id=ctx.correlation_id,
    )


@router.get("", response_model=PaginatedResponse[MessageMetadataOut])
def get_messages(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    session_id: str | None = Query(default=None),
    ctx: AuthContext = Depends(_require_any_permission("messaging:use", "messaging:read_all")),
    db: Session = Depends(get_db),
) -> PaginatedResponse[MessageMetadataOut]:
    query = select(MessageRecord)
    count_q = select(func.count()).select_from(MessageRecord)
    if not role_has_permission(ctx.user.role, "messaging:read_all"):
        filt = (MessageRecord.sender_id == ctx.user.id) | (MessageRecord.recipient_id == ctx.user.id)
        query = query.where(filt)
        count_q = count_q.where(filt)
    if session_id:
        query = query.where(MessageRecord.session_id == session_id)
        count_q = count_q.where(MessageRecord.session_id == session_id)
    total = int(db.scalar(count_q) or 0)
    rows = list(db.scalars(query.order_by(MessageRecord.created_at.desc()).limit(limit).offset(offset)).all())
    return PaginatedResponse[MessageMetadataOut](
        items=[_message_out(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
        correlation_id=ctx.correlation_id,
    )


@router.get("/replay-evidence", response_model=PaginatedResponse[ReplayRecordOut])
def get_replay_evidence(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    session_id: str | None = Query(default=None),
    ctx: AuthContext = Depends(_require_any_permission("messaging:use", "messaging:read_all")),
    db: Session = Depends(get_db),
) -> PaginatedResponse[ReplayRecordOut]:
    query = select(ReplayRecord)
    count_q = select(func.count()).select_from(ReplayRecord)
    if not role_has_permission(ctx.user.role, "messaging:read_all"):
        query = query.where(ReplayRecord.recipient_id == ctx.user.id)
        count_q = count_q.where(ReplayRecord.recipient_id == ctx.user.id)
    if session_id:
        query = query.where(ReplayRecord.session_id == session_id)
        count_q = count_q.where(ReplayRecord.session_id == session_id)
    total = int(db.scalar(count_q) or 0)
    rows = list(db.scalars(query.order_by(ReplayRecord.id.desc()).limit(limit).offset(offset)).all())
    return PaginatedResponse[ReplayRecordOut](
        items=[
            ReplayRecordOut(
                id=r.id,
                recipient_id=r.recipient_id,
                session_id=r.session_id,
                sequence_or_msg_id=r.sequence_or_msg_id,
                accepted=r.accepted,
                reason_code=r.reason_code,
                attempt_count=r.attempt_count,
                recorded_at=r.recorded_at,
                expires_at=r.expires_at,
            )
            for r in rows
        ],
        total=total,
        limit=limit,
        offset=offset,
        correlation_id=ctx.correlation_id,
    )


@router.get("/{message_id}", response_model=MessageMetadataOut)
def get_message_detail(
    message_id: str,
    ctx: AuthContext = Depends(_require_any_permission("messaging:use", "messaging:read_all")),
    db: Session = Depends(get_db),
) -> MessageMetadataOut:
    row = db.get(MessageRecord, message_id)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "MESSAGE_NOT_FOUND", "message": f"Message '{message_id}' not found.", "correlation_id": ctx.correlation_id},
        )
    _ensure_read_access(ctx, participants=(row.sender_id, row.recipient_id))
    return _message_out(row)


@router.post("/{message_id}/verify", response_model=MessageVerifyOut)
def post_verify_message(
    message_id: str,
    ctx: AuthContext = Depends(_require_any_permission("messaging:use", "messaging:read_all")),
    db: Session = Depends(get_db),
) -> MessageVerifyOut:
    msg = db.get(MessageRecord, message_id)
    if msg is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "MESSAGE_NOT_FOUND", "message": f"Message '{message_id}' not found.", "correlation_id": ctx.correlation_id},
        )
    _ensure_read_access(ctx, participants=(msg.sender_id, msg.recipient_id))
    try:
        res = verify_message_integrity_only(db, message_id=message_id)
    except MessagingError as exc:
        raise _err(exc, ctx.correlation_id) from None
    return MessageVerifyOut(**res, correlation_id=ctx.correlation_id)


@router.get("/{message_id}/delivery", response_model=MessageDeliveryOut)
def get_message_delivery(
    message_id: str,
    ctx: AuthContext = Depends(_require_any_permission("messaging:use", "messaging:read_all")),
    db: Session = Depends(get_db),
) -> MessageDeliveryOut:
    msg = db.get(MessageRecord, message_id)
    if msg is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "MESSAGE_NOT_FOUND", "message": f"Message '{message_id}' not found.", "correlation_id": ctx.correlation_id},
        )
    _ensure_read_access(ctx, participants=(msg.sender_id, msg.recipient_id))
    deliv = db.scalar(select(MessageDelivery).where(MessageDelivery.message_id == message_id))
    if deliv is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "DELIVERY_RECORD_NOT_FOUND", "message": "Delivery record missing.", "correlation_id": ctx.correlation_id},
        )
    return _delivery_out(deliv)


@router.post("/{message_id}/ack", response_model=MessageAckResponse)
def post_ack_message(
    message_id: str,
    ctx: AuthContext = Depends(_require_any_permission("messaging:use", "messaging:manage")),
    db: Session = Depends(get_db),
) -> MessageAckResponse:
    is_op = role_has_permission(ctx.user.role, "messaging:manage")
    try:
        msg, deliv, dup = acknowledge_message_delivery(
            db,
            message_id=message_id,
            actor_id=ctx.user.id,
            is_operator=is_op,
            correlation_id=ctx.correlation_id,
        )
    except MessagingError as exc:
        raise _err(exc, ctx.correlation_id) from None
    return MessageAckResponse(
        message=_message_out(msg),
        delivery=_delivery_out(deliv),
        duplicate_ack_ignored=dup,
        correlation_id=ctx.correlation_id,
    )


@router.post("/{message_id}/simulate-loss", response_model=MessageDeliveryOut)
def post_simulate_loss(
    message_id: str,
    payload: SimulateLossRequest,
    ctx: AuthContext = Depends(_require_any_permission("messaging:use", "messaging:manage")),
    db: Session = Depends(get_db),
) -> MessageDeliveryOut:
    msg = db.get(MessageRecord, message_id)
    if msg is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "MESSAGE_NOT_FOUND", "message": f"Message '{message_id}' not found.", "correlation_id": ctx.correlation_id},
        )
    _ensure_read_access(ctx, participants=(msg.sender_id, msg.recipient_id))
    try:
        deliv = simulate_packet_loss_and_retry(
            db,
            message_id=message_id,
            drop_attempts=payload.drop_attempts,
            max_retries=payload.max_retries,
            delay_ms=payload.delay_ms,
            disconnect_node_first=payload.disconnect_node_first,
            reconnect_after=payload.reconnect_after,
            actor_id=ctx.user.id,
            correlation_id=ctx.correlation_id,
        )
    except MessagingError as exc:
        raise _err(exc, ctx.correlation_id) from None
    return _delivery_out(deliv)


@router.post("/simulate-reorder", response_model=SimulateReorderResponse)
def post_simulate_reorder(
    payload: SimulateReorderRequest,
    ctx: AuthContext = Depends(_require_any_permission("messaging:use")),
    db: Session = Depends(get_db),
    keystore: LocalEncryptedKeyStore = Depends(get_keystore),
) -> SimulateReorderResponse:
    try:
        res = simulate_reordered_delivery_buffer(
            db,
            keystore,
            message_ids_arrival_order=payload.message_ids_arrival_order,
            recipient_id=ctx.user.id,
            recipient_device_id=ctx.device.id,
            correlation_id=ctx.correlation_id,
        )
    except MessagingError as exc:
        raise _err(exc, ctx.correlation_id) from None
    return SimulateReorderResponse(**res, correlation_id=ctx.correlation_id)
