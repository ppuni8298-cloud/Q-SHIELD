"""Phase 6 Read-Only Audit Ledger, Verification, Checkpoint, Receipt & Export API Endpoints.

Zero update or delete endpoints exist on the audit ledger.
"""

from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.audit.canonical import event_model_to_dict, redact_sensitive_fields
from backend.app.audit.evidence import (
    create_audit_checkpoint,
    export_evidence_package,
    get_audit_public_key_b64,
    issue_event_receipt,
    receipt_to_dict,
    verify_exported_package,
    verify_receipt_data,
)
from backend.app.audit.ledger import AuditError
from backend.app.audit.verifier import verify_ledger_db
from backend.app.auth.dependencies import AuthContext, require_permission
from backend.app.crypto.keystore import LocalEncryptedKeyStore, get_keystore
from backend.app.db.models import AuditCheckpoint, AuditEvent, AuditEvidenceReceipt
from backend.app.db.session import get_db
from backend.app.schemas.audit import (
    AuditCheckpointCreateRequest,
    AuditCheckpointOut,
    AuditEventOut,
    AuditExportPackageOut,
    AuditExportRequest,
    AuditExportVerifyRequest,
    AuditReceiptOut,
    AuditReceiptVerifyOut,
    AuditReceiptVerifyRequest,
    AuditVerificationOut,
    AuditVerifyRequest,
)
from backend.app.schemas.common import PaginatedResponse

router = APIRouter(prefix="/audit", tags=["audit"])


def _err(exc: AuditError, corr_id: str) -> HTTPException:
    return HTTPException(
        status_code=exc.status_code,
        detail={"code": exc.code, "message": exc.message, "correlation_id": corr_id},
    )


def _to_event_out(row: AuditEvent) -> AuditEventOut:
    data = redact_sensitive_fields(event_model_to_dict(row))
    return AuditEventOut(**data)


@router.get("/events", response_model=PaginatedResponse[AuditEventOut])
def get_audit_events(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    event_category: str | None = Query(default=None),
    actor_id: str | None = Query(default=None),
    correlation_id: str | None = Query(default=None),
    ctx: AuthContext = Depends(require_permission("audit:read")),
    db: Session = Depends(get_db),
) -> PaginatedResponse[AuditEventOut]:
    query = select(AuditEvent)
    count_q = select(func.count()).select_from(AuditEvent)
    if event_category is not None:
        query = query.where(AuditEvent.event_category == event_category)
        count_q = count_q.where(AuditEvent.event_category == event_category)
    if actor_id is not None:
        query = query.where(AuditEvent.actor_id == actor_id)
        count_q = count_q.where(AuditEvent.actor_id == actor_id)
    if correlation_id is not None:
        query = query.where(AuditEvent.correlation_id == correlation_id)
        count_q = count_q.where(AuditEvent.correlation_id == correlation_id)

    total = int(db.scalar(count_q) or 0)
    rows = list(db.scalars(query.order_by(AuditEvent.sequence.asc()).limit(limit).offset(offset)).all())
    return PaginatedResponse[AuditEventOut](
        items=[_to_event_out(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
        correlation_id=ctx.correlation_id,
    )


@router.get("/events/{event_id}", response_model=AuditEventOut)
def get_single_audit_event(
    event_id: str,
    ctx: AuthContext = Depends(require_permission("audit:read")),
    db: Session = Depends(get_db),
) -> AuditEventOut:
    row = db.scalar(select(AuditEvent).where(AuditEvent.event_id == event_id))
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "AUDIT_EVENT_NOT_FOUND", "message": f"Audit event '{event_id}' not found.", "correlation_id": ctx.correlation_id},
        )
    return _to_event_out(row)


@router.post("/verify", response_model=AuditVerificationOut)
def post_verify_ledger(
    payload: AuditVerifyRequest | None = None,
    ctx: AuthContext = Depends(require_permission("audit:read")),
    db: Session = Depends(get_db),
) -> AuditVerificationOut:
    start_seq = payload.start_sequence if payload is not None else None
    end_seq = payload.end_sequence if payload is not None else None
    if start_seq is not None and end_seq is not None and end_seq < start_seq:
        raise HTTPException(
            status_code=400,
            detail={"code": "INVALID_SEQUENCE_RANGE", "message": "end_sequence must be >= start_sequence.", "correlation_id": ctx.correlation_id},
        )
    res = verify_ledger_db(db, start_sequence=start_seq, end_sequence=end_seq)
    return AuditVerificationOut(**asdict(res))


@router.get("/checkpoints/latest", response_model=AuditCheckpointOut)
def get_latest_checkpoint(
    ctx: AuthContext = Depends(require_permission("audit:read")),
    db: Session = Depends(get_db),
) -> AuditCheckpointOut:
    row = db.scalars(select(AuditCheckpoint).order_by(AuditCheckpoint.sequence.desc()).limit(1)).first()
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "CHECKPOINT_NOT_FOUND", "message": "No audit checkpoint exists yet.", "correlation_id": ctx.correlation_id},
        )
    return AuditCheckpointOut.model_validate(row)


@router.post("/checkpoints", response_model=AuditCheckpointOut, status_code=201)
def post_create_checkpoint(
    payload: AuditCheckpointCreateRequest | None = None,
    ctx: AuthContext = Depends(require_permission("audit:manage")),
    db: Session = Depends(get_db),
    keystore: LocalEncryptedKeyStore = Depends(get_keystore),
) -> AuditCheckpointOut:
    up_to = payload.up_to_sequence if payload is not None else None
    try:
        row = create_audit_checkpoint(db, keystore, actor_id=ctx.user.id, up_to_sequence=up_to)
    except AuditError as exc:
        raise _err(exc, ctx.correlation_id) from None
    return AuditCheckpointOut.model_validate(row)


@router.post("/events/{event_id}/receipt", response_model=AuditReceiptOut, status_code=201)
def post_issue_event_receipt(
    event_id: str,
    ctx: AuthContext = Depends(require_permission("audit:manage")),
    db: Session = Depends(get_db),
    keystore: LocalEncryptedKeyStore = Depends(get_keystore),
) -> AuditReceiptOut:
    try:
        row = issue_event_receipt(db, keystore, event_id=event_id, actor_id=ctx.user.id)
    except AuditError as exc:
        raise _err(exc, ctx.correlation_id) from None
    return AuditReceiptOut(**receipt_to_dict(row))


@router.post("/receipts/verify", response_model=AuditReceiptVerifyOut)
def post_verify_receipt_payload(
    payload: AuditReceiptVerifyRequest,
    ctx: AuthContext = Depends(require_permission("audit:read")),
    db: Session = Depends(get_db),
) -> AuditReceiptVerifyOut:
    try:
        pk_b64 = payload.public_key_b64 or get_audit_public_key_b64(db)
    except AuditError as exc:
        raise _err(exc, ctx.correlation_id) from None
    ok, detail = verify_receipt_data(payload.receipt, public_key_b64=pk_b64)
    return AuditReceiptVerifyOut(
        valid=ok,
        receipt_id=str(payload.receipt.get("receipt_id")) if isinstance(payload.receipt, dict) and payload.receipt.get("receipt_id") else None,
        detail=detail,
        correlation_id=ctx.correlation_id,
    )


@router.get("/receipts/{receipt_id}", response_model=AuditReceiptOut)
def get_receipt(
    receipt_id: str,
    ctx: AuthContext = Depends(require_permission("audit:read")),
    db: Session = Depends(get_db),
) -> AuditReceiptOut:
    row = db.get(AuditEvidenceReceipt, receipt_id)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "RECEIPT_NOT_FOUND", "message": f"Receipt '{receipt_id}' not found.", "correlation_id": ctx.correlation_id},
        )
    return AuditReceiptOut(**receipt_to_dict(row))


@router.post("/receipts/{receipt_id}/verify", response_model=AuditReceiptVerifyOut)
def post_verify_stored_receipt(
    receipt_id: str,
    ctx: AuthContext = Depends(require_permission("audit:read")),
    db: Session = Depends(get_db),
) -> AuditReceiptVerifyOut:
    row = db.get(AuditEvidenceReceipt, receipt_id)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "RECEIPT_NOT_FOUND", "message": f"Receipt '{receipt_id}' not found.", "correlation_id": ctx.correlation_id},
        )
    try:
        pk_b64 = get_audit_public_key_b64(db)
    except AuditError as exc:
        raise _err(exc, ctx.correlation_id) from None
    ok, detail = verify_receipt_data(row, public_key_b64=pk_b64)
    return AuditReceiptVerifyOut(
        valid=ok,
        receipt_id=row.receipt_id,
        detail=detail,
        correlation_id=ctx.correlation_id,
    )


@router.post("/export", response_model=AuditExportPackageOut)
def post_export_evidence(
    payload: AuditExportRequest | None = None,
    ctx: AuthContext = Depends(require_permission("audit:export")),
    db: Session = Depends(get_db),
    keystore: LocalEncryptedKeyStore = Depends(get_keystore),
) -> AuditExportPackageOut:
    first_seq = payload.first_sequence if payload is not None else 1
    last_seq = payload.last_sequence if payload is not None else None
    try:
        pkg = export_evidence_package(
            db,
            keystore,
            actor_id=ctx.user.id,
            first_sequence=first_seq,
            last_sequence=last_seq,
        )
    except AuditError as exc:
        raise _err(exc, ctx.correlation_id) from None
    return AuditExportPackageOut(**pkg)


@router.post("/export/verify", response_model=AuditVerificationOut)
def post_verify_export(
    payload: AuditExportVerifyRequest,
    _ctx: AuthContext = Depends(require_permission("audit:read")),
) -> AuditVerificationOut:
    res = verify_exported_package(payload.package, public_key_b64=payload.public_key_b64)
    return AuditVerificationOut(**asdict(res))
