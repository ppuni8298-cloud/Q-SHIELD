"""Phase 7 Explainable Deterministic Threat Detector API Routes (/api/v1/detector/*)."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.auth.dependencies import AuthContext, require_permission
from backend.app.db.models import AlertRecord, DetectionRun
from backend.app.db.session import get_db
from backend.app.detector.config import RULE_CATALOG
from backend.app.detector.dataset import EVAL_DEFAULT_SEED, generate_synthetic_evaluation_dataset
from backend.app.detector.evaluation import evaluate_benchmark_dataset
from backend.app.detector.service import (
    DetectorServiceError,
    acknowledge_alert,
    load_active_detector_config,
    mark_alert_false_positive,
    resolve_alert,
    run_detection,
    update_detector_config,
)
from backend.app.schemas.common import PaginatedResponse
from backend.app.schemas.detector import (
    AlertActionResponse,
    AlertOut,
    AlertTransitionRequest,
    DetectionRunOut,
    DetectorConfigUpdateRequest,
    DetectorEvaluateRequest,
    DetectorEvaluateResponse,
    DetectorRuleOut,
    DetectorRulesCatalogOut,
)

router = APIRouter(prefix="/detector", tags=["detector"])


def _err(exc: DetectorServiceError, corr_id: str) -> HTTPException:
    return HTTPException(
        status_code=exc.status_code,
        detail={"code": exc.code, "message": exc.message, "correlation_id": corr_id},
    )


def _alert_to_out(row: AlertRecord) -> AlertOut:
    return AlertOut(
        id=row.id,
        rule_id=row.rule_id,
        rule_version=row.rule_version,
        fingerprint=row.fingerprint,
        severity=row.severity,
        confidence=row.confidence,
        explanation=row.explanation,
        actor_id=row.actor_id,
        device_id=row.device_id,
        session_id=row.session_id,
        node_id=row.node_id,
        resource_id=row.resource_id,
        services=json.loads(row.services_json) if row.services_json else [],
        event_refs=json.loads(row.event_refs_json) if row.event_refs_json else [],
        reason_codes=json.loads(row.reason_codes_json) if row.reason_codes_json else [],
        recommended_response=row.recommended_response,
        detection_window_sec=row.detection_window_sec,
        first_observed_at=row.first_observed_at,
        last_observed_at=row.last_observed_at,
        run_id=row.run_id,
        status=row.status,
        resolution_note=row.resolution_note,
        reviewed_by=row.reviewed_by,
        reviewed_at=row.reviewed_at,
        alert_time=row.alert_time,
    )


def _run_to_out(row: DetectionRun) -> DetectionRunOut:
    return DetectionRunOut(
        run_id=row.run_id,
        dataset_name=row.dataset_name,
        dataset_version=row.dataset_version,
        rule_set_version=row.rule_set_version,
        events_inspected=row.events_inspected,
        alerts_created=row.alerts_created,
        alerts_deduplicated=row.alerts_deduplicated,
        audit_chain_verified=row.audit_chain_verified,
        status=row.status,
        metrics=json.loads(row.metrics_json) if row.metrics_json else {},
        summary_detail=row.summary_detail,
        created_by=row.created_by,
        created_at=row.created_at,
    )


@router.get("/rules", response_model=DetectorRulesCatalogOut)
def get_detector_rules(
    _ctx: AuthContext = Depends(require_permission("detector:read")),
    db: Session = Depends(get_db),
) -> DetectorRulesCatalogOut:
    cfg = load_active_detector_config(db)
    return DetectorRulesCatalogOut(
        rule_set_version=cfg.rule_set_version,
        active_config=cfg.to_dict(),
        rules=[DetectorRuleOut(**r.__dict__) for r in RULE_CATALOG.values()],
    )


@router.post("/config", response_model=DetectorRulesCatalogOut)
def post_update_detector_config(
    payload: DetectorConfigUpdateRequest,
    ctx: AuthContext = Depends(require_permission("detector:manage")),
    db: Session = Depends(get_db),
) -> DetectorRulesCatalogOut:
    updates = payload.model_dump(exclude={"reason", "confirmation"}, exclude_none=True)
    try:
        cfg = update_detector_config(
            db,
            updates=updates,
            actor_id=ctx.user.id,
            reason=payload.reason,
            confirmation=payload.confirmation,
            correlation_id=ctx.correlation_id,
        )
    except DetectorServiceError as exc:
        raise _err(exc, ctx.correlation_id) from None
    return DetectorRulesCatalogOut(
        rule_set_version=cfg.rule_set_version,
        active_config=cfg.to_dict(),
        rules=[DetectorRuleOut(**r.__dict__) for r in RULE_CATALOG.values()],
    )


@router.post("/evaluate", response_model=DetectorEvaluateResponse)
def post_evaluate_detector(
    payload: DetectorEvaluateRequest | None = None,
    ctx: AuthContext = Depends(require_permission("detector:run")),
    db: Session = Depends(get_db),
) -> DetectorEvaluateResponse:
    req = payload or DetectorEvaluateRequest()
    if req.start_sequence is not None and req.end_sequence is not None and req.end_sequence < req.start_sequence:
        raise HTTPException(
            status_code=400,
            detail={"code": "INVALID_SEQUENCE_RANGE", "message": "end_sequence must be >= start_sequence.", "correlation_id": ctx.correlation_id},
        )
    try:
        run_row, alerts, metrics = run_detection(
            db,
            source=req.source,
            actor_id=ctx.user.id,
            correlation_id=ctx.correlation_id,
            start_sequence=req.start_sequence,
            end_sequence=req.end_sequence,
            custom_events=req.custom_events,
            approvals=req.approvals,
            seed=req.seed,
        )
    except DetectorServiceError as exc:
        raise _err(exc, ctx.correlation_id) from None
    return DetectorEvaluateResponse(
        run=_run_to_out(run_row),
        alerts=[_alert_to_out(a) for a in alerts],
        metrics=metrics,
        correlation_id=ctx.correlation_id,
    )


@router.get("/runs", response_model=PaginatedResponse[DetectionRunOut])
def get_detection_runs(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    ctx: AuthContext = Depends(require_permission("detector:read")),
    db: Session = Depends(get_db),
) -> PaginatedResponse[DetectionRunOut]:
    total = int(db.scalar(select(func.count()).select_from(DetectionRun)) or 0)
    rows = list(db.scalars(select(DetectionRun).order_by(DetectionRun.created_at.desc()).limit(limit).offset(offset)).all())
    return PaginatedResponse[DetectionRunOut](
        items=[_run_to_out(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
        correlation_id=ctx.correlation_id,
    )


@router.get("/runs/{run_id}", response_model=DetectionRunOut)
def get_detection_run(
    run_id: str,
    ctx: AuthContext = Depends(require_permission("detector:read")),
    db: Session = Depends(get_db),
) -> DetectionRunOut:
    row = db.get(DetectionRun, run_id)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "DETECTION_RUN_NOT_FOUND", "message": f"Detection run '{run_id}' not found.", "correlation_id": ctx.correlation_id},
        )
    return _run_to_out(row)


@router.get("/metrics", response_model=dict)
def get_detector_metrics(
    seed: int = Query(default=EVAL_DEFAULT_SEED, ge=0),
    _ctx: AuthContext = Depends(require_permission("detector:read")),
    db: Session = Depends(get_db),
) -> dict:
    cfg = load_active_detector_config(db)
    ds = generate_synthetic_evaluation_dataset(seed=seed)
    rep, _alerts = evaluate_benchmark_dataset(ds, config=cfg)
    return rep.to_dict()


@router.get("/alerts", response_model=PaginatedResponse[AlertOut])
def get_alerts(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    rule_id: str | None = Query(default=None),
    actor_id: str | None = Query(default=None),
    ctx: AuthContext = Depends(require_permission("detector:read")),
    db: Session = Depends(get_db),
) -> PaginatedResponse[AlertOut]:
    query = select(AlertRecord)
    count_q = select(func.count()).select_from(AlertRecord)
    if status is not None:
        query = query.where(AlertRecord.status == status)
        count_q = count_q.where(AlertRecord.status == status)
    if severity is not None:
        query = query.where(AlertRecord.severity == severity)
        count_q = count_q.where(AlertRecord.severity == severity)
    if rule_id is not None:
        query = query.where(AlertRecord.rule_id == rule_id)
        count_q = count_q.where(AlertRecord.rule_id == rule_id)
    if actor_id is not None:
        query = query.where(AlertRecord.actor_id == actor_id)
        count_q = count_q.where(AlertRecord.actor_id == actor_id)

    total = int(db.scalar(count_q) or 0)
    rows = list(db.scalars(query.order_by(AlertRecord.alert_time.desc()).limit(limit).offset(offset)).all())
    return PaginatedResponse[AlertOut](
        items=[_alert_to_out(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
        correlation_id=ctx.correlation_id,
    )


@router.get("/alerts/{alert_id}", response_model=AlertOut)
def get_alert_detail(
    alert_id: str,
    ctx: AuthContext = Depends(require_permission("detector:read")),
    db: Session = Depends(get_db),
) -> AlertOut:
    row = db.get(AlertRecord, alert_id)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "ALERT_NOT_FOUND", "message": f"Alert '{alert_id}' not found.", "correlation_id": ctx.correlation_id},
        )
    return _alert_to_out(row)


@router.post("/alerts/{alert_id}/acknowledge", response_model=AlertActionResponse)
def post_acknowledge_alert(
    alert_id: str,
    payload: AlertTransitionRequest,
    ctx: AuthContext = Depends(require_permission("detector:manage")),
    db: Session = Depends(get_db),
) -> AlertActionResponse:
    try:
        row = acknowledge_alert(
            db,
            alert_id=alert_id,
            actor_id=ctx.user.id,
            reason=payload.reason,
            confirmation=payload.confirmation,
            correlation_id=ctx.correlation_id,
        )
    except DetectorServiceError as exc:
        raise _err(exc, ctx.correlation_id) from None
    return AlertActionResponse(alert=_alert_to_out(row), correlation_id=ctx.correlation_id)


@router.post("/alerts/{alert_id}/resolve", response_model=AlertActionResponse)
def post_resolve_alert(
    alert_id: str,
    payload: AlertTransitionRequest,
    ctx: AuthContext = Depends(require_permission("detector:manage")),
    db: Session = Depends(get_db),
) -> AlertActionResponse:
    try:
        row = resolve_alert(
            db,
            alert_id=alert_id,
            actor_id=ctx.user.id,
            reason=payload.reason,
            confirmation=payload.confirmation,
            correlation_id=ctx.correlation_id,
        )
    except DetectorServiceError as exc:
        raise _err(exc, ctx.correlation_id) from None
    return AlertActionResponse(alert=_alert_to_out(row), correlation_id=ctx.correlation_id)


@router.post("/alerts/{alert_id}/false-positive", response_model=AlertActionResponse)
def post_false_positive_alert(
    alert_id: str,
    payload: AlertTransitionRequest,
    ctx: AuthContext = Depends(require_permission("detector:manage")),
    db: Session = Depends(get_db),
) -> AlertActionResponse:
    try:
        row = mark_alert_false_positive(
            db,
            alert_id=alert_id,
            actor_id=ctx.user.id,
            reason=payload.reason,
            confirmation=payload.confirmation,
            correlation_id=ctx.correlation_id,
        )
    except DetectorServiceError as exc:
        raise _err(exc, ctx.correlation_id) from None
    return AlertActionResponse(alert=_alert_to_out(row), correlation_id=ctx.correlation_id)
