"""Detector orchestration service: run management, deduplication, alert lifecycle & audit integration.

Crucially, recommendations NEVER automatically execute destructive control-plane actions
(no automatic key revocation, identity disabling, or node isolation).
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any
import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.audit.canonical import redact_sensitive_fields
from backend.app.audit.ledger import append_audit_event, audit_write_lock
from backend.app.db.models import AlertRecord, AuditEvent, DetectionRun, SettingEntry, utc_now
from backend.app.detector.config import DetectorConfig
from backend.app.detector.dataset import EVAL_DEFAULT_SEED, generate_synthetic_evaluation_dataset
from backend.app.detector.evaluation import evaluate_benchmark_dataset
from backend.app.detector.ingestion import (
    DetectorEvidenceError,
    ingest_event_records,
    ingest_from_audit_ledger,
)
from backend.app.detector.rules import CandidateAlert, evaluate_all_rules

DETECTOR_CONFIG_SETTING_KEY = "detector_rule_config_json"


class DetectorServiceError(Exception):
    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


def load_active_detector_config(db: Session) -> DetectorConfig:
    entry = db.get(SettingEntry, DETECTOR_CONFIG_SETTING_KEY)
    if entry is None or not entry.value:
        return DetectorConfig()
    try:
        raw = json.loads(entry.value)
        edges = raw.pop("allowed_service_edges", None)
        cfg = DetectorConfig(**{k: v for k, v in raw.items() if k in DetectorConfig.__dataclass_fields__})
        if isinstance(edges, list):
            cfg.allowed_service_edges = tuple((str(p[0]), str(p[1])) for p in edges if isinstance(p, (list, tuple)) and len(p) == 2)
        return cfg
    except Exception:
        return DetectorConfig()


def update_detector_config(
    db: Session,
    *,
    updates: dict[str, Any],
    actor_id: str,
    reason: str,
    confirmation: bool,
    correlation_id: str,
) -> DetectorConfig:
    if not confirmation:
        raise DetectorServiceError(400, "CONFIRMATION_REQUIRED", "Explicit confirmation is required to update rule configuration.")

    cfg = load_active_detector_config(db)
    cfg_dict = cfg.to_dict()
    for k, v in updates.items():
        if k in cfg_dict and v is not None:
            cfg_dict[k] = v

    edges = cfg_dict.pop("allowed_service_edges", None)
    new_cfg = DetectorConfig(**{k: v for k, v in cfg_dict.items() if k in DetectorConfig.__dataclass_fields__})
    if isinstance(edges, list):
        new_cfg.allowed_service_edges = tuple((str(p[0]), str(p[1])) for p in edges if isinstance(p, (list, tuple)) and len(p) == 2)

    serialized = json.dumps(new_cfg.to_dict(), separators=(",", ":"), sort_keys=True)
    with audit_write_lock():
        entry = db.get(SettingEntry, DETECTOR_CONFIG_SETTING_KEY)
        if entry is None:
            db.add(SettingEntry(key=DETECTOR_CONFIG_SETTING_KEY, value=serialized, updated_at=utc_now()))
        else:
            entry.value = serialized
            entry.updated_at = utc_now()
        append_audit_event(
            db,
            event_type="DETECTOR_CONFIG_UPDATED",
            event_category="DETECTOR",
            actor_id=actor_id,
            action="update_detector_config",
            target_type="detector_config",
            target_id=new_cfg.rule_set_version,
            outcome="ALLOW",
            reason_code="DETECTOR_RULES_UPDATED",
            correlation_id=correlation_id,
            source_component="detector_service",
            payload={"rule_set_version": new_cfg.rule_set_version, "updated_keys": sorted(updates.keys()), "reason": reason},
            commit=False,
        )
        db.commit()
    return new_cfg


def _persist_deduplicated_alerts(
    db: Session,
    candidates: list[CandidateAlert],
    *,
    run_id: str,
    actor_id: str,
    correlation_id: str,
) -> tuple[list[AlertRecord], int, int]:
    """Store CandidateAlerts deduplicated by stable SHA-256 fingerprint."""
    created_count = 0
    dedup_count = 0
    persisted: list[AlertRecord] = []

    for c in candidates:
        existing = db.scalar(
            select(AlertRecord)
            .where(
                AlertRecord.fingerprint == c.fingerprint,
                AlertRecord.status.in_(("OPEN", "ACKNOWLEDGED")),
            )
            .limit(1)
        )
        if existing is not None:
            # Merge additional event_refs cleanly without overwriting original evidence history
            old_refs = json.loads(existing.event_refs_json) if existing.event_refs_json else []
            merged_refs = list(dict.fromkeys(list(old_refs) + list(c.event_refs)))
            existing.event_refs_json = json.dumps(merged_refs)
            existing_last = existing.last_observed_at if existing.last_observed_at.tzinfo else existing.last_observed_at.replace(tzinfo=timezone.utc)
            cand_last = c.last_observed_at if c.last_observed_at.tzinfo else c.last_observed_at.replace(tzinfo=timezone.utc)
            existing.last_observed_at = max(existing_last, cand_last)
            persisted.append(existing)
            dedup_count += 1
            continue

        clean_expl = json.loads(json.dumps(redact_sensitive_fields({"msg": c.explanation})))["msg"]
        alert_id = f"alt-{uuid.uuid4().hex[:14]}"
        row = AlertRecord(
            id=alert_id,
            rule_id=c.rule_id,
            rule_version=c.rule_version,
            fingerprint=c.fingerprint,
            severity=c.severity,
            confidence=c.confidence,
            explanation=str(clean_expl),
            actor_id=c.actor_id,
            device_id=c.device_id,
            session_id=c.session_id,
            node_id=c.node_id,
            resource_id=c.resource_id,
            services_json=json.dumps(list(c.services)),
            event_refs_json=json.dumps(list(c.event_refs)),
            reason_codes_json=json.dumps(list(c.reason_codes)),
            recommended_response=c.recommended_response,
            detection_window_sec=c.detection_window_sec,
            first_observed_at=c.first_observed_at,
            last_observed_at=c.last_observed_at,
            run_id=run_id,
            alert_time=utc_now(),
            status="OPEN",
        )
        db.add(row)
        persisted.append(row)
        created_count += 1
        append_audit_event(
            db,
            event_type="DETECTOR_ALERT_CREATED",
            event_category="DETECTOR",
            actor_id=actor_id,
            action="create_alert",
            target_type="alert",
            target_id=alert_id,
            outcome="ALLOW",
            reason_code=c.rule_id,
            correlation_id=correlation_id,
            source_component="detector_service",
            payload={
                "run_id": run_id,
                "rule_id": c.rule_id,
                "rule_version": c.rule_version,
                "severity": c.severity,
                "fingerprint": c.fingerprint,
                "subject_actor_id": c.actor_id,
                "event_refs": list(c.event_refs),
            },
            commit=False,
        )

    return persisted, created_count, dedup_count


def run_detection(
    db: Session,
    *,
    source: str = "audit_ledger",
    actor_id: str,
    correlation_id: str,
    start_sequence: int | None = None,
    end_sequence: int | None = None,
    custom_events: list[dict[str, Any]] | None = None,
    approvals: list[dict[str, Any]] | None = None,
    seed: int = EVAL_DEFAULT_SEED,
    config_override: DetectorConfig | None = None,
) -> tuple[DetectionRun, list[AlertRecord], dict[str, Any] | None]:
    """Execute a deterministic detection run with audit tracking and tamper preconditions."""
    cfg = config_override or load_active_detector_config(db)
    if approvals:
        cfg = DetectorConfig(**{**cfg.__dict__, "approvals": list(approvals)})

    pre_run_max_seq = int(db.scalar(select(func.coalesce(func.max(AuditEvent.sequence), 0))) or 0)
    run_id = f"detrun-{uuid.uuid4().hex[:12]}"
    append_audit_event(
        db,
        event_type="DETECTOR_RUN_STARTED",
        event_category="DETECTOR",
        actor_id=actor_id,
        action="run_detector",
        target_type="detection_run",
        target_id=run_id,
        outcome="ALLOW",
        reason_code="DETECTOR_RUN_INITIATED",
        correlation_id=correlation_id,
        source_component="detector_service",
        payload={"source": source, "rule_set_version": cfg.rule_set_version},
        commit=True,
    )

    metrics_dict: dict[str, Any] | None = None
    dataset_name = source
    dataset_version = "live.audit.v1"
    chain_verified = True
    warnings: list[str] = []

    if source == "audit_ledger":
        effective_end = end_sequence if end_sequence is not None else (pre_run_max_seq if pre_run_max_seq > 0 else None)
        try:
            if pre_run_max_seq == 0 and start_sequence is None and end_sequence is None:
                norm_events = []
                warnings = ["MISSING_EVIDENCE: Audit ledger contained 0 prior events before detector run."]
                chain_verified = True
            else:
                norm_events, warnings, chain_verified = ingest_from_audit_ledger(
                    db, config=cfg, start_sequence=start_sequence, end_sequence=effective_end
                )
        except DetectorEvidenceError as exc:
            run_row = DetectionRun(
                run_id=run_id,
                dataset_name="audit_ledger",
                dataset_version="live.audit.v1",
                rule_set_version=cfg.rule_set_version,
                config_json=json.dumps(cfg.to_dict(), separators=(",", ":"), sort_keys=True),
                events_inspected=0,
                alerts_created=0,
                alerts_deduplicated=0,
                audit_chain_verified=False,
                status="FAILED_CLOSED",
                metrics_json="{}",
                summary_detail=exc.message,
                created_by=actor_id,
                created_at=utc_now(),
            )
            with audit_write_lock():
                db.add(run_row)
                append_audit_event(
                    db,
                    event_type="DETECTOR_RUN_FAILED_CLOSED",
                    event_category="DETECTOR",
                    actor_id=actor_id,
                    action="run_detector",
                    target_type="detection_run",
                    target_id=run_id,
                    outcome="DENY",
                    reason_code=exc.code,
                    correlation_id=correlation_id,
                    source_component="detector_service",
                    payload={"error": exc.message},
                    commit=False,
                )
                db.commit()
            raise DetectorServiceError(exc.status_code, exc.code, exc.message) from None
        candidates = evaluate_all_rules(norm_events, config=cfg)

    elif source == "synthetic_benchmark":
        ds = generate_synthetic_evaluation_dataset(seed=seed)
        dataset_name = ds.dataset_name
        dataset_version = ds.dataset_version
        metrics_rep, candidates = evaluate_benchmark_dataset(ds, config=cfg)
        metrics_dict = metrics_rep.to_dict()
        norm_events = ds.events  # count reference only

    elif source == "custom_events":
        if custom_events is None:
            raise DetectorServiceError(400, "MISSING_EVENTS", "custom_events payload is required.")
        if len(custom_events) > 5000:
            raise DetectorServiceError(400, "DETECTOR_INPUT_LIMIT", "Maximum 5000 events per evaluation request.")
        norm_events, warnings = ingest_event_records(custom_events, config=cfg)
        candidates = evaluate_all_rules(norm_events, config=cfg)
        dataset_version = "custom.v1"
    else:
        raise DetectorServiceError(400, "INVALID_DETECTOR_SOURCE", f"Unsupported detector source: {source}")

    run_status = "DEGRADED_MISSING_EVIDENCE" if warnings else "COMPLETED"
    summary_msg = "; ".join(warnings) if warnings else f"Inspected {len(norm_events)} event(s); emitted {len(candidates)} candidate alert(s)."

    with audit_write_lock():
        persisted_alerts, created_count, dedup_count = _persist_deduplicated_alerts(
            db, candidates, run_id=run_id, actor_id=actor_id, correlation_id=correlation_id
        )
        run_row = DetectionRun(
            run_id=run_id,
            dataset_name=dataset_name,
            dataset_version=dataset_version,
            rule_set_version=cfg.rule_set_version,
            config_json=json.dumps(cfg.to_dict(), separators=(",", ":"), sort_keys=True),
            events_inspected=len(norm_events),
            alerts_created=created_count,
            alerts_deduplicated=dedup_count,
            audit_chain_verified=chain_verified,
            status=run_status,
            metrics_json=json.dumps(metrics_dict or {}, separators=(",", ":"), sort_keys=True),
            summary_detail=summary_msg,
            created_by=actor_id,
            created_at=utc_now(),
        )
        db.add(run_row)
        append_audit_event(
            db,
            event_type="DETECTOR_RUN_COMPLETED",
            event_category="DETECTOR",
            actor_id=actor_id,
            action="run_detector",
            target_type="detection_run",
            target_id=run_id,
            outcome="ALLOW",
            reason_code=run_status,
            correlation_id=correlation_id,
            source_component="detector_service",
            payload={
                "source": source,
                "events_inspected": len(norm_events),
                "alerts_created": created_count,
                "alerts_deduplicated": dedup_count,
            },
            commit=False,
        )
        db.commit()
    db.refresh(run_row)
    return run_row, persisted_alerts, metrics_dict


def _transition_alert_status(
    db: Session,
    *,
    alert_id: str,
    target_status: str,
    event_type: str,
    actor_id: str,
    reason: str,
    confirmation: bool,
    correlation_id: str,
) -> AlertRecord:
    if not confirmation:
        raise DetectorServiceError(400, "CONFIRMATION_REQUIRED", "Explicit confirmation is required for alert transitions.")
    row = db.get(AlertRecord, alert_id)
    if row is None:
        raise DetectorServiceError(404, "ALERT_NOT_FOUND", f"Alert '{alert_id}' does not exist.")
    prev = row.status
    with audit_write_lock():
        row.status = target_status
        row.resolution_note = reason
        row.reviewed_by = actor_id
        row.reviewed_at = utc_now()
        append_audit_event(
            db,
            event_type=event_type,
            event_category="DETECTOR",
            actor_id=actor_id,
            action=f"alert_{target_status.lower()}",
            target_type="alert",
            target_id=alert_id,
            outcome="ALLOW",
            reason_code=f"ALERT_STATUS_{target_status}",
            correlation_id=correlation_id,
            source_component="detector_service",
            payload={"from_status": prev, "to_status": target_status, "rule_id": row.rule_id, "reason": reason},
            commit=False,
        )
        db.commit()
    db.refresh(row)
    return row


def acknowledge_alert(
    db: Session, *, alert_id: str, actor_id: str, reason: str, confirmation: bool, correlation_id: str
) -> AlertRecord:
    return _transition_alert_status(
        db,
        alert_id=alert_id,
        target_status="ACKNOWLEDGED",
        event_type="DETECTOR_ALERT_ACKNOWLEDGED",
        actor_id=actor_id,
        reason=reason,
        confirmation=confirmation,
        correlation_id=correlation_id,
    )


def resolve_alert(
    db: Session, *, alert_id: str, actor_id: str, reason: str, confirmation: bool, correlation_id: str
) -> AlertRecord:
    return _transition_alert_status(
        db,
        alert_id=alert_id,
        target_status="RESOLVED",
        event_type="DETECTOR_ALERT_RESOLVED",
        actor_id=actor_id,
        reason=reason,
        confirmation=confirmation,
        correlation_id=correlation_id,
    )


def mark_alert_false_positive(
    db: Session, *, alert_id: str, actor_id: str, reason: str, confirmation: bool, correlation_id: str
) -> AlertRecord:
    return _transition_alert_status(
        db,
        alert_id=alert_id,
        target_status="FALSE_POSITIVE",
        event_type="DETECTOR_ALERT_FALSE_POSITIVE",
        actor_id=actor_id,
        reason=reason,
        confirmation=confirmation,
        correlation_id=correlation_id,
    )
