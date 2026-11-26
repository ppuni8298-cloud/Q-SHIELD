"""Event ingestion, audit-chain precondition validation, clock-offset normalization, and label isolation.

Crucially, NormalizedDetectorEvent contains NO ground-truth label attribute: scoring rules
cannot observe labels from CSVs, JSONL fixtures, or DetectorEvent database rows.
"""

from __future__ import annotations

from collections.abc import Sequence
import csv
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.audit.canonical import canonical_json_bytes
from backend.app.audit.verifier import verify_ledger_db
from backend.app.auth.tokens import ensure_utc
from backend.app.db.models import AuditEvent
from backend.app.detector.config import DetectorConfig


class DetectorEvidenceError(Exception):
    """Raised when ledger integrity fails or critical detection inputs are invalid/missing."""

    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


@dataclass(frozen=True)
class NormalizedDetectorEvent:
    """Sanitized event representation without ground-truth labels or secret payloads."""

    event_id: str
    sequence: int | None
    event_time_utc: datetime
    received_time_utc: datetime
    corrected_event_time_utc: datetime
    source_clock_offset_ms: int
    uncertain_order: bool
    actor_id: str
    device_id: str | None
    session_id: str | None
    node_id: str | None
    resource_id: str | None
    resource_category: str
    source_service: str
    target_service: str
    event_type: str
    event_category: str
    action: str
    outcome: str
    reason_code: str
    role_before: str | None
    role_after: str | None
    approval_id: str | None
    correlation_id: str
    payload_digest: str
    is_retry_hint: bool
    sim_clock_ms: int | None
    latency_ms: int | None
    propagation_status: str | None
    receipt_index: int = 0
    extra_meta: dict[str, Any] = field(default_factory=dict)


def parse_utc(val: datetime | str | None, fallback: datetime | None = None) -> datetime:
    if isinstance(val, datetime):
        return ensure_utc(val).astimezone(timezone.utc)
    if isinstance(val, str) and val.strip():
        return ensure_utc(datetime.fromisoformat(val.strip().replace("Z", "+00:00"))).astimezone(timezone.utc)
    if fallback is not None:
        return fallback
    return datetime.now(timezone.utc)


def _flag_uncertain_intervals(events: list[NormalizedDetectorEvent], reorder_window_ms: int) -> list[NormalizedDetectorEvent]:
    """Flag events whose corrected clock +/- uncertainty window overlaps adjacent events of different receipt order."""
    if len(events) < 2:
        return events
    half_win = timedelta(milliseconds=max(500, reorder_window_ms // 2))
    out: list[NormalizedDetectorEvent] = []
    for idx, ev in enumerate(events):
        uncertain = ev.uncertain_order
        if ev.receipt_index > 0:
            prev_receipt = events[idx - 1]
            if (
                ev.corrected_event_time_utc < prev_receipt.corrected_event_time_utc
                or abs((ev.corrected_event_time_utc - prev_receipt.corrected_event_time_utc).total_seconds() * 1000.0) <= half_win.total_seconds() * 1000.0
            ) and ev.actor_id == prev_receipt.actor_id:
                if ev.corrected_event_time_utc < prev_receipt.corrected_event_time_utc:
                    uncertain = True
        out.append(
            NormalizedDetectorEvent(
                **{**ev.__dict__, "uncertain_order": uncertain}
            )
        )
    return out


def normalize_event_mapping(raw: dict[str, Any], *, receipt_index: int = 0) -> NormalizedDetectorEvent:
    """Normalize either AuditEvent-shaped dicts or toolkit/JSONL telemetry rows, stripping any 'label'."""
    raw_clean = {k: v for k, v in raw.items() if k not in ("label", "ground_truth", "truth_label")}
    payload = raw_clean.get("payload")
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except ValueError:
            payload = {}
    elif not isinstance(payload, dict):
        payload = {}

    ev_id = str(raw_clean.get("event_id") or raw_clean.get("id") or f"evt-anon-{receipt_index}")
    seq_val = raw_clean.get("sequence")
    sequence = int(seq_val) if seq_val is not None and str(seq_val).isdigit() else None

    ev_time_raw = raw_clean.get("event_time_utc") or raw_clean.get("timestamp_utc") or raw_clean.get("event_time")
    rx_time_raw = raw_clean.get("received_time_utc") or raw_clean.get("ingest_time") or ev_time_raw
    ev_time = parse_utc(ev_time_raw)
    rx_time = parse_utc(rx_time_raw, fallback=ev_time)
    offset_ms = int(raw_clean.get("source_clock_offset_ms") if raw_clean.get("source_clock_offset_ms") is not None else payload.get("source_clock_offset_ms", 0))
    corrected = ev_time - timedelta(milliseconds=offset_ms)

    actor_id = str(raw_clean.get("actor_id") or raw_clean.get("actor") or "unknown")
    device_id = raw_clean.get("device_id") or payload.get("device_id")
    session_id = raw_clean.get("session_id") or payload.get("session_id") or (raw_clean.get("target_id") if raw_clean.get("target_type") == "session" else None)
    node_id = raw_clean.get("node_id") or payload.get("node_id") or (raw_clean.get("target_id") if raw_clean.get("target_type") == "node" else None)
    resource_id = raw_clean.get("resource_id") or payload.get("resource_id") or (raw_clean.get("target_id") if raw_clean.get("target_type") == "resource" else None)
    resource_cat = str(raw_clean.get("resource_category") or payload.get("resource_category") or payload.get("classification") or raw_clean.get("target_service") or "general")

    src_svc = str(raw_clean.get("source_service") or payload.get("source_service") or raw_clean.get("source_component") or "portal")
    tgt_svc = str(raw_clean.get("target_service") or payload.get("target_service") or raw_clean.get("target_type") or "catalog")
    action = str(raw_clean.get("action") or "unknown")
    ev_type = str(raw_clean.get("event_type") or f"{src_svc}:{action}".upper())
    ev_cat = str(raw_clean.get("event_category") or "GENERAL")
    outcome = str(raw_clean.get("outcome") or raw_clean.get("decision") or "ALLOW").upper()
    reason_code = str(raw_clean.get("reason_code") or payload.get("reason_code") or outcome)
    role_before = raw_clean.get("role_before") or payload.get("from_role")
    role_after = raw_clean.get("role_after") or payload.get("to_role")
    approval_id = raw_clean.get("approval_id") or payload.get("approval_id") or None
    if approval_id == "":
        approval_id = None
    corr_id = str(raw_clean.get("correlation_id") or payload.get("correlation_id") or f"corr-{ev_id}")

    # Strip volatile delivery/sequence fields from payload digest so duplicates are accurately identified
    digest_basis = {
        "actor_id": actor_id,
        "action": action,
        "target_service": tgt_svc,
        "resource_id": resource_id,
        "payload": payload,
    }
    p_digest = hashlib.sha256(canonical_json_bytes(digest_basis)).hexdigest()

    is_retry = bool(raw_clean.get("is_retry_hint") or payload.get("is_retry"))
    sim_clock = raw_clean.get("sim_clock_ms") if raw_clean.get("sim_clock_ms") is not None else payload.get("sim_clock_ms")
    sim_clock_int = int(sim_clock) if sim_clock is not None and str(sim_clock) != "" else None
    lat = raw_clean.get("latency_ms") if raw_clean.get("latency_ms") is not None else payload.get("convergence_time_ms") or payload.get("latency_ms")
    lat_int = int(lat) if lat is not None and str(lat) != "" else None
    prop_status = raw_clean.get("propagation_status") or payload.get("propagation_status")

    return NormalizedDetectorEvent(
        event_id=ev_id,
        sequence=sequence,
        event_time_utc=ev_time,
        received_time_utc=rx_time,
        corrected_event_time_utc=corrected,
        source_clock_offset_ms=offset_ms,
        uncertain_order=False,
        actor_id=actor_id,
        device_id=str(device_id) if device_id else None,
        session_id=str(session_id) if session_id else None,
        node_id=str(node_id) if node_id else None,
        resource_id=str(resource_id) if resource_id else None,
        resource_category=resource_cat,
        source_service=src_svc,
        target_service=tgt_svc,
        event_type=ev_type,
        event_category=ev_cat,
        action=action,
        outcome=outcome,
        reason_code=reason_code,
        role_before=str(role_before) if role_before else None,
        role_after=str(role_after) if role_after else None,
        approval_id=str(approval_id) if approval_id else None,
        correlation_id=corr_id,
        payload_digest=p_digest,
        is_retry_hint=is_retry,
        sim_clock_ms=sim_clock_int,
        latency_ms=lat_int,
        propagation_status=str(prop_status) if prop_status else None,
        receipt_index=receipt_index,
        extra_meta={"from_key_id": payload.get("from_key_id"), "to_key_id": payload.get("to_key_id")},
    )


def ingest_event_records(
    raw_events: Sequence[dict[str, Any]],
    *,
    config: DetectorConfig,
) -> tuple[list[NormalizedDetectorEvent], list[str]]:
    """Ingest external/synthetic events cleanly while stripping ground-truth labels."""
    warnings: list[str] = []
    if not raw_events:
        warnings.append("MISSING_EVIDENCE: Event input stream is empty.")
        return [], warnings

    normalized = [normalize_event_mapping(dict(item), receipt_index=idx) for idx, item in enumerate(raw_events)]
    flagged = _flag_uncertain_intervals(normalized, config.reorder_window_ms)
    return flagged, warnings


def ingest_from_audit_ledger(
    db: Session,
    *,
    config: DetectorConfig,
    start_sequence: int | None = None,
    end_sequence: int | None = None,
) -> tuple[list[NormalizedDetectorEvent], list[str], bool]:
    """Verify live audit ledger integrity FIRST, then normalize events for deterministic scoring.

    Fails closed (raises DetectorEvidenceError) if audit hash chain verification detects tampering.
    """
    ver = verify_ledger_db(db, start_sequence=start_sequence, end_sequence=end_sequence)
    if not ver.valid:
        raise DetectorEvidenceError(
            409,
            "AUDIT_CHAIN_INVALID",
            f"Refusing trusted detection over invalid audit chain (seq={ver.first_invalid_sequence}, reason={ver.failure_category}).",
        )

    stmt = select(AuditEvent)
    if start_sequence is not None:
        stmt = stmt.where(AuditEvent.sequence >= start_sequence)
    if end_sequence is not None:
        stmt = stmt.where(AuditEvent.sequence <= end_sequence)
    rows = list(db.scalars(stmt.order_by(AuditEvent.sequence.asc())).all())
    if not rows:
        return [], ["MISSING_EVIDENCE: Audit ledger returned 0 events for requested range."], True

    raw_dicts = [
        {
            "event_id": r.event_id,
            "sequence": r.sequence,
            "event_type": r.event_type,
            "event_category": r.event_category,
            "timestamp_utc": r.timestamp_utc,
            "actor_id": r.actor_id,
            "action": r.action,
            "target_type": r.target_type,
            "target_id": r.target_id,
            "outcome": r.decision,
            "reason_code": r.reason_code,
            "correlation_id": r.correlation_id,
            "source_service": r.source_component,
            "payload": r.payload_json,
        }
        for r in rows
    ]
    events, warnings = ingest_event_records(raw_dicts, config=config)
    return events, warnings, True


def load_practice_csv_events(csv_path: Path, approvals_path: Path | None = None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Load Track-4-Toolkit practice events CSV and optional approvals.json safely."""
    with csv_path.open("r", encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    approvals: list[dict[str, Any]] = []
    if approvals_path is not None and approvals_path.is_file():
        data = json.loads(approvals_path.read_text(encoding="utf-8"))
        approvals = list(data.get("changes", []))
    return rows, approvals


def load_jsonl_events(jsonl_path: Path, *, config: DetectorConfig | None = None) -> tuple[list[NormalizedDetectorEvent], list[str]]:
    """Load curated JSONL event fixture safely, skipping malformed/NaN/non-object lines with warnings."""
    import math

    warnings: list[str] = []
    valid_raw: list[dict[str, Any]] = []

    def _reject_constant(val: str) -> Any:
        raise ValueError(f"Forbidden non-standard JSON constant: {val}")

    for line_no, line in enumerate(jsonl_path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            parsed = json.loads(stripped, parse_constant=_reject_constant)
        except ValueError as exc:
            warnings.append(f"MALFORMED_JSONL_LINE:{line_no}:{exc}")
            continue
        if not isinstance(parsed, dict):
            warnings.append(f"NON_OBJECT_JSONL_LINE:{line_no}")
            continue
        # Double-check finite numbers
        bad_float = any(isinstance(v, float) and not math.isfinite(v) for v in parsed.values())
        if bad_float:
            warnings.append(f"NON_FINITE_NUMBER:{line_no}")
            continue
        valid_raw.append(parsed)

    cfg = config or DetectorConfig()
    norm, ing_warnings = ingest_event_records(valid_raw, config=cfg)
    return norm, warnings + ing_warnings
