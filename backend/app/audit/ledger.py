"""Append-only audit ledger service, ORM mutation guards, concurrent writer serialization, and outbox fallback."""

from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
import threading
import time
from typing import Any
import uuid

from sqlalchemy import event, select
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from backend.app.audit.canonical import (
    AUDIT_GENESIS_PREV_HASH,
    AUDIT_HASH_ALGORITHM,
    AUDIT_SCHEMA_VERSION,
    build_audit_event_body,
    canonical_json_str,
    compute_audit_event_hash,
    format_utc_timestamp,
    redact_sensitive_fields,
    sanitize_audit_text,
)
from backend.app.config import settings
from backend.app.db.models import AuditEvent, utc_now

_AUDIT_WRITE_LOCK = threading.RLock()
_APPEND_ONLY_GUARD_REGISTERED = False


def audit_write_lock() -> threading.RLock:
    """Return process-wide reentrant lock serializing audit tail-hash reads and atomic commits."""
    return _AUDIT_WRITE_LOCK


class AuditError(Exception):
    """Domain error for audit ledger, verifier, receipt, and export failures."""

    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


class AuditAppendOnlyError(AuditError):
    """Raised whenever application or ORM code attempts to mutate or delete an AuditEvent."""

    def __init__(self, message: str = "Audit ledger is strictly append-only; updates and deletions are forbidden.") -> None:
        super().__init__(409, "AUDIT_APPEND_ONLY_VIOLATION", message)


def register_append_only_guards() -> None:
    """Attach SQLAlchemy before_flush listener preventing ORM updates or deletions on AuditEvent."""
    global _APPEND_ONLY_GUARD_REGISTERED
    if _APPEND_ONLY_GUARD_REGISTERED:
        return

    @event.listens_for(Session, "before_flush")
    def _enforce_audit_append_only(session: Session, _flush_context: Any, _instances: Any) -> None:
        for obj in session.dirty:
            if isinstance(obj, AuditEvent) and session.is_modified(obj, include_collections=False):
                raise AuditAppendOnlyError("Modifying existing AuditEvent records through application ORM is forbidden.")
        for obj in session.deleted:
            if isinstance(obj, AuditEvent):
                raise AuditAppendOnlyError("Deleting existing AuditEvent records through application ORM is forbidden.")

    _APPEND_ONLY_GUARD_REGISTERED = True


register_append_only_guards()


def update_audit_event(*_args: Any, **_kwargs: Any) -> None:
    """Explicit service-layer guard rejecting historical audit event modification."""
    raise AuditAppendOnlyError("Audit events cannot be modified after append.")


def delete_audit_event(*_args: Any, **_kwargs: Any) -> None:
    """Explicit service-layer guard rejecting historical audit event deletion."""
    raise AuditAppendOnlyError("Audit events cannot be deleted.")


def _write_outbox_entry(record: dict[str, Any], outbox_path: Path | None = None) -> None:
    target = outbox_path or Path(settings.audit_outbox_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n")


def append_audit_event(
    db: Session,
    *,
    event_type: str,
    event_category: str,
    actor_id: str,
    action: str,
    target_type: str,
    target_id: str,
    outcome: str,
    reason_code: str,
    correlation_id: str,
    source_component: str,
    payload: dict[str, Any] | None = None,
    commit: bool = True,
    event_id: str | None = None,
    timestamp_utc: datetime | None = None,
    outbox_path: Path | None = None,
) -> AuditEvent:
    """Append a cryptographically chained event to the audit ledger safely under concurrency."""
    sanitized_payload = redact_sensitive_fields(payload or {})
    if not isinstance(sanitized_payload, dict):
        sanitized_payload = {"value": sanitized_payload}
    payload_str = canonical_json_str(sanitized_payload)

    clean_actor = sanitize_audit_text(actor_id or "anonymous")
    clean_action = sanitize_audit_text(action)
    clean_target_type = sanitize_audit_text(target_type)
    clean_target_id = sanitize_audit_text(target_id)
    clean_outcome = sanitize_audit_text(outcome)
    clean_reason = sanitize_audit_text(reason_code)
    clean_corr = sanitize_audit_text(correlation_id or f"corr-{uuid.uuid4().hex[:12]}")
    clean_type = sanitize_audit_text(event_type)
    clean_cat = sanitize_audit_text(event_category)
    clean_src = sanitize_audit_text(source_component)
    ev_id = event_id or f"audit-{uuid.uuid4().hex[:16]}"
    ev_time = timestamp_utc or utc_now()

    def _build_and_add() -> AuditEvent:
        db.flush()
        last = db.scalars(select(AuditEvent).order_by(AuditEvent.sequence.desc()).limit(1)).first()
        next_seq = (int(last.sequence) + 1) if last is not None else 1
        prev_hash = str(last.event_hash) if last is not None else AUDIT_GENESIS_PREV_HASH
        body = build_audit_event_body(
            schema_version=AUDIT_SCHEMA_VERSION,
            hash_algorithm=AUDIT_HASH_ALGORITHM,
            sequence=next_seq,
            event_id=ev_id,
            timestamp_utc=ev_time,
            event_type=clean_type,
            event_category=clean_cat,
            actor_id=clean_actor,
            target_type=clean_target_type,
            target_id=clean_target_id,
            action=clean_action,
            outcome=clean_outcome,
            reason_code=clean_reason,
            correlation_id=clean_corr,
            source_component=clean_src,
            payload=sanitized_payload,
            prev_hash=prev_hash,
        )
        ev_hash = compute_audit_event_hash(prev_hash=prev_hash, sequence=next_seq, canonical_body=body)
        row = AuditEvent(
            sequence=next_seq,
            event_id=ev_id,
            event_type=clean_type,
            event_category=clean_cat,
            timestamp_utc=ev_time,
            actor_id=clean_actor,
            action=clean_action,
            target_type=clean_target_type,
            target_id=clean_target_id,
            decision=clean_outcome,
            reason_code=clean_reason,
            correlation_id=clean_corr,
            source_component=clean_src,
            payload_json=payload_str,
            prev_hash=prev_hash,
            event_hash=ev_hash,
            hash_algorithm=AUDIT_HASH_ALGORITHM,
            schema_version=AUDIT_SCHEMA_VERSION,
        )
        db.add(row)
        db.flush()
        return row

    if not commit:
        with _AUDIT_WRITE_LOCK:
            return _build_and_add()

    last_exc: Exception | None = None
    for attempt in range(5):
        with _AUDIT_WRITE_LOCK:
            try:
                row = _build_and_add()
                db.commit()
                db.refresh(row)
                return row
            except (IntegrityError, OperationalError) as exc:
                db.rollback()
                last_exc = exc
                time.sleep(0.01 * (attempt + 1))
            except Exception as exc:
                db.rollback()
                _write_outbox_entry(
                    {
                        "event_id": ev_id,
                        "timestamp_utc": format_utc_timestamp(ev_time),
                        "event_type": clean_type,
                        "event_category": clean_cat,
                        "actor_id": clean_actor,
                        "target_type": clean_target_type,
                        "target_id": clean_target_id,
                        "action": clean_action,
                        "outcome": clean_outcome,
                        "reason_code": clean_reason,
                        "correlation_id": clean_corr,
                        "source_component": clean_src,
                        "payload": sanitized_payload,
                        "error": str(exc),
                    },
                    outbox_path=outbox_path,
                )
                raise AuditError(503, "AUDIT_WRITE_FAILED", "Audit ledger write failed; event captured in durable outbox.") from exc

    _write_outbox_entry(
        {
            "event_id": ev_id,
            "timestamp_utc": format_utc_timestamp(ev_time),
            "event_type": clean_type,
            "actor_id": clean_actor,
            "action": clean_action,
            "outcome": clean_outcome,
            "reason_code": clean_reason,
            "correlation_id": clean_corr,
            "error": str(last_exc) if last_exc else "retry_exhausted",
        },
        outbox_path=outbox_path,
    )
    raise AuditError(503, "AUDIT_WRITE_FAILED", "Audit ledger write failed under contention; captured in outbox.")


def record_audit_safe(db: Session, **kwargs: Any) -> AuditEvent | None:
    """Best-effort audit wrapper for already-denying error paths; falls back to outbox, never flips DENY to ALLOW."""
    try:
        return append_audit_event(db, **kwargs)
    except Exception:
        return None
