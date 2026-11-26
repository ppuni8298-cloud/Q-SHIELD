"""Read-only cryptographic audit chain verifier.

Detects all integrity & ordering attacks without repairing or rewriting history:
- Modified payload, event_hash, or prev_hash
- Missing/deleted events, sequence gaps, duplicate sequences
- Reordered events, inserted events, invalid genesis record
- Invalid canonical serialization or unsupported schema_version
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.audit.canonical import (
    AUDIT_GENESIS_PREV_HASH,
    AUDIT_HASH_ALGORITHM,
    AUDIT_LEDGER_ID,
    AUDIT_SCHEMA_VERSION,
    build_audit_event_body,
    canonical_json_bytes,
    compute_audit_event_hash,
    event_model_to_dict,
)
from backend.app.db.models import AuditEvent, utc_now


@dataclass(frozen=True)
class AuditVerificationResult:
    valid: bool
    ledger_id: str
    verified_event_count: int
    total_events_inspected: int
    first_sequence: int | None
    last_sequence: int | None
    head_hash: str | None
    first_invalid_sequence: int | None
    first_invalid_event_id: str | None
    failure_category: str | None
    expected_hash: str | None
    actual_hash: str | None
    detail: str
    verified_at: datetime


def verify_audit_records(
    records: Sequence[Mapping[str, Any]],
    *,
    expected_first_sequence: int = 1,
    expected_prev_hash: str = AUDIT_GENESIS_PREV_HASH,
    require_genesis: bool = True,
    ledger_id: str = AUDIT_LEDGER_ID,
) -> AuditVerificationResult:
    """Verify a chronological sequence of audit event mappings strictly read-only."""
    now = utc_now()
    total = len(records)
    if total == 0:
        return AuditVerificationResult(
            valid=True,
            ledger_id=ledger_id,
            verified_event_count=0,
            total_events_inspected=0,
            first_sequence=None,
            last_sequence=None,
            head_hash=None,
            first_invalid_sequence=None,
            first_invalid_event_id=None,
            failure_category=None,
            expected_hash=None,
            actual_hash=None,
            detail="Audit range contains 0 events.",
            verified_at=now,
        )

    verified = 0
    seen_sequences: set[int] = set()
    prev_seq: int | None = None
    prev_hash_expected = expected_prev_hash
    first_seq_seen: int | None = None
    last_hash_seen: str | None = None

    def _fail(
        seq: int | None,
        ev_id: str | None,
        category: str,
        detail: str,
        exp_h: str | None = None,
        act_h: str | None = None,
    ) -> AuditVerificationResult:
        return AuditVerificationResult(
            valid=False,
            ledger_id=ledger_id,
            verified_event_count=verified,
            total_events_inspected=total,
            first_sequence=first_seq_seen,
            last_sequence=prev_seq,
            head_hash=last_hash_seen,
            first_invalid_sequence=seq,
            first_invalid_event_id=ev_id,
            failure_category=category,
            expected_hash=exp_h,
            actual_hash=act_h,
            detail=detail,
            verified_at=now,
        )

    required_keys = {
        "sequence",
        "event_id",
        "event_type",
        "event_category",
        "timestamp_utc",
        "actor_id",
        "target_type",
        "target_id",
        "action",
        "reason_code",
        "correlation_id",
        "source_component",
        "prev_hash",
        "event_hash",
        "hash_algorithm",
        "schema_version",
    }

    for idx, rec in enumerate(records):
        ev_id = str(rec.get("event_id")) if rec.get("event_id") is not None else None
        raw_seq = rec.get("sequence")
        try:
            seq = int(raw_seq)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return _fail(None, ev_id, "INVALID_SEQUENCE", "Event sequence is missing or non-integer.")

        if idx == 0:
            first_seq_seen = seq

        if not required_keys.issubset(rec.keys()) or ("outcome" not in rec and "decision" not in rec):
            return _fail(seq, ev_id, "INVALID_CANONICAL_SERIALIZATION", "Event record is missing required fields.")

        if str(rec.get("schema_version")) != AUDIT_SCHEMA_VERSION:
            return _fail(
                seq,
                ev_id,
                "INVALID_SCHEMA_VERSION",
                f"Unsupported audit schema_version '{rec.get('schema_version')}'.",
            )
        if str(rec.get("hash_algorithm")) != AUDIT_HASH_ALGORITHM:
            return _fail(
                seq,
                ev_id,
                "INVALID_HASH_ALGORITHM",
                f"Unsupported hash_algorithm '{rec.get('hash_algorithm')}'.",
            )

        # Check sequence ordering, duplicates, gaps, and genesis invariants
        if seq in seen_sequences:
            return _fail(seq, ev_id, "DUPLICATE_SEQUENCE", f"Duplicate audit sequence {seq} detected.")
        seen_sequences.add(seq)

        if idx == 0:
            if require_genesis and seq != 1:
                return _fail(
                    seq,
                    ev_id,
                    "MISSING_GENESIS_OR_SEQUENCE_GAP",
                    f"Expected genesis sequence 1, found {seq}.",
                )
            if not require_genesis and seq != expected_first_sequence:
                return _fail(
                    seq,
                    ev_id,
                    "SEQUENCE_GAP",
                    f"Expected starting sequence {expected_first_sequence}, found {seq}.",
                )
        else:
            assert prev_seq is not None
            if seq < prev_seq:
                return _fail(
                    seq,
                    ev_id,
                    "REORDERED_EVENTS",
                    f"Sequence {seq} appears after higher sequence {prev_seq}.",
                )
            if seq != prev_seq + 1:
                return _fail(
                    seq,
                    ev_id,
                    "SEQUENCE_GAP_OR_DELETED_EVENT",
                    f"Sequence jumped from {prev_seq} to {seq} (missing event).",
                )

        stored_prev = str(rec.get("prev_hash", ""))
        if idx == 0 and require_genesis:
            if stored_prev != AUDIT_GENESIS_PREV_HASH:
                return _fail(
                    seq,
                    ev_id,
                    "INVALID_GENESIS_RECORD",
                    "Genesis event prev_hash does not match AUDIT_GENESIS_PREV_HASH.",
                    exp_h=AUDIT_GENESIS_PREV_HASH,
                    act_h=stored_prev,
                )
        elif stored_prev != prev_hash_expected:
            return _fail(
                seq,
                ev_id,
                "PREV_HASH_MISMATCH",
                f"Previous hash mismatch at sequence {seq}.",
                exp_h=prev_hash_expected,
                act_h=stored_prev,
            )

        # Validate payload JSON / structure and canonical serialization
        try:
            if "payload" in rec:
                payload_obj = rec["payload"]
            elif "payload_json" in rec:
                payload_obj = json.loads(str(rec["payload_json"]))
            else:
                return _fail(seq, ev_id, "INVALID_CANONICAL_SERIALIZATION", "Payload is missing.")
            if not isinstance(payload_obj, dict):
                return _fail(seq, ev_id, "INVALID_CANONICAL_SERIALIZATION", "Payload must be a JSON object.")

            outcome_val = str(rec.get("outcome") if "outcome" in rec else rec.get("decision"))
            body = build_audit_event_body(
                schema_version=str(rec["schema_version"]),
                hash_algorithm=str(rec["hash_algorithm"]),
                sequence=seq,
                event_id=str(rec["event_id"]),
                timestamp_utc=rec["timestamp_utc"],
                event_type=str(rec["event_type"]),
                event_category=str(rec["event_category"]),
                actor_id=str(rec["actor_id"]),
                target_type=str(rec["target_type"]),
                target_id=str(rec["target_id"]),
                action=str(rec["action"]),
                outcome=outcome_val,
                reason_code=str(rec["reason_code"]),
                correlation_id=str(rec["correlation_id"]),
                source_component=str(rec["source_component"]),
                payload=payload_obj,
                prev_hash=stored_prev,
            )
            canonical_json_bytes(body)
            expected_event_hash = compute_audit_event_hash(
                prev_hash=stored_prev,
                sequence=seq,
                canonical_body=body,
            )
        except Exception as exc:
            return _fail(
                seq,
                ev_id,
                "INVALID_CANONICAL_SERIALIZATION",
                f"Canonical serialization or timestamp validation failed at sequence {seq}: {exc}",
            )

        stored_hash = str(rec.get("event_hash", ""))
        if expected_event_hash != stored_hash:
            return _fail(
                seq,
                ev_id,
                "EVENT_HASH_OR_PAYLOAD_MISMATCH",
                f"Event digest mismatch at sequence {seq} (modified payload, metadata, or event_hash).",
                exp_h=expected_event_hash,
                act_h=stored_hash,
            )

        verified += 1
        prev_seq = seq
        prev_hash_expected = expected_event_hash
        last_hash_seen = expected_event_hash

    return AuditVerificationResult(
        valid=True,
        ledger_id=ledger_id,
        verified_event_count=verified,
        total_events_inspected=total,
        first_sequence=first_seq_seen,
        last_sequence=prev_seq,
        head_hash=last_hash_seen,
        first_invalid_sequence=None,
        first_invalid_event_id=None,
        failure_category=None,
        expected_hash=None,
        actual_hash=None,
        detail=f"Verified {verified} audit event(s) cleanly with intact SHA-256 chain.",
        verified_at=now,
    )


def verify_ledger_db(
    db: Session,
    *,
    start_sequence: int | None = None,
    end_sequence: int | None = None,
) -> AuditVerificationResult:
    """Read-only database chain verifier supporting full-ledger or bounded sequence range checks."""
    stmt = select(AuditEvent)
    if start_sequence is not None:
        stmt = stmt.where(AuditEvent.sequence >= start_sequence)
    if end_sequence is not None:
        stmt = stmt.where(AuditEvent.sequence <= end_sequence)
    rows = list(db.scalars(stmt.order_by(AuditEvent.sequence.asc())).all())
    dicts = [event_model_to_dict(r) for r in rows]

    req_first = start_sequence if start_sequence is not None else 1
    req_genesis = req_first == 1
    expected_prev = AUDIT_GENESIS_PREV_HASH
    if not req_genesis and dicts:
        pred = db.scalar(select(AuditEvent).where(AuditEvent.sequence == req_first - 1))
        if pred is None:
            return AuditVerificationResult(
                valid=False,
                ledger_id=AUDIT_LEDGER_ID,
                verified_event_count=0,
                total_events_inspected=len(dicts),
                first_sequence=dicts[0]["sequence"],
                last_sequence=dicts[-1]["sequence"],
                head_hash=dicts[-1]["event_hash"],
                first_invalid_sequence=req_first - 1,
                first_invalid_event_id=None,
                failure_category="MISSING_PREDECESSOR_EVENT",
                expected_hash=None,
                actual_hash=None,
                detail=f"Predecessor sequence {req_first - 1} is missing.",
                verified_at=utc_now(),
            )
        expected_prev = str(pred.event_hash)

    return verify_audit_records(
        dicts,
        expected_first_sequence=req_first,
        expected_prev_hash=expected_prev,
        require_genesis=req_genesis,
    )
