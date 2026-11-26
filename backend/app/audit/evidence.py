"""Signed ML-DSA-65 Audit Checkpoints, Evidence Receipts, Verifiable Exports & Standalone Verifier."""

from __future__ import annotations

import base64
import binascii
from typing import Any
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.audit.canonical import (
    AUDIT_CHECKPOINT_SCHEMA,
    AUDIT_EXPORT_SCHEMA,
    AUDIT_GENESIS_PREV_HASH,
    AUDIT_HASH_ALGORITHM,
    AUDIT_LEDGER_ID,
    AUDIT_RECEIPT_SCHEMA,
    canonical_json_bytes,
    event_model_to_dict,
    format_utc_timestamp,
    redact_sensitive_fields,
)
from backend.app.audit.ledger import AuditError
from backend.app.audit.verifier import AuditVerificationResult, verify_audit_records, verify_ledger_db
from backend.app.crypto.keystore import KeyStoreError, LocalEncryptedKeyStore
from backend.app.crypto.mldsa import MLDSA65Provider, MLDSAError
from backend.app.db.models import (
    AuditCheckpoint,
    AuditEvent,
    AuditEvidenceReceipt,
    SettingEntry,
    utc_now,
)

AUDIT_SIGNER_KEY_ID = "key-audit-signer-v1"
MAX_EXPORT_EVENTS = 5000


def _get_audit_signer_sk(keystore: LocalEncryptedKeyStore) -> bytes:
    try:
        return keystore.get_secret_bytes(AUDIT_SIGNER_KEY_ID, expected_purpose="audit")
    except KeyStoreError as exc:
        raise AuditError(503, "AUDIT_SIGNER_UNAVAILABLE", f"Audit signing key unavailable: {exc}") from None


def get_audit_public_key_b64(db: Session) -> str:
    entry = db.get(SettingEntry, "audit_signer_public_key_b64")
    if entry is None or not entry.value:
        raise AuditError(503, "AUDIT_PUBLIC_KEY_MISSING", "Audit signer public key is not provisioned.")
    return entry.value


def _checkpoint_signing_body(
    *,
    checkpoint_id: str,
    ledger_id: str,
    schema_version: str,
    first_sequence: int,
    last_sequence: int,
    root_hash: str,
    signature_algorithm: str,
    signer_key_id: str,
    created_at_iso: str,
) -> dict[str, Any]:
    return {
        "checkpoint_id": checkpoint_id,
        "ledger_id": ledger_id,
        "schema_version": schema_version,
        "first_sequence": int(first_sequence),
        "last_sequence": int(last_sequence),
        "root_hash": root_hash,
        "signature_algorithm": signature_algorithm,
        "signer_key_id": signer_key_id,
        "created_at": created_at_iso,
    }


def _receipt_signing_body(
    *,
    receipt_id: str,
    receipt_type: str,
    ledger_id: str,
    schema_version: str,
    event_id: str | None,
    sequence: int,
    first_sequence: int,
    last_sequence: int,
    event_hash: str,
    chain_head_hash: str,
    signature_algorithm: str,
    signer_key_id: str,
    created_at_iso: str,
) -> dict[str, Any]:
    return {
        "receipt_id": receipt_id,
        "receipt_type": receipt_type,
        "ledger_id": ledger_id,
        "schema_version": schema_version,
        "event_id": event_id,
        "sequence": int(sequence),
        "first_sequence": int(first_sequence),
        "last_sequence": int(last_sequence),
        "event_hash": event_hash,
        "chain_head_hash": chain_head_hash,
        "signature_algorithm": signature_algorithm,
        "signer_key_id": signer_key_id,
        "created_at": created_at_iso,
    }


def _sign_body(sk_bytes: bytes, body: dict[str, Any]) -> str:
    msg = canonical_json_bytes(body)
    sig = MLDSA65Provider.sign(sk_bytes, msg)
    return base64.b64encode(sig).decode("ascii")


def _verify_body_sig(public_key_b64: str, body: dict[str, Any], signature_b64: str) -> tuple[bool, str]:
    try:
        pk = base64.b64decode(public_key_b64, validate=True)
        sig = base64.b64decode(signature_b64, validate=True)
        msg = canonical_json_bytes(body)
        ok = MLDSA65Provider.verify(pk, msg, sig)
        return (True, "Signature verified cleanly.") if ok else (False, "ML-DSA-65 signature mismatch.")
    except (binascii.Error, ValueError, MLDSAError, TypeError) as exc:
        return False, f"Malformed cryptographic encoding: {exc}"


def create_audit_checkpoint(
    db: Session,
    keystore: LocalEncryptedKeyStore,
    *,
    actor_id: str,
    up_to_sequence: int | None = None,
) -> AuditCheckpoint:
    """Create an ML-DSA-65 signed checkpoint ONLY after verifying the ledger chain intact."""
    ver = verify_ledger_db(db, end_sequence=up_to_sequence)
    if not ver.valid:
        raise AuditError(409, "AUDIT_CHAIN_INVALID", f"Cannot checkpoint invalid ledger: {ver.detail}")
    if ver.verified_event_count == 0 or ver.last_sequence is None or ver.head_hash is None:
        raise AuditError(409, "AUDIT_LEDGER_EMPTY", "Cannot create checkpoint on empty audit ledger.")

    existing = db.get(AuditCheckpoint, ver.last_sequence)
    if existing is not None:
        if existing.root_hash != ver.head_hash:
            raise AuditError(409, "CHECKPOINT_CONFLICT", "Existing checkpoint hash diverges from verified chain head.")
        return existing

    sk = _get_audit_signer_sk(keystore)
    now = utc_now()
    created_iso = format_utc_timestamp(now)
    ckpt_id = f"ckpt-{ver.last_sequence}-{uuid.uuid4().hex[:8]}"
    body = _checkpoint_signing_body(
        checkpoint_id=ckpt_id,
        ledger_id=AUDIT_LEDGER_ID,
        schema_version=AUDIT_CHECKPOINT_SCHEMA,
        first_sequence=ver.first_sequence or 1,
        last_sequence=ver.last_sequence,
        root_hash=ver.head_hash,
        signature_algorithm="ML-DSA-65",
        signer_key_id=AUDIT_SIGNER_KEY_ID,
        created_at_iso=created_iso,
    )
    sig_b64 = _sign_body(sk, body)

    row = AuditCheckpoint(
        sequence=ver.last_sequence,
        checkpoint_id=ckpt_id,
        first_sequence=ver.first_sequence or 1,
        last_sequence=ver.last_sequence,
        root_hash=ver.head_hash,
        schema_version=AUDIT_CHECKPOINT_SCHEMA,
        signature_algorithm="ML-DSA-65",
        signer_key_id=AUDIT_SIGNER_KEY_ID,
        signature_b64=sig_b64,
        signature_metadata=canonical_json_bytes({"ledger_id": AUDIT_LEDGER_ID, "created_at_iso": created_iso}).decode("utf-8"),
        created_by=actor_id,
        created_at=now,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def verify_checkpoint_record(
    checkpoint: AuditCheckpoint,
    *,
    public_key_b64: str,
) -> tuple[bool, str]:
    """Verify ML-DSA-65 signature over a stored AuditCheckpoint."""
    created_iso = format_utc_timestamp(checkpoint.created_at)
    body = _checkpoint_signing_body(
        checkpoint_id=checkpoint.checkpoint_id,
        ledger_id=AUDIT_LEDGER_ID,
        schema_version=checkpoint.schema_version,
        first_sequence=checkpoint.first_sequence,
        last_sequence=checkpoint.last_sequence,
        root_hash=checkpoint.root_hash,
        signature_algorithm=checkpoint.signature_algorithm,
        signer_key_id=checkpoint.signer_key_id,
        created_at_iso=created_iso,
    )
    return _verify_body_sig(public_key_b64, body, checkpoint.signature_b64)


def issue_event_receipt(
    db: Session,
    keystore: LocalEncryptedKeyStore,
    *,
    event_id: str,
    actor_id: str,
) -> AuditEvidenceReceipt:
    """Issue a signed ML-DSA-65 evidence receipt for an existing verified audit event."""
    target = db.scalar(select(AuditEvent).where(AuditEvent.event_id == event_id))
    if target is None:
        raise AuditError(404, "AUDIT_EVENT_NOT_FOUND", f"Audit event '{event_id}' does not exist.")

    ver = verify_ledger_db(db)
    if not ver.valid or ver.head_hash is None:
        raise AuditError(409, "AUDIT_CHAIN_INVALID", f"Cannot sign receipt on invalid ledger: {ver.detail}")

    sk = _get_audit_signer_sk(keystore)
    now = utc_now()
    created_iso = format_utc_timestamp(now)
    rec_id = f"rcpt-{uuid.uuid4().hex[:14]}"
    body = _receipt_signing_body(
        receipt_id=rec_id,
        receipt_type="EVENT",
        ledger_id=AUDIT_LEDGER_ID,
        schema_version=AUDIT_RECEIPT_SCHEMA,
        event_id=target.event_id,
        sequence=target.sequence,
        first_sequence=target.sequence,
        last_sequence=target.sequence,
        event_hash=target.event_hash,
        chain_head_hash=ver.head_hash,
        signature_algorithm="ML-DSA-65",
        signer_key_id=AUDIT_SIGNER_KEY_ID,
        created_at_iso=created_iso,
    )
    sig_b64 = _sign_body(sk, body)
    row = AuditEvidenceReceipt(
        receipt_id=rec_id,
        receipt_type="EVENT",
        ledger_id=AUDIT_LEDGER_ID,
        event_id=target.event_id,
        sequence=target.sequence,
        first_sequence=target.sequence,
        last_sequence=target.sequence,
        event_hash=target.event_hash,
        chain_head_hash=ver.head_hash,
        schema_version=AUDIT_RECEIPT_SCHEMA,
        signature_algorithm="ML-DSA-65",
        signer_key_id=AUDIT_SIGNER_KEY_ID,
        signature_b64=sig_b64,
        created_by=actor_id,
        created_at=now,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def receipt_to_dict(row: AuditEvidenceReceipt) -> dict[str, Any]:
    return {
        "receipt_id": row.receipt_id,
        "receipt_type": row.receipt_type,
        "ledger_id": row.ledger_id,
        "schema_version": row.schema_version,
        "event_id": row.event_id,
        "sequence": int(row.sequence),
        "first_sequence": int(row.first_sequence),
        "last_sequence": int(row.last_sequence),
        "event_hash": row.event_hash,
        "chain_head_hash": row.chain_head_hash,
        "signature_algorithm": row.signature_algorithm,
        "signer_key_id": row.signer_key_id,
        "signature_b64": row.signature_b64,
        "created_by": row.created_by,
        "created_at": format_utc_timestamp(row.created_at),
    }


def verify_receipt_data(receipt: dict[str, Any] | AuditEvidenceReceipt, *, public_key_b64: str) -> tuple[bool, str]:
    """Verify ML-DSA-65 signature over any AuditEvidenceReceipt or exported receipt dict."""
    data = receipt_to_dict(receipt) if isinstance(receipt, AuditEvidenceReceipt) else receipt
    try:
        body = _receipt_signing_body(
            receipt_id=str(data["receipt_id"]),
            receipt_type=str(data["receipt_type"]),
            ledger_id=str(data["ledger_id"]),
            schema_version=str(data["schema_version"]),
            event_id=data.get("event_id"),
            sequence=int(data["sequence"]),
            first_sequence=int(data["first_sequence"]),
            last_sequence=int(data["last_sequence"]),
            event_hash=str(data["event_hash"]),
            chain_head_hash=str(data["chain_head_hash"]),
            signature_algorithm=str(data["signature_algorithm"]),
            signer_key_id=str(data["signer_key_id"]),
            created_at_iso=format_utc_timestamp(data["created_at"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        return False, f"Receipt structure incomplete or invalid: {exc}"
    return _verify_body_sig(public_key_b64, body, str(data.get("signature_b64", "")))


def export_evidence_package(
    db: Session,
    keystore: LocalEncryptedKeyStore,
    *,
    actor_id: str,
    first_sequence: int = 1,
    last_sequence: int | None = None,
) -> dict[str, Any]:
    """Export an independently verifiable signed audit evidence package."""
    if first_sequence < 1:
        raise AuditError(400, "INVALID_SEQUENCE_RANGE", "first_sequence must be >= 1.")

    stmt = select(AuditEvent).where(AuditEvent.sequence >= first_sequence)
    if last_sequence is not None:
        if last_sequence < first_sequence:
            raise AuditError(400, "INVALID_SEQUENCE_RANGE", "last_sequence must be >= first_sequence.")
        if (last_sequence - first_sequence + 1) > MAX_EXPORT_EVENTS:
            raise AuditError(400, "EXPORT_LIMIT_EXCEEDED", f"Maximum {MAX_EXPORT_EVENTS} events per export.")
        stmt = stmt.where(AuditEvent.sequence <= last_sequence)

    rows = list(db.scalars(stmt.order_by(AuditEvent.sequence.asc()).limit(MAX_EXPORT_EVENTS + 1)).all())
    if len(rows) > MAX_EXPORT_EVENTS:
        raise AuditError(400, "EXPORT_LIMIT_EXCEEDED", f"Maximum {MAX_EXPORT_EVENTS} events per export.")
    if not rows:
        raise AuditError(404, "EXPORT_EMPTY", "No audit events found in requested sequence range.")

    ver = verify_ledger_db(db, start_sequence=first_sequence, end_sequence=rows[-1].sequence)
    if not ver.valid or ver.head_hash is None:
        raise AuditError(409, "AUDIT_CHAIN_INVALID", f"Refusing export over tampered ledger: {ver.detail}")

    genesis = db.scalar(select(AuditEvent).where(AuditEvent.sequence == 1))
    genesis_hash = str(genesis.event_hash) if genesis is not None else AUDIT_GENESIS_PREV_HASH
    prev_ckpt = db.scalar(
        select(AuditCheckpoint)
        .where(AuditCheckpoint.sequence <= rows[-1].sequence)
        .order_by(AuditCheckpoint.sequence.desc())
        .limit(1)
    )
    prev_ckpt_ref = (
        {
            "checkpoint_id": prev_ckpt.checkpoint_id,
            "sequence": prev_ckpt.sequence,
            "root_hash": prev_ckpt.root_hash,
            "signature_b64": prev_ckpt.signature_b64,
            "created_at": format_utc_timestamp(prev_ckpt.created_at),
        }
        if prev_ckpt is not None
        else None
    )

    predecessor_prev_hash = str(rows[0].prev_hash)
    events_out = [redact_sensitive_fields(event_model_to_dict(r)) for r in rows]
    now = utc_now()
    created_iso = format_utc_timestamp(now)
    sk = _get_audit_signer_sk(keystore)
    pk_b64 = get_audit_public_key_b64(db)
    rec_id = f"rcpt-exp-{uuid.uuid4().hex[:12]}"
    receipt_body = _receipt_signing_body(
        receipt_id=rec_id,
        receipt_type="EXPORT",
        ledger_id=AUDIT_LEDGER_ID,
        schema_version=AUDIT_RECEIPT_SCHEMA,
        event_id=rows[-1].event_id,
        sequence=rows[-1].sequence,
        first_sequence=rows[0].sequence,
        last_sequence=rows[-1].sequence,
        event_hash=rows[-1].event_hash,
        chain_head_hash=ver.head_hash,
        signature_algorithm="ML-DSA-65",
        signer_key_id=AUDIT_SIGNER_KEY_ID,
        created_at_iso=created_iso,
    )
    sig_b64 = _sign_body(sk, receipt_body)
    receipt_row = AuditEvidenceReceipt(
        receipt_id=rec_id,
        receipt_type="EXPORT",
        ledger_id=AUDIT_LEDGER_ID,
        event_id=rows[-1].event_id,
        sequence=rows[-1].sequence,
        first_sequence=rows[0].sequence,
        last_sequence=rows[-1].sequence,
        event_hash=rows[-1].event_hash,
        chain_head_hash=ver.head_hash,
        schema_version=AUDIT_RECEIPT_SCHEMA,
        signature_algorithm="ML-DSA-65",
        signer_key_id=AUDIT_SIGNER_KEY_ID,
        signature_b64=sig_b64,
        created_by=actor_id,
        created_at=now,
    )
    db.add(receipt_row)
    db.commit()

    return {
        "export_schema_version": AUDIT_EXPORT_SCHEMA,
        "ledger_id": AUDIT_LEDGER_ID,
        "hash_algorithm": AUDIT_HASH_ALGORITHM,
        "export_created_at": created_iso,
        "first_sequence": int(rows[0].sequence),
        "last_sequence": int(rows[-1].sequence),
        "expected_prev_hash": predecessor_prev_hash,
        "genesis_hash": genesis_hash,
        "previous_checkpoint": prev_ckpt_ref,
        "final_chain_head_hash": ver.head_hash,
        "signer_public_key_b64": pk_b64,
        "receipt": receipt_to_dict(receipt_row),
        "events": events_out,
    }


def verify_exported_package(
    package: dict[str, Any],
    *,
    public_key_b64: str | None = None,
) -> AuditVerificationResult:
    """Independently verify an exported audit evidence package without trusting server state."""
    now = utc_now()
    if package.get("export_schema_version") != AUDIT_EXPORT_SCHEMA:
        return AuditVerificationResult(
            valid=False,
            ledger_id=str(package.get("ledger_id", "unknown")),
            verified_event_count=0,
            total_events_inspected=len(package.get("events", [])),
            first_sequence=None,
            last_sequence=None,
            head_hash=None,
            first_invalid_sequence=None,
            first_invalid_event_id=None,
            failure_category="INVALID_EXPORT_SCHEMA",
            expected_hash=None,
            actual_hash=None,
            detail="Unsupported or missing export_schema_version.",
            verified_at=now,
        )

    events = package.get("events")
    if not isinstance(events, list) or not events:
        return AuditVerificationResult(
            valid=False,
            ledger_id=str(package.get("ledger_id", AUDIT_LEDGER_ID)),
            verified_event_count=0,
            total_events_inspected=0,
            first_sequence=package.get("first_sequence"),
            last_sequence=package.get("last_sequence"),
            head_hash=None,
            first_invalid_sequence=package.get("first_sequence"),
            first_invalid_event_id=None,
            failure_category="EMPTY_OR_MISSING_EVENTS",
            expected_hash=None,
            actual_hash=None,
            detail="Export package contains no events.",
            verified_at=now,
        )

    first_seq = int(package.get("first_sequence", 1))
    last_seq = int(package.get("last_sequence", first_seq))
    exp_prev = str(package.get("expected_prev_hash", AUDIT_GENESIS_PREV_HASH if first_seq == 1 else ""))
    if first_seq == 1 and exp_prev != AUDIT_GENESIS_PREV_HASH:
        return AuditVerificationResult(
            valid=False,
            ledger_id=str(package.get("ledger_id", AUDIT_LEDGER_ID)),
            verified_event_count=0,
            total_events_inspected=len(events),
            first_sequence=first_seq,
            last_sequence=last_seq,
            head_hash=None,
            first_invalid_sequence=1,
            first_invalid_event_id=None,
            failure_category="INVALID_GENESIS_RECORD",
            expected_hash=AUDIT_GENESIS_PREV_HASH,
            actual_hash=exp_prev,
            detail="Export genesis prev_hash is invalid.",
            verified_at=now,
        )

    chain_res = verify_audit_records(
        events,
        expected_first_sequence=first_seq,
        expected_prev_hash=exp_prev,
        require_genesis=(first_seq == 1),
        ledger_id=str(package.get("ledger_id", AUDIT_LEDGER_ID)),
    )
    if not chain_res.valid:
        return chain_res

    expected_count = last_seq - first_seq + 1
    if len(events) != expected_count or chain_res.last_sequence != last_seq:
        return AuditVerificationResult(
            valid=False,
            ledger_id=chain_res.ledger_id,
            verified_event_count=chain_res.verified_event_count,
            total_events_inspected=len(events),
            first_sequence=chain_res.first_sequence,
            last_sequence=chain_res.last_sequence,
            head_hash=chain_res.head_hash,
            first_invalid_sequence=last_seq,
            first_invalid_event_id=None,
            failure_category="EXPORT_RANGE_INCOMPLETE",
            expected_hash=None,
            actual_hash=None,
            detail=f"Export claimed range {first_seq}..{last_seq} ({expected_count} events) but got {len(events)}.",
            verified_at=now,
        )

    claimed_head = str(package.get("final_chain_head_hash", ""))
    if chain_res.head_hash != claimed_head:
        return AuditVerificationResult(
            valid=False,
            ledger_id=chain_res.ledger_id,
            verified_event_count=chain_res.verified_event_count,
            total_events_inspected=len(events),
            first_sequence=chain_res.first_sequence,
            last_sequence=chain_res.last_sequence,
            head_hash=chain_res.head_hash,
            first_invalid_sequence=last_seq,
            first_invalid_event_id=events[-1].get("event_id"),
            failure_category="EXPORT_HEAD_HASH_MISMATCH",
            expected_hash=chain_res.head_hash,
            actual_hash=claimed_head,
            detail="Export final_chain_head_hash disagrees with verified event tail.",
            verified_at=now,
        )

    if first_seq == 1 and str(package.get("genesis_hash", "")) != str(events[0].get("event_hash", "")):
        return AuditVerificationResult(
            valid=False,
            ledger_id=chain_res.ledger_id,
            verified_event_count=chain_res.verified_event_count,
            total_events_inspected=len(events),
            first_sequence=chain_res.first_sequence,
            last_sequence=chain_res.last_sequence,
            head_hash=chain_res.head_hash,
            first_invalid_sequence=1,
            first_invalid_event_id=events[0].get("event_id"),
            failure_category="EXPORT_GENESIS_MISMATCH",
            expected_hash=str(events[0].get("event_hash", "")),
            actual_hash=str(package.get("genesis_hash", "")),
            detail="Export genesis_hash does not match event #1.",
            verified_at=now,
        )

    receipt = package.get("receipt")
    pk = public_key_b64 or str(package.get("signer_public_key_b64", ""))
    if not isinstance(receipt, dict) or not pk:
        return AuditVerificationResult(
            valid=False,
            ledger_id=chain_res.ledger_id,
            verified_event_count=chain_res.verified_event_count,
            total_events_inspected=len(events),
            first_sequence=chain_res.first_sequence,
            last_sequence=chain_res.last_sequence,
            head_hash=chain_res.head_hash,
            first_invalid_sequence=last_seq,
            first_invalid_event_id=None,
            failure_category="MISSING_RECEIPT_OR_KEY",
            expected_hash=None,
            actual_hash=None,
            detail="Export package is missing receipt or signer public key.",
            verified_at=now,
        )

    if int(receipt.get("first_sequence", -1)) != first_seq or int(receipt.get("last_sequence", -1)) != last_seq or str(receipt.get("chain_head_hash", "")) != claimed_head:
        return AuditVerificationResult(
            valid=False,
            ledger_id=chain_res.ledger_id,
            verified_event_count=chain_res.verified_event_count,
            total_events_inspected=len(events),
            first_sequence=chain_res.first_sequence,
            last_sequence=chain_res.last_sequence,
            head_hash=chain_res.head_hash,
            first_invalid_sequence=last_seq,
            first_invalid_event_id=None,
            failure_category="RECEIPT_RANGE_OR_HEAD_MISMATCH",
            expected_hash=claimed_head,
            actual_hash=str(receipt.get("chain_head_hash", "")),
            detail="Export receipt metadata disagrees with exported range or head hash.",
            verified_at=now,
        )

    sig_ok, sig_detail = verify_receipt_data(receipt, public_key_b64=pk)
    if not sig_ok:
        return AuditVerificationResult(
            valid=False,
            ledger_id=chain_res.ledger_id,
            verified_event_count=chain_res.verified_event_count,
            total_events_inspected=len(events),
            first_sequence=chain_res.first_sequence,
            last_sequence=chain_res.last_sequence,
            head_hash=chain_res.head_hash,
            first_invalid_sequence=last_seq,
            first_invalid_event_id=None,
            failure_category="RECEIPT_SIGNATURE_INVALID",
            expected_hash=None,
            actual_hash=None,
            detail=sig_detail,
            verified_at=now,
        )

    return AuditVerificationResult(
        valid=True,
        ledger_id=chain_res.ledger_id,
        verified_event_count=chain_res.verified_event_count,
        total_events_inspected=len(events),
        first_sequence=first_seq,
        last_sequence=last_seq,
        head_hash=claimed_head,
        first_invalid_sequence=None,
        first_invalid_event_id=None,
        failure_category=None,
        expected_hash=None,
        actual_hash=None,
        detail=f"Export package verified independently ({chain_res.verified_event_count} events + ML-DSA-65 receipt).",
        verified_at=now,
    )
