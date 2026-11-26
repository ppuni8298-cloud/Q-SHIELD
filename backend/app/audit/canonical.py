"""Deterministic canonical serialization, secret redaction, log-injection escaping, and SHA-256 chain hashing."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import math
from typing import Any
import unicodedata

from backend.app.auth.tokens import ensure_utc

AUDIT_LEDGER_ID = "qshield-control-plane-audit-v1"
AUDIT_SCHEMA_VERSION = "qshield.audit.v1"
AUDIT_HASH_ALGORITHM = "SHA-256"
AUDIT_GENESIS_PREV_HASH = "0" * 64
AUDIT_CHECKPOINT_SCHEMA = "qshield.audit.checkpoint.v1"
AUDIT_RECEIPT_SCHEMA = "qshield.audit.receipt.v1"
AUDIT_EXPORT_SCHEMA = "qshield.audit.export.v1"

_SENSITIVE_KEY_TOKENS = (
    "password",
    "passwd",
    "secret",
    "token",
    "private_key",
    "key_material",
    "shared_secret",
    "plaintext",
    "master_key",
    "wrapping_key",
    "dek",
    "kek",
    "signing_key",
    "raw_key",
)


def sanitize_audit_text(value: str) -> str:
    """Normalize Unicode NFC and escape control chars (CR/LF/NUL/etc.) to prevent log injection."""
    normalized = unicodedata.normalize("NFC", value)
    out: list[str] = []
    for ch in normalized:
        code = ord(ch)
        if ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif code < 0x20 or code == 0x7F:
            out.append(f"\\x{code:02x}")
        else:
            out.append(ch)
    return "".join(out)


def _is_sensitive_key(key: str) -> bool:
    low = key.lower()
    # Allow explicit non-secret metadata fields like key_id, key_version, kek_id, token_count
    if low in ("key_id", "from_key_id", "to_key_id", "kek_id", "signer_key_id", "key_version", "from_version", "to_version"):
        return False
    return any(tok in low for tok in _SENSITIVE_KEY_TOKENS)


def redact_sensitive_fields(value: Any, *, _key_hint: str | None = None) -> Any:
    """Recursively redact sensitive keys and normalize Unicode + control chars."""
    if _key_hint is not None and _is_sensitive_key(_key_hint):
        return "[REDACTED]"
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Non-finite floats (NaN/Inf) are forbidden in canonical audit data.")
        return 0.0 if value == 0.0 else value
    if isinstance(value, str):
        return sanitize_audit_text(value)
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for k, v in value.items():
            sk = sanitize_audit_text(str(k))
            cleaned[sk] = redact_sensitive_fields(v, _key_hint=sk)
        return cleaned
    if isinstance(value, (list, tuple)):
        return [redact_sensitive_fields(item) for item in value]
    return sanitize_audit_text(str(value))


def normalize_canonical_value(value: Any) -> Any:
    """Canonicalize values deterministically (NFC strings, -0.0->0.0, sorted keys, no NaN)."""
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Non-finite float encountered during canonical serialization.")
        return 0.0 if value == 0.0 else value
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, dict):
        return {unicodedata.normalize("NFC", str(k)): normalize_canonical_value(v) for k, v in sorted(value.items(), key=lambda kv: unicodedata.normalize("NFC", str(kv[0])))}
    if isinstance(value, (list, tuple)):
        return [normalize_canonical_value(item) for item in value]
    raise TypeError(f"Unsupported value type in canonical JSON: {type(value).__name__}")


def canonical_json_bytes(obj: Any) -> bytes:
    """Encode an object as exact deterministic UTF-8 canonical JSON bytes."""
    norm = normalize_canonical_value(obj)
    return json.dumps(norm, separators=(",", ":"), sort_keys=True, ensure_ascii=False, allow_nan=False).encode("utf-8")


def canonical_json_str(obj: Any) -> str:
    return canonical_json_bytes(obj).decode("utf-8")


def format_utc_timestamp(dt: datetime | str) -> str:
    """Format timestamp to canonical UTC ISO-8601 string with explicit microsecond precision (+00:00)."""
    if isinstance(dt, str):
        parsed = datetime.fromisoformat(dt.replace("Z", "+00:00"))
        dt_utc = ensure_utc(parsed)
    else:
        dt_utc = ensure_utc(dt)
    return dt_utc.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")


def build_audit_event_body(
    *,
    schema_version: str,
    hash_algorithm: str,
    sequence: int,
    event_id: str,
    timestamp_utc: datetime | str,
    event_type: str,
    event_category: str,
    actor_id: str,
    target_type: str,
    target_id: str,
    action: str,
    outcome: str,
    reason_code: str,
    correlation_id: str,
    source_component: str,
    payload: dict[str, Any],
    prev_hash: str,
) -> dict[str, Any]:
    """Build exact canonical dictionary hashed into each ledger record."""
    return {
        "schema_version": schema_version,
        "hash_algorithm": hash_algorithm,
        "sequence": int(sequence),
        "event_id": str(event_id),
        "timestamp_utc": format_utc_timestamp(timestamp_utc),
        "event_type": str(event_type),
        "event_category": str(event_category),
        "actor_id": str(actor_id),
        "target_type": str(target_type),
        "target_id": str(target_id),
        "action": str(action),
        "outcome": str(outcome),
        "reason_code": str(reason_code),
        "correlation_id": str(correlation_id),
        "source_component": str(source_component),
        "payload": payload,
        "prev_hash": str(prev_hash),
    }


def compute_audit_event_hash(*, prev_hash: str, sequence: int, canonical_body: dict[str, Any]) -> str:
    """Compute SHA-256 chain hash binding domain tag, prev_hash, sequence, and canonical event contents."""
    raw = (
        b"QSHIELD-AUDIT-EVENT-V1|"
        + prev_hash.encode("ascii")
        + b"|"
        + str(int(sequence)).encode("ascii")
        + b"|"
        + canonical_json_bytes(canonical_body)
    )
    return hashlib.sha256(raw).hexdigest()


def event_model_to_dict(row: Any) -> dict[str, Any]:
    """Convert an AuditEvent ORM object into an exported/verifiable dictionary."""
    payload = json.loads(row.payload_json) if row.payload_json else {}
    return {
        "sequence": int(row.sequence),
        "event_id": str(row.event_id),
        "event_type": str(row.event_type),
        "event_category": str(row.event_category),
        "timestamp_utc": format_utc_timestamp(row.timestamp_utc),
        "actor_id": str(row.actor_id),
        "target_type": str(row.target_type),
        "target_id": str(row.target_id),
        "action": str(row.action),
        "outcome": str(row.decision),
        "decision": str(row.decision),
        "reason_code": str(row.reason_code),
        "correlation_id": str(row.correlation_id),
        "source_component": str(row.source_component),
        "payload": payload,
        "prev_hash": str(row.prev_hash),
        "event_hash": str(row.event_hash),
        "hash_algorithm": str(row.hash_algorithm),
        "schema_version": str(row.schema_version),
    }
