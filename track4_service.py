"""Q-SHIELD official Track 4 root adapter entrypoint.

Implements the versioned adapter contract (docs/adapter-v1.md) as a single
process-per-request CLI reading one UTF-8 JSON object from stdin and writing
exactly one JSON object to stdout.

Import boundary: Python 3.12 standard library + ``pqcrypto==0.4.0`` only.
State persistence uses ``TRACK4_STATE_DIR`` if set, else the OS temp directory,
so the repository root may remain read-only.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
from typing import Any

from pqcrypto.kem import ml_kem_768

MAX_STDIN_BYTES = 16 * 1024 * 1024
MAX_STDOUT_BYTES = 65536
SQLITE_BUSY_TIMEOUT_MS = 5000
STATE_FILENAME = "qshield_track4_state.sqlite3"


def _get_state_db_path() -> Path:
    """Resolve the writable SQLite state file inside TRACK4_STATE_DIR or OS tempdir."""
    raw_dir = os.environ.get("TRACK4_STATE_DIR")
    base_dir = Path(raw_dir) if raw_dir else Path(tempfile.gettempdir())
    base_dir.mkdir(parents=True, exist_ok=True)
    return base_dir / STATE_FILENAME


def _open_connection(db_path: Path) -> sqlite3.Connection:
    """Open a SQLite connection configured for cross-process durability and safety."""
    conn = sqlite3.connect(str(db_path), timeout=SQLITE_BUSY_TIMEOUT_MS / 1000.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=FULL")
    return conn


def _init_schema(conn: sqlite3.Connection) -> None:
    """Create the adapter persistence tables if they do not exist."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS adapter_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS asset_owners (
            asset_id TEXT PRIMARY KEY,
            owner_id TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS asset_contents (
            asset_id TEXT PRIMARY KEY,
            body TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS disabled_actors (
            actor_id TEXT PRIMARY KEY
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_records (
            request_id TEXT PRIMARY KEY,
            actor_id TEXT NOT NULL,
            asset_id TEXT NOT NULL,
            op TEXT NOT NULL,
            decision TEXT NOT NULL CHECK (decision IN ('allow', 'deny')),
            rule TEXT NOT NULL,
            seq INTEGER NOT NULL
        )
        """
    )


def _is_nonempty_str(value: Any) -> bool:
    """Return True if value is a non-empty string."""
    return isinstance(value, str) and len(value) > 0


def _validate_str_mapping(mapping: Any) -> bool:
    """Return True if mapping is a dict with string keys and string values."""
    if not isinstance(mapping, dict):
        return False
    return all(isinstance(k, str) and len(k) > 0 and isinstance(v, str) for k, v in mapping.items())


def _is_initialized(conn: sqlite3.Connection) -> bool:
    """Check whether setup has completed successfully in the state store."""
    row = conn.execute("SELECT value FROM adapter_meta WHERE key = 'initialized'").fetchone()
    return row is not None and row["value"] == "1"


def _authorize_read(conn: sqlite3.Connection, actor: str, asset: str) -> tuple[bool, str, str | None]:
    """Evaluate ownership and revocation state for an actor reading an asset."""
    disabled_row = conn.execute(
        "SELECT 1 FROM disabled_actors WHERE actor_id = ?",
        (actor,),
    ).fetchone()
    if disabled_row is not None:
        return False, "identity_disabled", None

    owner_row = conn.execute(
        "SELECT owner_id FROM asset_owners WHERE asset_id = ?",
        (asset,),
    ).fetchone()
    if owner_row is None or owner_row["owner_id"] != actor:
        return False, "owner_required", None

    content_row = conn.execute(
        "SELECT body FROM asset_contents WHERE asset_id = ?",
        (asset,),
    ).fetchone()
    if content_row is None:
        return False, "asset_missing", None

    return True, "owner_allowed", str(content_row["body"])


def _next_audit_seq(conn: sqlite3.Connection) -> int:
    """Return next monotonic audit sequence number."""
    row = conn.execute("SELECT COALESCE(MAX(seq), 0) AS max_seq FROM audit_records").fetchone()
    return int(row["max_seq"]) + 1


def _handle_setup(conn: sqlite3.Connection, request: dict[str, Any]) -> dict[str, Any]:
    """Atomically reset and initialize adapter scenario state."""
    owners = request.get("owners")
    contents = request.get("contents")
    disabled = request.get("disabled", [])
    key_material = request.get("key_material", "")

    if not _validate_str_mapping(owners) or not _validate_str_mapping(contents):
        return {"ready": False, "error": "invalid_setup_mappings"}
    if not isinstance(disabled, list) or not all(_is_nonempty_str(a) for a in disabled):
        return {"ready": False, "error": "invalid_disabled_list"}
    if not isinstance(key_material, str):
        return {"ready": False, "error": "invalid_key_material"}

    # Store only a cryptographic digest of synthetic key_material; never persist or echo raw material.
    key_digest = hashlib.sha256(key_material.encode("utf-8")).hexdigest()

    conn.execute("BEGIN IMMEDIATE")
    try:
        _init_schema(conn)
        conn.execute("DELETE FROM adapter_meta")
        conn.execute("DELETE FROM asset_owners")
        conn.execute("DELETE FROM asset_contents")
        conn.execute("DELETE FROM disabled_actors")
        conn.execute("DELETE FROM audit_records")

        conn.executemany(
            "INSERT INTO asset_owners (asset_id, owner_id) VALUES (?, ?)",
            [(asset_id, owner_id) for asset_id, owner_id in owners.items()],
        )
        conn.executemany(
            "INSERT INTO asset_contents (asset_id, body) VALUES (?, ?)",
            [(asset_id, body) for asset_id, body in contents.items()],
        )
        conn.executemany(
            "INSERT OR IGNORE INTO disabled_actors (actor_id) VALUES (?)",
            [(actor_id,) for actor_id in disabled],
        )
        conn.execute(
            "INSERT INTO adapter_meta (key, value) VALUES ('key_material_sha256', ?)",
            (key_digest,),
        )
        conn.execute(
            "INSERT INTO adapter_meta (key, value) VALUES ('initialized', '1')",
        )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise

    return {"ready": True}


def _handle_read(conn: sqlite3.Connection, request: dict[str, Any]) -> dict[str, Any]:
    """Authorize read request, record audit decision, and return body only on allow."""
    actor = request.get("actor")
    asset = request.get("asset")
    request_id = request.get("request_id")

    if not (_is_nonempty_str(actor) and _is_nonempty_str(asset) and _is_nonempty_str(request_id)):
        return {"decision": "deny", "error": "invalid_request"}

    conn.execute("BEGIN IMMEDIATE")
    try:
        _init_schema(conn)
        if not _is_initialized(conn):
            conn.execute("ROLLBACK")
            return {"decision": "deny", "error": "not_initialized"}

        allowed, rule, body = _authorize_read(conn, actor, asset)
        decision = "allow" if allowed else "deny"
        seq = _next_audit_seq(conn)
        conn.execute(
            """
            INSERT INTO audit_records (request_id, actor_id, asset_id, op, decision, rule, seq)
            VALUES (?, ?, ?, 'read', ?, ?, ?)
            ON CONFLICT(request_id) DO UPDATE SET
                actor_id = excluded.actor_id,
                asset_id = excluded.asset_id,
                op = excluded.op,
                decision = excluded.decision,
                rule = excluded.rule,
                seq = excluded.seq
            """,
            (request_id, actor, asset, decision, rule, seq),
        )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise

    if allowed and body is not None:
        return {"decision": "allow", "body": body}
    return {"decision": "deny"}


def _handle_revoke(conn: sqlite3.Connection, request: dict[str, Any]) -> dict[str, Any]:
    """Persistently revoke an actor while leaving other actors authorized."""
    actor = request.get("actor")
    if not _is_nonempty_str(actor):
        return {"revoked": False, "error": "invalid_request"}

    conn.execute("BEGIN IMMEDIATE")
    try:
        _init_schema(conn)
        if not _is_initialized(conn):
            conn.execute("ROLLBACK")
            return {"revoked": False, "error": "not_initialized"}

        conn.execute(
            "INSERT OR IGNORE INTO disabled_actors (actor_id) VALUES (?)",
            (actor,),
        )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise

    return {}


def _handle_audit(conn: sqlite3.Connection, request: dict[str, Any]) -> dict[str, Any]:
    """Return recorded decision for request_id; fail closed on unknown or missing IDs."""
    request_id = request.get("request_id")
    if not _is_nonempty_str(request_id):
        return {"decision": "deny", "error": "invalid_request"}

    _init_schema(conn)
    if not _is_initialized(conn):
        return {"request_id": request_id, "decision": "deny", "error": "not_initialized"}

    row = conn.execute(
        "SELECT request_id, decision, rule FROM audit_records WHERE request_id = ?",
        (request_id,),
    ).fetchone()
    if row is None:
        return {"request_id": request_id, "decision": "deny", "error": "unknown_request"}

    return {"request_id": str(row["request_id"]), "decision": str(row["decision"])}


def _decode_mlkem768_public_key(public_key_b64: Any) -> bytes | None:
    """Strictly decode standard Base64 and verify raw ML-KEM-768 public key byte length."""
    if not _is_nonempty_str(public_key_b64) or not public_key_b64.isascii():
        return None
    try:
        raw_pk = base64.b64decode(public_key_b64, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw_pk) != ml_kem_768.PUBLIC_KEY_SIZE:
        return None
    return raw_pk


def _handle_protected_read(conn: sqlite3.Connection, request: dict[str, Any]) -> dict[str, Any]:
    """Authorize read, encapsulate with ML-KEM-768, and compute HMAC-SHA-256 proof."""
    actor = request.get("actor")
    asset = request.get("asset")
    challenge = request.get("challenge")
    public_key_b64 = request.get("public_key")

    if not (_is_nonempty_str(actor) and _is_nonempty_str(asset) and _is_nonempty_str(challenge)):
        return {"decision": "deny", "error": "invalid_request"}

    raw_pk = _decode_mlkem768_public_key(public_key_b64)
    if raw_pk is None:
        return {"decision": "deny", "error": "invalid_public_key"}

    conn.execute("BEGIN IMMEDIATE")
    try:
        _init_schema(conn)
        if not _is_initialized(conn):
            conn.execute("ROLLBACK")
            return {"decision": "deny", "error": "not_initialized"}

        allowed, _rule, body = _authorize_read(conn, actor, asset)
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise

    if not allowed or body is None:
        return {"decision": "deny"}

    ciphertext, shared_secret = ml_kem_768.encrypt(raw_pk)
    message = (challenge + body).encode("utf-8")
    proof = hmac.new(shared_secret, message, hashlib.sha256).hexdigest()
    ciphertext_b64 = base64.b64encode(ciphertext).decode("ascii")
    return {"ciphertext": ciphertext_b64, "proof": proof}


def dispatch(request: dict[str, Any]) -> dict[str, Any]:
    """Dispatch one validated JSON request dictionary to the corresponding operation."""
    op = request.get("op")
    if not _is_nonempty_str(op):
        return {"error": "invalid_operation"}

    db_path = _get_state_db_path()
    conn = _open_connection(db_path)
    try:
        if op == "setup":
            return _handle_setup(conn, request)
        if op == "read":
            return _handle_read(conn, request)
        if op == "revoke":
            return _handle_revoke(conn, request)
        if op == "audit":
            return _handle_audit(conn, request)
        if op == "protected_read":
            return _handle_protected_read(conn, request)
        return {"error": "unsupported_operation"}
    finally:
        conn.close()


def _reject_nonstandard_json_constant(token: str) -> Any:
    """Reject NaN/Infinity tokens in incoming JSON requests."""
    raise ValueError(f"Unsupported JSON constant: {token}")


def _read_request_from_stdin() -> dict[str, Any]:
    """Read and parse one strict UTF-8 JSON object from stdin up to MAX_STDIN_BYTES."""
    raw = sys.stdin.buffer.read(MAX_STDIN_BYTES + 1)
    if len(raw) > MAX_STDIN_BYTES:
        raise ValueError("Input exceeds maximum allowed payload size")
    if not raw:
        raise ValueError("Empty stdin payload")
    text = raw.decode("utf-8")
    parsed = json.loads(text, parse_constant=_reject_nonstandard_json_constant)
    if not isinstance(parsed, dict):
        raise ValueError("Request must be a JSON object")
    return parsed


def main() -> int:
    """Process one JSON request from stdin, emit one JSON object to stdout, and exit."""
    try:
        request = _read_request_from_stdin()
        response = dispatch(request)
        if not isinstance(response, dict):
            raise ValueError("Response must be a JSON object")
        encoded = json.dumps(response, allow_nan=False, separators=(",", ":"))
        encoded_bytes = (encoded + "\n").encode("utf-8")
        if len(encoded_bytes) > MAX_STDOUT_BYTES:
            raise ValueError("Response exceeded 64 KiB stdout limit")
    except Exception:
        # Never log request payloads, stack traces, keys, shared secrets, or protected bodies.
        sys.stderr.write("Request failed; inspect adapter input and state directory.\n")
        return 1

    sys.stdout.buffer.write(encoded_bytes)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
