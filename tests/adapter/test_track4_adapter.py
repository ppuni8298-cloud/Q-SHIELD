"""Independent black-box adapter tests derived from docs/adapter-v1.md and Phase 1 spec.

Tests execute track4_service.py as an isolated fresh subprocess per request so
persistence, stdout/stderr protocol, timeout, stream caps, zero secret leakage,
and ML-KEM-768 + HMAC-SHA-256 cryptographic interoperability are verified end-to-end.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from pqcrypto.kem import ml_kem_768
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
ADAPTER_ENTRY = REPO_ROOT / "track4_service.py"
MAX_STREAM_BYTES = 65536


def run_adapter(
    payload: dict | str | bytes,
    state_dir: Path,
    *,
    timeout: float = 8.0,
    isolated_env: bool = False,
) -> tuple[int, bytes, bytes]:
    """Run track4_service.py in a fresh process with TRACK4_STATE_DIR set."""
    env = os.environ.copy()
    if isolated_env:
        # Strip non-essential vars while keeping Python runtime paths functional.
        keep = {k: env[k] for k in ("PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT") if k in env}
        env = keep
    for var in ("TRACK4_STATE_DIR", "TMPDIR", "TEMP", "TMP"):
        env[var] = str(state_dir)

    raw_input = (
        payload
        if isinstance(payload, bytes)
        else payload.encode("utf-8")
        if isinstance(payload, str)
        else json.dumps(payload).encode("utf-8")
    )

    proc = subprocess.run(
        [sys.executable, "-B", str(ADAPTER_ENTRY)],
        cwd=str(REPO_ROOT),
        env=env,
        input=raw_input,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def call_json(payload: dict, state_dir: Path, *, timeout: float = 8.0) -> tuple[dict, bytes, bytes]:
    """Invoke adapter with JSON dict and assert single-JSON-object stdout protocol."""
    code, out, err = run_adapter(payload, state_dir, timeout=timeout)
    assert code == 0, f"Expected exit 0, got {code}; stderr={err!r}"
    assert len(out) <= MAX_STREAM_BYTES
    assert len(err) <= MAX_STREAM_BYTES
    decoded = json.loads(out.decode("utf-8"))
    assert isinstance(decoded, dict)
    # Exactly one JSON object on stdout (single line, no extra trailing garbage).
    lines = out.decode("utf-8").splitlines()
    assert len(lines) == 1
    return decoded, out, err


def test_setup_and_repeated_setup_reset(tmp_path: Path) -> None:
    setup1 = {
        "op": "setup",
        "owners": {"doc1": "alice", "doc2": "bob"},
        "contents": {"doc1": "alice-secret-1", "doc2": "bob-secret-2"},
        "disabled": ["charlie"],
        "key_material": "synthetic-marker-alpha-999",
    }
    resp, out, err = call_json(setup1, tmp_path)
    assert resp == {"ready": True}
    assert b"synthetic-marker-alpha-999" not in out
    assert b"synthetic-marker-alpha-999" not in err

    # Revoke alice and read doc2 before resetting.
    call_json({"op": "revoke", "actor": "alice"}, tmp_path)
    r1, _, _ = call_json({"op": "read", "actor": "bob", "asset": "doc2", "request_id": "req-old"}, tmp_path)
    assert r1 == {"decision": "allow", "body": "bob-secret-2"}

    # Repeated setup in the SAME state directory must wipe prior revocations, assets, and audits.
    setup2 = {
        "op": "setup",
        "owners": {"doc3": "alice"},
        "contents": {"doc3": "fresh-alice-body"},
        "disabled": [],
        "key_material": "synthetic-marker-beta-111",
    }
    resp2, out2, err2 = call_json(setup2, tmp_path)
    assert resp2 == {"ready": True}
    assert b"synthetic-marker-beta-111" not in out2
    assert b"synthetic-marker-beta-111" not in err2

    # Alice is now enabled on doc3; old doc2 and old request_id are gone.
    r_alice, _, _ = call_json({"op": "read", "actor": "alice", "asset": "doc3", "request_id": "req-new"}, tmp_path)
    assert r_alice == {"decision": "allow", "body": "fresh-alice-body"}

    r_old_asset, _, _ = call_json({"op": "read", "actor": "bob", "asset": "doc2", "request_id": "req-missing"}, tmp_path)
    assert r_old_asset["decision"] == "deny"
    assert "body" not in r_old_asset

    audit_old, _, _ = call_json({"op": "audit", "request_id": "req-old"}, tmp_path)
    assert audit_old["decision"] == "deny"
    assert audit_old.get("error") == "unknown_request"


def test_read_authorization_disabled_actor_and_no_leakage(tmp_path: Path) -> None:
    marker = "synthetic-key-material-do-not-leak"
    call_json(
        {
            "op": "setup",
            "owners": {"asset-a": "owner1", "asset-b": "peer1", "asset-c": "disabled1"},
            "contents": {"asset-a": "secret-a", "asset-b": "secret-b", "asset-c": "secret-c"},
            "disabled": ["disabled1"],
            "key_material": marker,
        },
        tmp_path,
    )

    # Authorized owner read
    allow_resp, out, err = call_json(
        {"op": "read", "actor": "owner1", "asset": "asset-a", "request_id": "r-allow"},
        tmp_path,
    )
    assert allow_resp == {"decision": "allow", "body": "secret-a"}
    assert marker.encode() not in out and marker.encode() not in err

    # Unauthorized wrong-owner read
    deny_wrong, out, err = call_json(
        {"op": "read", "actor": "owner1", "asset": "asset-b", "request_id": "r-wrong"},
        tmp_path,
    )
    assert deny_wrong == {"decision": "deny"}
    assert b"secret-b" not in out and b"secret-b" not in err
    assert marker.encode() not in out and marker.encode() not in err

    # Actor disabled at setup time must be denied even on their own asset
    deny_disabled, out, err = call_json(
        {"op": "read", "actor": "disabled1", "asset": "asset-c", "request_id": "r-dis"},
        tmp_path,
    )
    assert deny_disabled == {"decision": "deny"}
    assert b"secret-c" not in out and b"secret-c" not in err

    # Unknown asset and unknown actor
    deny_unknown, _, _ = call_json(
        {"op": "read", "actor": "nobody", "asset": "no-asset", "request_id": "r-unk"},
        tmp_path,
    )
    assert deny_unknown == {"decision": "deny"}


def test_revoke_persistence_peer_isolation_and_audit(tmp_path: Path) -> None:
    call_json(
        {
            "op": "setup",
            "owners": {"f1": "alice", "f2": "bob"},
            "contents": {"f1": "alice-data", "f2": "bob-data"},
            "disabled": [],
            "key_material": "km-xyz",
        },
        tmp_path,
    )

    # Allowed read audited
    r_ok, _, _ = call_json({"op": "read", "actor": "alice", "asset": "f1", "request_id": "req-1"}, tmp_path)
    assert r_ok == {"decision": "allow", "body": "alice-data"}
    a_ok, _, _ = call_json({"op": "audit", "request_id": "req-1"}, tmp_path)
    assert a_ok == {"request_id": "req-1", "decision": "allow"}

    # Revoke alice
    rev_resp, _, _ = call_json({"op": "revoke", "actor": "alice"}, tmp_path)
    assert isinstance(rev_resp, dict)

    # Alice denied in subsequent fresh processes
    r_denied, out, _ = call_json({"op": "read", "actor": "alice", "asset": "f1", "request_id": "req-2"}, tmp_path)
    assert r_denied == {"decision": "deny"}
    assert b"alice-data" not in out

    # Audit reflects denial for req-2 while req-1 historical record stays intact
    a_deny, _, _ = call_json({"op": "audit", "request_id": "req-2"}, tmp_path)
    assert a_deny == {"request_id": "req-2", "decision": "deny"}
    a_hist, _, _ = call_json({"op": "audit", "request_id": "req-1"}, tmp_path)
    assert a_hist == {"request_id": "req-1", "decision": "allow"}

    # Bob remains unaffected
    r_peer, _, _ = call_json({"op": "read", "actor": "bob", "asset": "f2", "request_id": "req-3"}, tmp_path)
    assert r_peer == {"decision": "allow", "body": "bob-data"}


def test_protected_read_mlkem768_hmac_interoperability(tmp_path: Path) -> None:
    stored_body = "classified-quantum-note-utf8-\u03bb\u2713"
    challenge = "chal-2026-11-26-nonce-42"
    marker = "synthetic-km-secret-98765"

    call_json(
        {
            "op": "setup",
            "owners": {"vault-1": "alice", "vault-2": "bob"},
            "contents": {"vault-1": stored_body, "vault-2": "bob-only"},
            "disabled": [],
            "key_material": marker,
        },
        tmp_path,
    )

    pk, sk = ml_kem_768.generate_keypair()
    pk_b64 = base64.b64encode(pk).decode("ascii")

    resp, out, err = call_json(
        {
            "op": "protected_read",
            "actor": "alice",
            "asset": "vault-1",
            "challenge": challenge,
            "public_key": pk_b64,
        },
        tmp_path,
    )
    assert set(resp.keys()) == {"ciphertext", "proof"}
    assert marker.encode() not in out and marker.encode() not in err
    assert stored_body.encode("utf-8") not in out and stored_body.encode("utf-8") not in err

    # Independent decapsulation & HMAC-SHA-256 verification (exact contract: challenge + stored_body, no separator)
    ct = base64.b64decode(resp["ciphertext"], validate=True)
    assert len(ct) == ml_kem_768.CIPHERTEXT_SIZE
    shared_secret = ml_kem_768.decrypt(sk, ct)
    expected_proof = hmac.new(
        shared_secret,
        (challenge + stored_body).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    assert resp["proof"] == expected_proof
    assert resp["proof"] == resp["proof"].lower()
    assert len(resp["proof"]) == 64

    # Wrong owner denied on protected_read
    deny_wrong, out_w, err_w = call_json(
        {
            "op": "protected_read",
            "actor": "bob",
            "asset": "vault-1",
            "challenge": challenge,
            "public_key": pk_b64,
        },
        tmp_path,
    )
    assert deny_wrong["decision"] == "deny"
    assert "ciphertext" not in deny_wrong and "proof" not in deny_wrong
    assert stored_body.encode("utf-8") not in out_w and stored_body.encode("utf-8") not in err_w

    # Revoked owner denied on protected_read
    call_json({"op": "revoke", "actor": "alice"}, tmp_path)
    deny_rev, out_r, err_r = call_json(
        {
            "op": "protected_read",
            "actor": "alice",
            "asset": "vault-1",
            "challenge": challenge,
            "public_key": pk_b64,
        },
        tmp_path,
    )
    assert deny_rev["decision"] == "deny"
    assert "ciphertext" not in deny_rev and "proof" not in deny_rev
    assert stored_body.encode("utf-8") not in out_r and stored_body.encode("utf-8") not in err_r


def test_protected_read_malformed_keys_and_base64_rejected(tmp_path: Path) -> None:
    call_json(
        {
            "op": "setup",
            "owners": {"vault-1": "alice"},
            "contents": {"vault-1": "top-secret-body"},
            "disabled": [],
            "key_material": "km-protected",
        },
        tmp_path,
    )

    pk, _ = ml_kem_768.generate_keypair()
    # Deterministically ensure '-' and '_' appear in URL-safe Base64 (bytes 0xFB, 0xFF produce '+' and '/' in std Base64).
    pk_with_special_bytes = b"\xfb\xff\xfe" + pk[3:]
    urlsafe_pk = base64.urlsafe_b64encode(pk_with_special_bytes).decode("ascii")
    assert "-" in urlsafe_pk or "_" in urlsafe_pk

    bad_inputs = [
        "not-valid-base64!!!",
        base64.b64encode(b"too-short").decode("ascii"),
        base64.b64encode(pk + b"\x00").decode("ascii"),
        base64.b64encode(pk[:-1]).decode("ascii"),
        "",
        "@@@",
        urlsafe_pk,
    ]

    for bad_pk in bad_inputs:
        resp, out, err = call_json(
            {
                "op": "protected_read",
                "actor": "alice",
                "asset": "vault-1",
                "challenge": "chal-1",
                "public_key": bad_pk,
            },
            tmp_path,
        )
        assert resp["decision"] == "deny"
        assert "ciphertext" not in resp and "proof" not in resp
        assert b"top-secret-body" not in out and b"top-secret-body" not in err

    # Empty challenge rejected safely
    resp_chal, out_c, _ = call_json(
        {
            "op": "protected_read",
            "actor": "alice",
            "asset": "vault-1",
            "challenge": "",
            "public_key": base64.b64encode(pk).decode("ascii"),
        },
        tmp_path,
    )
    assert resp_chal["decision"] == "deny"
    assert b"top-secret-body" not in out_c


def test_malformed_json_missing_fields_unknown_op_and_oversized_input(tmp_path: Path) -> None:
    # Malformed JSON / non-dict / NaN / empty stdin -> non-zero exit with sanitized stderr and empty stdout
    for bad_raw in (
        b"{not json",
        b"[1, 2, 3]",
        b'{"op": "setup", "x": NaN}',
        b"",
        b"\xff\xfe\xfd",
    ):
        code, out, err = run_adapter(bad_raw, tmp_path)
        assert code != 0
        assert out == b""
        assert len(err) <= MAX_STREAM_BYTES
        assert b"Traceback" not in err

    # Oversized input (>16 MiB) -> rejected safely without traceback
    oversized = b'{"op":"setup","pad":"' + (b"a" * (16 * 1024 * 1024 + 32)) + b'"}'
    code, out, err = run_adapter(oversized, tmp_path, timeout=8.0)
    assert code != 0
    assert out == b""
    assert b"Traceback" not in err

    # Unknown op -> safe JSON response
    unk, _, _ = call_json({"op": "delete_everything"}, tmp_path)
    assert unk == {"error": "unsupported_operation"}

    # Missing required fields on read / setup / audit
    bad_read, _, _ = call_json({"op": "read", "actor": "alice"}, tmp_path)
    assert bad_read["decision"] == "deny"

    bad_setup, _, _ = call_json({"op": "setup", "owners": "bad"}, tmp_path)
    assert bad_setup["ready"] is False

    bad_audit, _, _ = call_json({"op": "audit"}, tmp_path)
    assert bad_audit["decision"] == "deny"


def test_repo_root_stays_untouched_and_isolated_env_works(tmp_path: Path) -> None:
    before = {p.name for p in REPO_ROOT.iterdir()}
    code, out, err = run_adapter(
        {
            "op": "setup",
            "owners": {"a1": "u1"},
            "contents": {"a1": "hello"},
            "disabled": [],
            "key_material": "secret-marker",
        },
        tmp_path,
        isolated_env=True,
        timeout=8.0,
    )
    assert code == 0, f"stderr={err!r}"
    assert json.loads(out.decode("utf-8")) == {"ready": True}
    after = {p.name for p in REPO_ROOT.iterdir()}
    assert before == after
    assert (tmp_path / "qshield_track4_state.sqlite3").is_file()


def test_stdout_64kib_cap_and_os_tempdir_fallback(tmp_path: Path) -> None:
    # Oversized response (>64 KiB) fails cleanly to stderr with empty stdout
    huge_body = "x" * 70000
    call_json(
        {
            "op": "setup",
            "owners": {"big": "alice"},
            "contents": {"big": huge_body},
            "disabled": [],
            "key_material": "km",
        },
        tmp_path,
    )
    code, out, err = run_adapter(
        {"op": "read", "actor": "alice", "asset": "big", "request_id": "req-big"},
        tmp_path,
    )
    assert code != 0
    assert out == b""
    assert len(err) <= MAX_STREAM_BYTES
    assert b"x" * 100 not in err

    # Fallback to OS temp dir when TRACK4_STATE_DIR is unset
    env = os.environ.copy()
    env.pop("TRACK4_STATE_DIR", None)
    env["TMPDIR"] = str(tmp_path)
    env["TEMP"] = str(tmp_path)
    env["TMP"] = str(tmp_path)
    proc = subprocess.run(
        [sys.executable, "-B", str(ADAPTER_ENTRY)],
        cwd=str(REPO_ROOT),
        env=env,
        input=json.dumps(
            {
                "op": "setup",
                "owners": {"t1": "u1"},
                "contents": {"t1": "temp-ok"},
                "disabled": [],
                "key_material": "km-temp",
            }
        ).encode("utf-8"),
        capture_output=True,
        timeout=8.0,
        check=False,
    )
    assert proc.returncode == 0
    assert json.loads(proc.stdout.decode("utf-8")) == {"ready": True}
    assert (tmp_path / "qshield_track4_state.sqlite3").is_file()
