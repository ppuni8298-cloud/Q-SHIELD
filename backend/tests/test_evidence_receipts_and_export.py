"""Independent tests for Phase 6 Signed Checkpoints, Evidence Receipts & Verifiable Exports."""

from __future__ import annotations

import base64

from fastapi.testclient import TestClient
from pqcrypto.sign import ml_dsa_65
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.audit.canonical import canonical_json_bytes, format_utc_timestamp
from backend.app.audit.evidence import verify_exported_package, verify_receipt_data
from backend.app.audit.ledger import append_audit_event
from backend.app.crypto.keystore import LocalEncryptedKeyStore
from backend.app.db.models import SettingEntry
from backend.app.services.seed import DEMO_SYNTHETIC_TOKENS


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_signed_checkpoints_and_evidence_receipts_verify_and_fail_on_tamper(
    client: TestClient,
    db_session: Session,
    keystore: LocalEncryptedKeyStore,
) -> None:
    secops_tok = DEMO_SYNTHETIC_TOKENS["sess-secops-valid"]
    auditor_tok = DEMO_SYNTHETIC_TOKENS["sess-auditor-valid"]

    created_ids: list[str] = []
    for i in range(4):
        row = append_audit_event(
            db_session,
            event_type="EVIDENCE_EVENT",
            event_category="CRYPTO",
            actor_id="user-secops",
            action=f"action_{i}",
            target_type="key",
            target_id=f"key-{i}",
            outcome="ALLOW",
            reason_code="OK",
            correlation_id=f"corr-ev-{i}",
            source_component="test",
            payload={"idx": i, "secret": "hidden-value"},
            commit=True,
        )
        created_ids.append(row.event_id)

    # 1. Create ML-DSA-65 signed checkpoint
    ckpt_resp = client.post("/api/v1/audit/checkpoints", json={}, headers=_auth(secops_tok))
    assert ckpt_resp.status_code == 201
    ckpt = ckpt_resp.json()
    assert ckpt["last_sequence"] == 4
    assert ckpt["signature_algorithm"] == "ML-DSA-65"
    assert ckpt["signer_key_id"] == "key-audit-signer-v1"

    latest_resp = client.get("/api/v1/audit/checkpoints/latest", headers=_auth(auditor_tok))
    assert latest_resp.status_code == 200 and latest_resp.json()["checkpoint_id"] == ckpt["checkpoint_id"]

    # Independent verification of checkpoint signature using raw pqcrypto ML-DSA-65 directly
    pk_b64 = db_session.get(SettingEntry, "audit_signer_public_key_b64").value
    pk_bytes = base64.b64decode(pk_b64)
    ckpt_msg = canonical_json_bytes(
        {
            "checkpoint_id": ckpt["checkpoint_id"],
            "ledger_id": "qshield-control-plane-audit-v1",
            "schema_version": ckpt["schema_version"],
            "first_sequence": ckpt["first_sequence"],
            "last_sequence": ckpt["last_sequence"],
            "root_hash": ckpt["root_hash"],
            "signature_algorithm": ckpt["signature_algorithm"],
            "signer_key_id": ckpt["signer_key_id"],
            "created_at": format_utc_timestamp(ckpt["created_at"]),
        }
    )
    assert ml_dsa_65.verify(pk_bytes, ckpt_msg, base64.b64decode(ckpt["signature_b64"])) is True

    # Modified checkpoint hash MUST fail independent verification
    tampered_ckpt_msg = ckpt_msg.replace(ckpt["root_hash"].encode("ascii"), b"0" * 64)
    assert ml_dsa_65.verify(pk_bytes, tampered_ckpt_msg, base64.b64decode(ckpt["signature_b64"])) is False

    # 2. Issue & verify event evidence receipt
    rcpt_resp = client.post(f"/api/v1/audit/events/{created_ids[2]}/receipt", headers=_auth(secops_tok))
    assert rcpt_resp.status_code == 201
    rcpt = rcpt_resp.json()
    assert rcpt["sequence"] == 3
    assert rcpt["event_id"] == created_ids[2]

    # Stored receipt verification & standalone verification pass
    v_stored = client.post(f"/api/v1/audit/receipts/{rcpt['receipt_id']}/verify", headers=_auth(auditor_tok))
    assert v_stored.status_code == 200 and v_stored.json()["valid"] is True

    ok_direct, _ = verify_receipt_data(rcpt, public_key_b64=pk_b64)
    assert ok_direct is True

    # Tampered receipt fails verification
    bad_rcpt = dict(rcpt, event_hash="a" * 64)
    assert client.post(
        "/api/v1/audit/receipts/verify",
        json={"receipt": bad_rcpt},
        headers=_auth(auditor_tok),
    ).json()["valid"] is False

    # Wrong public key fails verification
    wrong_pk, _ = ml_dsa_65.generate_keypair()
    wrong_pk_b64 = base64.b64encode(wrong_pk).decode("ascii")
    assert verify_receipt_data(rcpt, public_key_b64=wrong_pk_b64)[0] is False

    # Tamper underlying ledger -> creating new checkpoint refused cleanly (409)
    db_session.execute(text('UPDATE audit_events SET reason_code = "MUTATED" WHERE sequence = 2'))
    db_session.commit()
    bad_ckpt = client.post("/api/v1/audit/checkpoints", json={}, headers=_auth(secops_tok))
    assert bad_ckpt.status_code == 409


def test_evidence_export_independent_verification_range_tamper_and_secret_hygiene(
    client: TestClient,
    db_session: Session,
    keystore: LocalEncryptedKeyStore,
) -> None:
    auditor_tok = DEMO_SYNTHETIC_TOKENS["sess-auditor-valid"]

    for i in range(6):
        append_audit_event(
            db_session,
            event_type="EXPORT_EVT",
            event_category="PROTECTED_ACCESS",
            actor_id="user-alex",
            action=f"read_{i}",
            target_type="resource",
            target_id="res-alex-brief",
            outcome="ALLOW",
            reason_code="OK",
            correlation_id=f"corr-exp-{i}",
            source_component="test",
            payload={"step": i, "key_material": "top-secret-never-export"},
            commit=True,
        )

    # Export sub-range 2..5 and verify independently
    exp_resp = client.post(
        "/api/v1/audit/export",
        json={"first_sequence": 2, "last_sequence": 5},
        headers=_auth(auditor_tok),
    )
    assert exp_resp.status_code == 200
    pkg = exp_resp.json()
    assert pkg["first_sequence"] == 2
    assert pkg["last_sequence"] == 5
    assert len(pkg["events"]) == 4

    # Zero secret material in export
    raw_audit_sk_hex = keystore.get_secret_bytes("key-audit-signer-v1", expected_purpose="audit").hex()
    pkg_dump = str(pkg)
    assert "top-secret-never-export" not in pkg_dump
    assert raw_audit_sk_hex not in pkg_dump

    pk_b64 = db_session.get(SettingEntry, "audit_signer_public_key_b64").value
    ver_res = verify_exported_package(pkg, public_key_b64=pk_b64)
    assert ver_res.valid is True
    assert ver_res.verified_event_count == 4

    # API independent verify endpoint also verifies
    api_ver = client.post(
        "/api/v1/audit/export/verify",
        json={"package": pkg, "public_key_b64": pk_b64},
        headers=_auth(auditor_tok),
    )
    assert api_ver.status_code == 200 and api_ver.json()["valid"] is True

    # 1. Modified event in export -> rejected
    bad_mod = dict(pkg, events=[dict(e, payload=dict(e["payload"])) for e in pkg["events"]])
    bad_mod["events"][1]["payload"]["step"] = 999
    assert verify_exported_package(bad_mod, public_key_b64=pk_b64).valid is False

    # 2. Missing event from export -> rejected
    bad_miss = dict(pkg, events=pkg["events"][:-1])
    assert verify_exported_package(bad_miss, public_key_b64=pk_b64).valid is False

    # 3. Reordered events in export -> rejected
    bad_order = dict(pkg, events=[pkg["events"][1], pkg["events"][0], pkg["events"][2], pkg["events"][3]])
    assert verify_exported_package(bad_order, public_key_b64=pk_b64).valid is False

    # 4. Wrong signer public key -> rejected
    wrong_pk, _ = ml_dsa_65.generate_keypair()
    wrong_pk_b64 = base64.b64encode(wrong_pk).decode("ascii")
    assert verify_exported_package(pkg, public_key_b64=wrong_pk_b64).valid is False

    # 5. Altered export receipt -> rejected
    bad_rcpt_pkg = dict(pkg, receipt=dict(pkg["receipt"], chain_head_hash="b" * 64))
    assert verify_exported_package(bad_rcpt_pkg, public_key_b64=pk_b64).valid is False

    # 6. Export size limit check (>5000) -> rejected cleanly
    over_limit = client.post(
        "/api/v1/audit/export",
        json={"first_sequence": 1, "last_sequence": 6000},
        headers=_auth(auditor_tok),
    )
    assert over_limit.status_code == 400
