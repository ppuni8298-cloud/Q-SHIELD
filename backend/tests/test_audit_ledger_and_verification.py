"""Independent tests for Phase 6 Append-Only Audit Ledger, Tamper Detection, Concurrency & Coverage."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import unicodedata

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import select, text
from sqlalchemy.orm import Session

import backend.app.audit.ledger as ledger_mod
from backend.app.audit.canonical import AUDIT_GENESIS_PREV_HASH, event_model_to_dict
from backend.app.audit.ledger import (
    AuditAppendOnlyError,
    AuditError,
    append_audit_event,
    delete_audit_event,
    update_audit_event,
)
from backend.app.audit.verifier import verify_audit_records, verify_ledger_db
from backend.app.crypto.keystore import LocalEncryptedKeyStore
from backend.app.db.models import AuditEvent, Device, User, UserSession
from backend.app.db.session import create_session_factory
from backend.app.policy.engine import ZeroTrustPolicyEngine
from backend.app.schemas.policy import PolicyEvalRequest
from backend.app.services.seed import DEMO_SYNTHETIC_TOKENS


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _independent_sha256_event_hash(ev: dict) -> str:
    """Recompute exact Phase 6 digest formula independently without importing compute_audit_event_hash."""
    body = {
        "schema_version": ev["schema_version"],
        "hash_algorithm": ev["hash_algorithm"],
        "sequence": ev["sequence"],
        "event_id": ev["event_id"],
        "timestamp_utc": ev["timestamp_utc"],
        "event_type": ev["event_type"],
        "event_category": ev["event_category"],
        "actor_id": ev["actor_id"],
        "target_type": ev["target_type"],
        "target_id": ev["target_id"],
        "action": ev["action"],
        "outcome": ev["outcome"],
        "reason_code": ev["reason_code"],
        "correlation_id": ev["correlation_id"],
        "source_component": ev["source_component"],
        "payload": ev["payload"],
        "prev_hash": ev["prev_hash"],
    }
    canon = json.dumps(body, separators=(",", ":"), sort_keys=True, ensure_ascii=False, allow_nan=False).encode("utf-8")
    raw = b"QSHIELD-AUDIT-EVENT-V1|" + ev["prev_hash"].encode("ascii") + b"|" + str(ev["sequence"]).encode("ascii") + b"|" + canon
    return hashlib.sha256(raw).hexdigest()


def test_ledger_genesis_canonical_unicode_null_numeric_and_concurrency(db_engine, db_session: Session) -> None:
    fixed_ts = datetime(2026, 11, 26, 12, 0, 0, 123456, tzinfo=timezone.utc)

    # 1. Genesis event links to explicit 64-zero prev_hash & matches independent hash computation
    # Use decomposed Unicode ("e\u0301") + -0.0 + None + control characters to verify canonical normalization & injection defense
    e1 = append_audit_event(
        db_session,
        event_type="TEST_GENESIS",
        event_category="AUDIT",
        actor_id="user-admin",
        action="init\nfake_line=true",
        target_type="ledger",
        target_id="main",
        outcome="ALLOW",
        reason_code="INIT_OK",
        correlation_id="corr-gen",
        source_component="test_suite",
        payload={"unicode": "Cafe\u0301", "zero": -0.0, "empty": None, "b_key": 42, "a_key": True, "password": "do-not-store-password"},
        timestamp_utc=fixed_ts,
        commit=True,
    )
    assert e1.sequence == 1
    assert e1.prev_hash == AUDIT_GENESIS_PREV_HASH
    assert "\n" not in e1.action
    assert "\\n" in e1.action
    d1 = event_model_to_dict(e1)
    assert d1["payload"]["unicode"] == unicodedata.normalize("NFC", "Cafe\u0301")
    assert d1["payload"]["password"] == "[REDACTED]"
    assert d1["payload"]["empty"] is None
    assert d1["payload"]["zero"] == 0.0
    assert d1["event_hash"] == _independent_sha256_event_hash(d1)

    # 2. Second event chains prev_hash == e1.event_hash
    e2 = append_audit_event(
        db_session,
        event_type="TEST_SECOND",
        event_category="AUDIT",
        actor_id="user-secops",
        action="verify",
        target_type="ledger",
        target_id="main",
        outcome="ALLOW",
        reason_code="SECOND_OK",
        correlation_id="corr-2",
        source_component="test_suite",
        payload={"nested": {"raw_secret": "shh-123"}},
        commit=True,
    )
    assert e2.sequence == 2
    assert e2.prev_hash == e1.event_hash
    assert "shh-123" not in e2.payload_json

    # 3. Concurrent multi-thread event insertion across separate SQLite WAL sessions
    factory = create_session_factory(db_engine)

    def _worker(idx: int) -> int:
        with factory() as sess:
            ev = append_audit_event(
                sess,
                event_type="CONCURRENT_OP",
                event_category="AUDIT",
                actor_id=f"user-worker-{idx}",
                action="concurrent_write",
                target_type="ledger",
                target_id=f"item-{idx}",
                outcome="ALLOW",
                reason_code="CONCURRENT_OK",
                correlation_id=f"corr-w-{idx}",
                source_component="concurrency_test",
                payload={"worker": idx},
                commit=True,
            )
            return ev.sequence

    with ThreadPoolExecutor(max_workers=6) as pool:
        seqs = sorted(pool.map(_worker, range(12)))
    assert seqs == list(range(3, 15))

    db_session.expire_all()
    ver = verify_ledger_db(db_session)
    assert ver.valid is True
    assert ver.verified_event_count == 14
    assert ver.head_hash is not None


def test_tamper_detection_across_all_11_attack_scenarios_and_non_repair(db_session: Session) -> None:
    for i in range(4):
        append_audit_event(
            db_session,
            event_type="CHAIN_SEED",
            event_category="CRYPTO",
            actor_id="user-secops",
            action=f"op_{i}",
            target_type="key",
            target_id=f"k-{i}",
            outcome="ALLOW",
            reason_code="OK",
            correlation_id=f"corr-{i}",
            source_component="test",
            payload={"step": i},
            commit=True,
        )
    assert verify_ledger_db(db_session).valid is True

    rows = list(db_session.scalars(select(AuditEvent).order_by(AuditEvent.sequence.asc())).all())
    clean_dicts = [event_model_to_dict(r) for r in rows]

    # 1. Modified payload
    tampered = [dict(x, payload=dict(x["payload"])) for x in clean_dicts]
    tampered[1]["payload"]["step"] = 999
    r_mod_payload = verify_audit_records(tampered)
    assert r_mod_payload.valid is False and r_mod_payload.first_invalid_sequence == 2
    assert r_mod_payload.failure_category == "EVENT_HASH_OR_PAYLOAD_MISMATCH"

    # 2. Modified event hash
    tampered = [dict(x) for x in clean_dicts]
    tampered[2]["event_hash"] = "f" * 64
    r_mod_hash = verify_audit_records(tampered)
    assert r_mod_hash.valid is False and r_mod_hash.first_invalid_sequence == 3
    assert r_mod_hash.failure_category == "EVENT_HASH_OR_PAYLOAD_MISMATCH"

    # 3. Modified prev_hash
    tampered = [dict(x) for x in clean_dicts]
    tampered[2]["prev_hash"] = "a" * 64
    r_mod_prev = verify_audit_records(tampered)
    assert r_mod_prev.valid is False and r_mod_prev.first_invalid_sequence == 3
    assert r_mod_prev.failure_category == "PREV_HASH_MISMATCH"

    # 4. Deleted middle event / sequence gap
    tampered = [clean_dicts[0], clean_dicts[2], clean_dicts[3]]
    r_del = verify_audit_records(tampered)
    assert r_del.valid is False and r_del.first_invalid_sequence == 3
    assert r_del.failure_category == "SEQUENCE_GAP_OR_DELETED_EVENT"

    # 5. Duplicate sequence
    tampered = [clean_dicts[0], clean_dicts[1], clean_dicts[1], clean_dicts[2]]
    r_dup = verify_audit_records(tampered)
    assert r_dup.valid is False and r_dup.failure_category == "DUPLICATE_SEQUENCE"

    # 6. Reordered events
    tampered = [clean_dicts[0], clean_dicts[2], clean_dicts[1], clean_dicts[3]]
    r_reord = verify_audit_records(tampered)
    assert r_reord.valid is False and r_reord.first_invalid_sequence == 3

    # 7. Inserted forged event in middle (even if sequence numbers renumbered or inserted before tail)
    forged = dict(clean_dicts[1], event_id="audit-forged", payload={"step": 77})
    r_ins = verify_audit_records([clean_dicts[0], forged, clean_dicts[2], clean_dicts[3]])
    assert r_ins.valid is False and r_ins.first_invalid_sequence == 2

    # 8. Invalid genesis record (wrong genesis sequence OR wrong genesis prev_hash)
    bad_gen_seq = verify_audit_records(clean_dicts[1:])
    assert bad_gen_seq.valid is False and bad_gen_seq.failure_category == "MISSING_GENESIS_OR_SEQUENCE_GAP"
    tampered_gen = [dict(x) for x in clean_dicts]
    tampered_gen[0]["prev_hash"] = "1" * 64
    r_bad_gen_prev = verify_audit_records(tampered_gen)
    assert r_bad_gen_prev.valid is False and r_bad_gen_prev.failure_category == "INVALID_GENESIS_RECORD"

    # 9. Unsupported schema version & bad canonical serialization
    tampered_schema = [dict(x) for x in clean_dicts]
    tampered_schema[0]["schema_version"] = "qshield.audit.v999"
    r_bad_schema = verify_audit_records(tampered_schema)
    assert r_bad_schema.valid is False and r_bad_schema.failure_category == "INVALID_SCHEMA_VERSION"

    tampered_bad_ts = [dict(x) for x in clean_dicts]
    tampered_bad_ts[1]["timestamp_utc"] = "not-a-timestamp"
    r_bad_ser = verify_audit_records(tampered_bad_ts)
    assert r_bad_ser.valid is False and r_bad_ser.failure_category == "INVALID_CANONICAL_SERIALIZATION"

    # 10. Raw DB SQL tampering does NOT get repaired by verify_ledger_db
    db_session.execute(
        text('UPDATE audit_events SET payload_json = :p WHERE sequence = 2'),
        {"p": '{"step":12345}'},
    )
    db_session.commit()
    db_session.expire_all()
    db_ver1 = verify_ledger_db(db_session)
    db_ver2 = verify_ledger_db(db_session)
    assert db_ver1.valid is False and db_ver1.first_invalid_sequence == 2
    assert db_ver2.valid is False and db_ver2.first_invalid_sequence == 2


def test_append_only_guards_outbox_and_fail_closed_policy(
    client: TestClient,
    db_session: Session,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secops_tok = DEMO_SYNTHETIC_TOKENS["sess-secops-valid"]
    auditor_tok = DEMO_SYNTHETIC_TOKENS["sess-auditor-valid"]

    ev = append_audit_event(
        db_session,
        event_type="APPEND_ONLY_TARGET",
        event_category="AUDIT",
        actor_id="user-admin",
        action="test_guard",
        target_type="ledger",
        target_id="1",
        outcome="ALLOW",
        reason_code="OK",
        correlation_id="corr-guard",
        source_component="test",
        commit=True,
    )

    # 1. Service update/delete rejected
    with pytest.raises(AuditAppendOnlyError):
        update_audit_event(db_session, ev)
    with pytest.raises(AuditAppendOnlyError):
        delete_audit_event(db_session, ev)

    # 2. ORM mutation / delete rejected before flush
    ev.reason_code = "TAMPERED_REASON"
    with pytest.raises(AuditAppendOnlyError):
        db_session.flush()
    db_session.rollback()

    ev_fresh = db_session.get(AuditEvent, 1)
    db_session.delete(ev_fresh)
    with pytest.raises(AuditAppendOnlyError):
        db_session.flush()
    db_session.rollback()

    # 3. API rejects HTTP PUT/PATCH/DELETE on audit routes (no mutation endpoints exist)
    for method in ("put", "patch", "delete"):
        resp = getattr(client, method)(f"/api/v1/audit/events/{ev.event_id}", headers=_auth(secops_tok))
        assert resp.status_code == 405

    # Auditor cannot create checkpoints or receipts; owner cannot read audit ledger
    assert client.get("/api/v1/audit/events", headers=_auth(DEMO_SYNTHETIC_TOKENS["sess-alex-valid"])).status_code == 403
    assert client.post("/api/v1/audit/checkpoints", json={}, headers=_auth(auditor_tok)).status_code == 403

    # 4. Failed audit write on ALLOW policy MUST fail closed to DENY (never silently grant access)
    engine = ZeroTrustPolicyEngine()
    monkeypatch.setattr(
        "backend.app.policy.engine.append_audit_event",
        lambda *_a, **_kw: (_ for _ in ()).throw(RuntimeError("Simulated audit storage outage")),
    )
    decision_allow_req = engine.evaluate(
        db_session,
        PolicyEvalRequest(
            actor_id="user-alex",
            session_id="sess-alex-valid",
            device_id="dev-alex-trusted",
            resource_id="res-alex-brief",
            action="read",
        ),
        correlation_id="corr-audit-fail-allow",
    )
    assert decision_allow_req.decision == "DENY"
    assert decision_allow_req.reason_code == "DENY_INTERNAL_ERROR"

    # And a denied request STILL returns DENY when audit insertion fails
    decision_deny_req = engine.evaluate(
        db_session,
        PolicyEvalRequest(
            actor_id="user-blair",
            session_id="sess-blair-valid",
            device_id="dev-blair-trusted",
            resource_id="res-alex-brief",
            action="read",
        ),
        correlation_id="corr-audit-fail-deny",
    )
    assert decision_deny_req.decision == "DENY"

    # 5. Durable outbox captures standalone failed DB write
    outbox = tmp_path / "audit_outbox.jsonl"
    orig_add = db_session.add

    def _boom_add(obj):
        if isinstance(obj, AuditEvent):
            raise RuntimeError("Simulated SQLite disk error")
        return orig_add(obj)

    monkeypatch.setattr(db_session, "add", _boom_add)
    with pytest.raises(AuditError):
        append_audit_event(
            db_session,
            event_type="OUTBOX_TEST",
            event_category="AUDIT",
            actor_id="user-admin",
            action="test_outbox",
            target_type="system",
            target_id="outbox",
            outcome="DENY",
            reason_code="FAIL_TEST",
            correlation_id="corr-outbox",
            source_component="test",
            outbox_path=outbox,
        )
    assert outbox.exists()
    assert "OUTBOX_TEST" in outbox.read_text(encoding="utf-8")


def test_full_security_operation_audit_coverage_and_zero_secret_leakage(
    client: TestClient,
    db_session: Session,
    keystore: LocalEncryptedKeyStore,
) -> None:
    alex_tok = DEMO_SYNTHETIC_TOKENS["sess-alex-valid"]
    blair_tok = DEMO_SYNTHETIC_TOKENS["sess-blair-valid"]
    secops_tok = DEMO_SYNTHETIC_TOKENS["sess-secops-valid"]
    admin_tok = DEMO_SYNTHETIC_TOKENS["sess-admin-valid"]
    auditor_tok = DEMO_SYNTHETIC_TOKENS["sess-auditor-valid"]

    classified_body = "ULTRA_SENSITIVE_AUDIT_LEAK_MARKER_88991"

    # Identity auth success & failure
    assert client.post("/api/v1/auth/demo-login", json={"actor_id": "user-alex", "device_id": "dev-alex-trusted"}).status_code == 200
    assert client.post("/api/v1/auth/demo-login", json={"actor_id": "user-disabled", "device_id": "dev-alex-trusted"}).status_code == 403

    # RBAC denial + identity creation + role change
    assert client.get("/api/v1/keys", headers=_auth(alex_tok)).status_code == 403
    assert client.post(
        "/api/v1/users",
        json={"id": "user-temp-audit", "display_name": "Temp User", "role": "owner", "reason": "Audit test", "confirmation": True},
        headers=_auth(admin_tok),
    ).status_code == 201
    assert client.patch(
        "/api/v1/users/user-temp-audit",
        json={"role": "auditor", "enabled": False, "reason": "Role shift & disable", "confirmation": True},
        headers=_auth(admin_tok),
    ).status_code == 200

    # Device enroll + revoke
    assert client.post(
        "/api/v1/devices/enroll",
        json={"id": "dev-audit-01", "owner_id": "user-alex", "credential_fingerprint": "fp-audit-01", "initial_state": "PENDING", "reason": "Enroll check"},
        headers=_auth(alex_tok),
    ).status_code == 201
    assert client.post(
        "/api/v1/devices/dev-audit-01/revoke",
        json={"reason": "Lost in test", "confirmation": True},
        headers=_auth(secops_tok),
    ).status_code == 200

    # Protected resource encrypt + decrypt + cross-user deny
    assert client.post("/api/v1/resources/res-alex-brief/encrypt", json={"plaintext": classified_body}, headers=_auth(alex_tok)).status_code == 201
    assert client.post("/api/v1/resources/res-alex-brief/decrypt", headers=_auth(alex_tok)).status_code == 200
    assert client.post("/api/v1/resources/res-alex-brief/decrypt", headers=_auth(blair_tok)).status_code == 403

    # Node configuration, revocation propagation & convergence, stale node denial
    assert client.post("/api/v1/nodes/configure", json={"node_count": 3, "reason": "Audit nodes"}, headers=_auth(secops_tok)).status_code == 200
    assert (
        client.post(
            "/api/v1/nodes/node-2/availability",
            json={"available": False, "fault_mode": "OFFLINE", "reason": "Audit offline drill"},
            headers=_auth(secops_tok),
        ).status_code
        == 200
    )
    assert client.post("/api/v1/nodes/node-2/access", json={"resource_id": "res-alex-brief", "action": "read"}, headers=_auth(alex_tok)).status_code == 403
    assert client.post("/api/v1/nodes/node-2/restart", headers=_auth(secops_tok)).status_code == 200
    assert (
        client.post(
            "/api/v1/revocations",
            json={"subject_type": "device", "subject_id": "dev-blair-trusted", "reason": "Audit revocation drill", "confirmation": True},
            headers=_auth(secops_tok),
        ).status_code
        == 201
    )

    # Backup create + verify + rotation + crash recovery
    bkp = client.post("/api/v1/keys/backups/create", json={"reason": "Audit backup test"}, headers=_auth(secops_tok))
    assert bkp.status_code == 201
    assert client.post(f"/api/v1/keys/backups/{bkp.json()['backup_id']}/verify", headers=_auth(auditor_tok)).status_code == 200
    assert client.post(
        "/api/v1/keys/rotate",
        json={"purpose": "vault_kek", "reason": "Audit rotation coverage", "auto_advance": True},
        headers=_auth(secops_tok),
    ).status_code == 201
    crashed = client.post(
        "/api/v1/keys/rotate",
        json={"purpose": "vault_kek", "reason": "Audit crash coverage", "crash_at": "BEFORE_COMMIT"},
        headers=_auth(secops_tok),
    )
    assert crashed.status_code == 500
    assert client.post("/api/v1/keys/recovery/run", json={}, headers=_auth(secops_tok)).status_code == 200

    # Query audit ledger & verify chain integrity
    ver = client.post("/api/v1/audit/verify", json={}, headers=_auth(auditor_tok))
    assert ver.status_code == 200
    assert ver.json()["valid"] is True
    assert ver.json()["verified_event_count"] >= 24

    events_resp = client.get("/api/v1/audit/events?limit=200", headers=_auth(auditor_tok))
    assert events_resp.status_code == 200
    types = {e["event_type"] for e in events_resp.json()["items"]}
    for expected in (
        "AUTH_LOGIN_SUCCESS",
        "AUTH_LOGIN_FAILED",
        "AUTHORIZATION_DENIED",
        "IDENTITY_CREATED",
        "ROLE_CHANGED",
        "DEVICE_ENROLLED",
        "DEVICE_REVOKED",
        "RESOURCE_ENCRYPTED",
        "RESOURCE_DECRYPTED",
        "ACCESS_DENIED",
        "NODES_CONFIGURED",
        "NODE_AVAILABILITY_CHANGED",
        "NODE_ACCESS_DENIED",
        "NODE_RESTARTED",
        "REVOCATION_ISSUED",
        "REVOCATION_PROPAGATION",
        "REVOCATION_CONVERGENCE",
        "BACKUP_CREATED",
        "BACKUP_VERIFIED",
        "KEY_ROTATION_STAGE",
        "CRASH_RECOVERY_EXECUTED",
    ):
        assert expected in types, f"Missing expected audit event type: {expected}"

    # Zero leakage of resource plaintext or raw KEK/token secrets in entire audit table/API
    raw_dump = events_resp.text
    assert classified_body not in raw_dump
    assert DEMO_SYNTHETIC_TOKENS["sess-alex-valid"] not in raw_dump
    raw_kek = keystore.get_secret_bytes("key-v1-active", expected_purpose="vault_kek").hex()
    assert raw_kek not in raw_dump
