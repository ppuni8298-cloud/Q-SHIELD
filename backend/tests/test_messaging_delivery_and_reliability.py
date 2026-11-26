"""Phase 8 tests: Delivery reliability simulator, revocation invalidation, concurrency, audit & RBAC."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.audit.verifier import verify_ledger_db
from backend.app.crypto.hmac_hash import sha256_hex
from backend.app.crypto.keystore import LocalEncryptedKeyStore
from backend.app.db.models import AuditEvent, CryptoSession, MessageDelivery, MessageRecord, NodeRegistry, utc_now
from backend.app.messaging.message_service import send_encrypted_message
from backend.app.messaging.session_manager import establish_messaging_session
from backend.app.services.seed import DEMO_SYNTHETIC_TOKENS


def _auth(tok: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {tok}"}


def _establish_alex_blair(client: TestClient) -> dict:
    r = client.post(
        "/api/v1/messages/sessions",
        json={"recipient_id": "user-blair", "recipient_device_id": "dev-blair-trusted", "ttl_seconds": 1800},
        headers=_auth(DEMO_SYNTHETIC_TOKENS["sess-alex-valid"]),
    )
    assert r.status_code == 200
    return r.json()


def _send_one(client: TestClient, sess_id: str, text_body: str = "hello") -> dict:
    r = client.post(
        "/api/v1/messages/send",
        json={"session_id": sess_id, "plaintext": text_body},
        headers=_auth(DEMO_SYNTHETIC_TOKENS["sess-alex-valid"]),
    )
    assert r.status_code == 200, r.text
    return r.json()


def test_21_normal_delivery_verify_endpoint_without_plaintext_release(client: TestClient) -> None:
    sess_id = _establish_alex_blair(client)["session"]["id"]
    sent = _send_one(client, sess_id, "verify-without-decrypt-secret")
    msg_id = sent["message"]["message_id"]

    ver = client.post(f"/api/v1/messages/{msg_id}/verify", headers=_auth(DEMO_SYNTHETIC_TOKENS["sess-auditor-valid"]))
    assert ver.status_code == 200
    body = ver.json()
    assert body["verified"] is True and body["aad_valid"] is True and body["already_consumed"] is False
    assert "verify-without-decrypt-secret" not in ver.text

    deliv = client.get(f"/api/v1/messages/{msg_id}/delivery", headers=_auth(DEMO_SYNTHETIC_TOKENS["sess-blair-valid"]))
    assert deliv.status_code == 200 and deliv.json()["status"] == "QUEUED"


def test_22_packet_loss_within_retry_limit_recovers_and_delivers(client: TestClient) -> None:
    sess_id = _establish_alex_blair(client)["session"]["id"]
    msg_id = _send_one(client, sess_id, "recoverable-packet")["message"]["message_id"]

    sim = client.post(
        f"/api/v1/messages/{msg_id}/simulate-loss",
        json={"drop_attempts": 2, "max_retries": 3, "delay_ms": 40},
        headers=_auth(DEMO_SYNTHETIC_TOKENS["sess-secops-valid"]),
    )
    assert sim.status_code == 200
    s_json = sim.json()
    assert s_json["status"] == "DELAYED"
    assert s_json["attempt_count"] == 3
    assert s_json["simulated_delay_ms"] >= 40

    rec = client.post(
        "/api/v1/messages/receive",
        json={"message_id": msg_id},
        headers=_auth(DEMO_SYNTHETIC_TOKENS["sess-blair-valid"]),
    )
    assert rec.status_code == 200 and rec.json()["plaintext"] == "recoverable-packet"


def test_23_packet_loss_exceeding_max_retries_honestly_dead_letters(client: TestClient) -> None:
    sess_id = _establish_alex_blair(client)["session"]["id"]
    msg_id = _send_one(client, sess_id, "exhausted-packet")["message"]["message_id"]

    sim = client.post(
        f"/api/v1/messages/{msg_id}/simulate-loss",
        json={"drop_attempts": 5, "max_retries": 3},
        headers=_auth(DEMO_SYNTHETIC_TOKENS["sess-secops-valid"]),
    )
    assert sim.status_code == 200
    assert sim.json()["status"] == "DEAD_LETTER"
    assert sim.json()["last_error_code"] == "DELIVERY_RETRY_EXHAUSTED"

    msg_meta = client.get(f"/api/v1/messages/{msg_id}", headers=_auth(DEMO_SYNTHETIC_TOKENS["sess-alex-valid"]))
    assert msg_meta.json()["status"] == "DEAD_LETTER"


def test_24_simulated_delay_vs_ttl_expiry(client: TestClient, db_session: Session) -> None:
    sess_id = _establish_alex_blair(client)["session"]["id"]
    msg_id = _send_one(client, sess_id, "ttl-vs-delay")["message"]["message_id"]

    sim = client.post(
        f"/api/v1/messages/{msg_id}/simulate-loss",
        json={"drop_attempts": 0, "max_retries": 3, "delay_ms": 500},
        headers=_auth(DEMO_SYNTHETIC_TOKENS["sess-alex-valid"]),
    )
    assert sim.status_code == 200 and sim.json()["simulated_delay_ms"] >= 500

    # Simulate expiry passing while delayed in queue -> receive fails closed
    row = db_session.get(MessageRecord, msg_id)
    row.expires_at = utc_now() - timedelta(seconds=5)
    db_session.commit()
    rec = client.post(
        "/api/v1/messages/receive",
        json={"message_id": msg_id},
        headers=_auth(DEMO_SYNTHETIC_TOKENS["sess-blair-valid"]),
    )
    assert rec.status_code == 403 and rec.json()["error"]["code"] == "DENY_MESSAGE_EXPIRED"


def test_25_out_of_order_delivery_recovers_in_canonical_sequence_order(client: TestClient) -> None:
    sess_id = _establish_alex_blair(client)["session"]["id"]
    m1 = _send_one(client, sess_id, "seq-1")["message"]["message_id"]
    m2 = _send_one(client, sess_id, "seq-2")["message"]["message_id"]
    m3 = _send_one(client, sess_id, "seq-3")["message"]["message_id"]

    # Arrive out of order: [m3, m1, m2] -> buffer delivers strictly [m1, m2, m3]
    ro = client.post(
        "/api/v1/messages/simulate-reorder",
        json={"message_ids_arrival_order": [m3, m1, m2]},
        headers=_auth(DEMO_SYNTHETIC_TOKENS["sess-blair-valid"]),
    )
    assert ro.status_code == 200
    assert ro.json()["delivered_order"] == [m1, m2, m3]
    assert ro.json()["discarded"] == []


def test_26_reorder_buffer_discards_corrupt_duplicate_and_missing_entries(
    client: TestClient, db_session: Session
) -> None:
    sess_id = _establish_alex_blair(client)["session"]["id"]
    m1 = _send_one(client, sess_id, "valid-1")["message"]["message_id"]
    m2 = _send_one(client, sess_id, "corrupt-2")["message"]["message_id"]

    # Tamper AAD field on m2 inside DB
    row2 = db_session.get(MessageRecord, m2)
    row2.encrypted_envelope = row2.encrypted_envelope.replace("qshield.msg.aad.v1", "bad.schema")
    db_session.commit()

    ro = client.post(
        "/api/v1/messages/simulate-reorder",
        json={"message_ids_arrival_order": [m2, m1, m1, "msg-does-not-exist"]},
        headers=_auth(DEMO_SYNTHETIC_TOKENS["sess-blair-valid"]),
    )
    assert ro.status_code == 200
    assert ro.json()["delivered_order"] == [m1]
    reasons = {d["message_id"]: d["reason"] for d in ro.json()["discarded"]}
    assert "UNSUPPORTED_SCHEMA" in reasons[m2]
    assert reasons["msg-does-not-exist"] == "MISSING_OR_UNKNOWN_MESSAGE"


def test_27_reorder_buffer_bounded_capacity_enforced(client: TestClient) -> None:
    too_many = [f"m-{i}" for i in range(33)]
    res = client.post(
        "/api/v1/messages/simulate-reorder",
        json={"message_ids_arrival_order": too_many},
        headers=_auth(DEMO_SYNTHETIC_TOKENS["sess-blair-valid"]),
    )
    assert res.status_code == 422


def test_28_duplicate_delivery_blocked_after_initial_acceptance(client: TestClient) -> None:
    sess_id = _establish_alex_blair(client)["session"]["id"]
    m1 = _send_one(client, sess_id, "single-delivery")["message"]["message_id"]

    assert (
        client.post(
            "/api/v1/messages/receive",
            json={"message_id": m1},
            headers=_auth(DEMO_SYNTHETIC_TOKENS["sess-blair-valid"]),
        ).status_code
        == 200
    )

    ro = client.post(
        "/api/v1/messages/simulate-reorder",
        json={"message_ids_arrival_order": [m1]},
        headers=_auth(DEMO_SYNTHETIC_TOKENS["sess-blair-valid"]),
    )
    assert ro.status_code == 200
    assert ro.json()["delivered_order"] == []
    assert ro.json()["discarded"][0]["reason"] == "REPLAY_DETECTED"


def test_29_duplicate_acknowledgements_ignored_idempotently(client: TestClient) -> None:
    sess_id = _establish_alex_blair(client)["session"]["id"]
    m1 = _send_one(client, sess_id, "ack-target")["message"]["message_id"]
    client.post(
        "/api/v1/messages/receive",
        json={"message_id": m1},
        headers=_auth(DEMO_SYNTHETIC_TOKENS["sess-blair-valid"]),
    )

    a1 = client.post(f"/api/v1/messages/{m1}/ack", headers=_auth(DEMO_SYNTHETIC_TOKENS["sess-blair-valid"]))
    assert a1.status_code == 200
    assert a1.json()["duplicate_ack_ignored"] is False
    assert a1.json()["delivery"]["ack_count"] == 1
    assert a1.json()["delivery"]["status"] == "ACKED"

    a2 = client.post(f"/api/v1/messages/{m1}/ack", headers=_auth(DEMO_SYNTHETIC_TOKENS["sess-blair-valid"]))
    assert a2.status_code == 200
    assert a2.json()["duplicate_ack_ignored"] is True
    assert a2.json()["delivery"]["ack_count"] == 1
    assert a2.json()["delivery"]["duplicate_acks_ignored"] == 1
    assert a2.json()["delivery"]["status"] == "DUPLICATE_ACK_IGNORED"


def test_30_node_disconnection_blocks_delivery_until_reconnect(client: TestClient) -> None:
    sess_id = _establish_alex_blair(client)["session"]["id"]
    m1 = _send_one(client, sess_id, "node-disconnect-test")["message"]["message_id"]

    # Disconnect relay node without reconnecting -> send routed explicitly to that offline node fails 503
    disc = client.post(
        f"/api/v1/messages/{m1}/simulate-loss",
        json={"drop_attempts": 0, "disconnect_node_first": True, "reconnect_after": False},
        headers=_auth(DEMO_SYNTHETIC_TOKENS["sess-secops-valid"]),
    )
    assert disc.status_code == 200 and disc.json()["status"] == "DISCONNECTED"
    offline_node = disc.json()["relay_node_id"]

    blocked_send = client.post(
        "/api/v1/messages/send",
        json={"session_id": sess_id, "plaintext": "via-offline-node", "relay_node_id": offline_node},
        headers=_auth(DEMO_SYNTHETIC_TOKENS["sess-alex-valid"]),
    )
    assert blocked_send.status_code == 503 and blocked_send.json()["error"]["code"] == "NODE_DISCONNECTED"

    # Reconnect and deliver cleanly
    rec = client.post(
        f"/api/v1/messages/{m1}/simulate-loss",
        json={"drop_attempts": 0, "disconnect_node_first": True, "reconnect_after": True},
        headers=_auth(DEMO_SYNTHETIC_TOKENS["sess-secops-valid"]),
    )
    assert rec.status_code == 200 and rec.json()["status"] == "IN_TRANSIT"
    assert (
        client.post(
            "/api/v1/messages/receive",
            json={"message_id": m1},
            headers=_auth(DEMO_SYNTHETIC_TOKENS["sess-blair-valid"]),
        ).json()["plaintext"]
        == "node-disconnect-test"
    )


def test_31_revocation_of_device_identity_or_key_invalidates_messaging_session(
    client: TestClient, db_session: Session
) -> None:
    sess_id = _establish_alex_blair(client)["session"]["id"]
    msg_id = _send_one(client, sess_id, "before-device-loss")["message"]["message_id"]

    # Revoke Blair's device via Phase 4 revocation coordinator endpoint!
    rev = client.post(
        "/api/v1/revocations",
        json={
            "subject_type": "device",
            "subject_id": "dev-blair-trusted",
            "reason": "Simulated device theft during active messaging",
            "confirmation": True,
        },
        headers=_auth(DEMO_SYNTHETIC_TOKENS["sess-secops-valid"]),
    )
    assert rev.status_code == 201

    db_session.expire_all()
    csess = db_session.get(CryptoSession, sess_id)
    assert csess.state == "REVOKED"

    # Note: Blair's bearer token was bound to dev-blair-trusted so AuthMiddleware returns 401/403 too,
    # AND direct receive attempt / Alex send attempt inside revoked session BOTH fail closed!
    send_after = client.post(
        "/api/v1/messages/send",
        json={"session_id": sess_id, "plaintext": "blocked-after-revoke"},
        headers=_auth(DEMO_SYNTHETIC_TOKENS["sess-alex-valid"]),
    )
    assert send_after.status_code == 403 and send_after.json()["error"]["code"] == "DENY_SESSION_REVOKED"

    recv_after = client.post(
        "/api/v1/messages/receive",
        json={"message_id": msg_id},
        headers=_auth(DEMO_SYNTHETIC_TOKENS["sess-blair-valid"]),
    )
    assert recv_after.status_code in (401, 403)
    assert "before-device-loss" not in recv_after.text


def test_32_concurrent_sends_and_duplicate_receive_race_safety(client: TestClient) -> None:
    sess_id = _establish_alex_blair(client)["session"]["id"]
    m_race = _send_one(client, sess_id, "race-payload")["message"]["message_id"]

    # Concurrent receive race on same message: only 1 worker can decrypt, rest get 409 REPLAY_DETECTED
    def _try_recv(_i: int) -> int:
        return client.post(
            "/api/v1/messages/receive",
            json={"message_id": m_race},
            headers=_auth(DEMO_SYNTHETIC_TOKENS["sess-blair-valid"]),
        ).status_code

    with ThreadPoolExecutor(max_workers=4) as pool:
        codes = list(pool.map(_try_recv, range(4)))
    assert codes.count(200) == 1
    assert all(c in (200, 409) for c in codes)


def test_33_audit_ledger_integrity_and_zero_secret_or_plaintext_leakage(
    client: TestClient, db_session: Session
) -> None:
    est = _establish_alex_blair(client)
    sess_id = est["session"]["id"]
    res_tok = est["resumption_token"]
    secret_body = "ULTRA_CONFIDENTIAL_MESSAGE_XYZ123"
    m1 = _send_one(client, sess_id, secret_body)["message"]["message_id"]
    client.post(
        "/api/v1/messages/receive",
        json={"message_id": m1},
        headers=_auth(DEMO_SYNTHETIC_TOKENS["sess-blair-valid"]),
    )

    db_session.expire_all()
    ver = verify_ledger_db(db_session)
    assert ver.valid is True

    # Inspect all audit events -> ZERO plaintext or resumption tokens leaked!
    rows = db_session.query(AuditEvent).all()
    assert any(r.event_type == "MSG_SESSION_ESTABLISHED" for r in rows)
    assert any(r.event_type == "MSG_SENT" for r in rows)
    assert any(r.event_type == "MSG_DELIVERED" for r in rows)
    for r in rows:
        assert secret_body not in r.payload_json
        assert res_tok not in r.payload_json


def test_34_messaging_rbac_boundaries_owner_auditor_secops_admin(client: TestClient) -> None:
    sess_id = _establish_alex_blair(client)["session"]["id"]
    m1 = _send_one(client, sess_id, "rbac-secret")["message"]["message_id"]

    # Uninvolved third-party secops cannot send/receive as Alex or Blair, CAN read non-plaintext metadata
    assert (
        client.post(
            "/api/v1/messages/send",
            json={"session_id": sess_id, "plaintext": "impersonate"},
            headers=_auth(DEMO_SYNTHETIC_TOKENS["sess-secops-valid"]),
        ).status_code
        == 403
    )

    # Auditor can inspect session status, delivery, and replay evidence (no plaintext), CANNOT establish/send/receive
    aud_tok = DEMO_SYNTHETIC_TOKENS["sess-auditor-valid"]
    assert client.get(f"/api/v1/messages/sessions/{sess_id}", headers=_auth(aud_tok)).status_code == 200
    aud_list = client.get("/api/v1/messages", headers=_auth(aud_tok))
    assert aud_list.status_code == 200 and "rbac-secret" not in aud_list.text
    assert (
        client.post(
            "/api/v1/messages/sessions",
            json={"recipient_id": "user-blair", "recipient_device_id": "dev-blair-trusted"},
            headers=_auth(aud_tok),
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/v1/messages/send",
            json={"session_id": sess_id, "plaintext": "blocked"},
            headers=_auth(aud_tok),
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/v1/messages/receive",
            json={"message_id": m1},
            headers=_auth(aud_tok),
        ).status_code
        == 403
    )
