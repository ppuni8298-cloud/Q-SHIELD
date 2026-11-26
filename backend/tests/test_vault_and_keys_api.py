"""Independent black-box API tests for Phase 3 key lifecycle, envelope vault, and tamper defense."""

from __future__ import annotations

import base64
import json

from fastapi.testclient import TestClient
from sqlalchemy import text

from backend.app.crypto.keystore import LocalEncryptedKeyStore
from backend.app.db.session import create_session_factory
from backend.app.services.seed import DEMO_SYNTHETIC_TOKENS


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_crypto_selftest_and_ready_endpoints(client: TestClient) -> None:
    secops_tok = DEMO_SYNTHETIC_TOKENS["sess-secops-valid"]
    alex_tok = DEMO_SYNTHETIC_TOKENS["sess-alex-valid"]

    ready = client.get("/api/v1/ready")
    assert ready.status_code == 200 and ready.json()["crypto"] == "ok"

    # Owner cannot trigger diagnostic selftest; operator/auditor can
    assert client.get("/api/v1/crypto/selftest", headers=_auth(alex_tok)).status_code == 403
    st = client.get("/api/v1/crypto/selftest", headers=_auth(secops_tok))
    assert st.status_code == 200
    assert st.json()["passed"] is True
    assert all(st.json()["checks"].values())


def test_key_metadata_lifecycle_and_no_secret_exposure(client: TestClient, db_engine) -> None:
    alex_tok = DEMO_SYNTHETIC_TOKENS["sess-alex-valid"]
    secops_tok = DEMO_SYNTHETIC_TOKENS["sess-secops-valid"]
    auditor_tok = DEMO_SYNTHETIC_TOKENS["sess-auditor-valid"]

    # Owner cannot read or manage keys
    assert client.get("/api/v1/keys", headers=_auth(alex_tok)).status_code == 403

    # Auditor can read key metadata, cannot generate or transition
    keys_list = client.get("/api/v1/keys", headers=_auth(auditor_tok))
    assert keys_list.status_code == 200
    assert keys_list.json()["total"] >= 2
    assert "secret" not in keys_list.text.lower()

    assert (
        client.post(
            "/api/v1/keys/generate",
            json={"key_id": "k-aud", "purpose": "kem", "version": 2, "reason": "auditor try"},
            headers=_auth(auditor_tok),
        ).status_code
        == 403
    )

    # Operator generates ML-KEM-768 key in PREPARED state; response contains metadata only
    gen = client.post(
        "/api/v1/keys/generate",
        json={"key_id": "key-kem-v2", "purpose": "kem", "version": 2, "reason": "Stage next KEM key"},
        headers=_auth(secops_tok),
    )
    assert gen.status_code == 201
    assert gen.json()["key"]["state"] == "PREPARED"
    assert gen.json()["key"]["algorithm"] == "ML-KEM-768"

    # Lifecycle transitions: PREPARED -> ACTIVE -> ROTATING -> ACTIVE_NEW -> RETIRED -> REVOKED
    for target in ("ACTIVE", "ROTATING", "ACTIVE_NEW", "RETIRED", "REVOKED"):
        tr = client.post(
            "/api/v1/keys/key-kem-v2/transition",
            json={"target_state": target, "reason": f"Move to {target}", "confirmation": True},
            headers=_auth(secops_tok),
        )
        assert tr.status_code == 200 and tr.json()["key"]["state"] == target

    # Revoked key cannot be reactivated
    reactivate = client.post(
        "/api/v1/keys/key-kem-v2/transition",
        json={"target_state": "ACTIVE", "reason": "Illegal reactivate", "confirmation": True},
        headers=_auth(secops_tok),
    )
    assert reactivate.status_code == 409

    # Compromised seeded key is also terminal
    comp = client.post(
        "/api/v1/keys/generate",
        json={"key_id": "key-sign-v1", "purpose": "signing", "version": 1, "activate_immediately": True, "reason": "Signing key"},
        headers=_auth(secops_tok),
    )
    assert comp.status_code == 201
    client.post(
        "/api/v1/keys/key-sign-v1/transition",
        json={"target_state": "COMPROMISED", "reason": "Key compromise drill", "confirmation": True},
        headers=_auth(secops_tok),
    )
    assert (
        client.post(
            "/api/v1/keys/key-sign-v1/transition",
            json={"target_state": "ACTIVE", "reason": "Illegal reactivate", "confirmation": True},
            headers=_auth(secops_tok),
        ).status_code
        == 409
    )

    # Ensure key_metadata table never contains secret columns or key blobs
    with db_engine.connect() as conn:
        cols = {row[1] for row in conn.execute(text("PRAGMA table_info(key_metadata)")).fetchall()}
        assert "private_key" not in cols and "secret" not in cols


def test_resource_envelope_encrypt_decrypt_and_authz_isolation(client: TestClient) -> None:
    alex_tok = DEMO_SYNTHETIC_TOKENS["sess-alex-valid"]
    blair_tok = DEMO_SYNTHETIC_TOKENS["sess-blair-valid"]
    auditor_tok = DEMO_SYNTHETIC_TOKENS["sess-auditor-valid"]
    secret_text = "Q-SHIELD synthetic classified brief body \u03bb-77"

    enc = client.post(
        "/api/v1/resources/res-alex-brief/encrypt",
        json={"plaintext": secret_text},
        headers=_auth(alex_tok),
    )
    assert enc.status_code == 201
    meta = enc.json()["crypto_metadata"]
    assert meta["algorithm"] == "AES-256-GCM"
    assert meta["key_version"] == 1
    assert secret_text not in enc.text

    # Metadata endpoint returns non-secret AAD metadata only
    meta_get = client.get("/api/v1/resources/res-alex-brief/crypto-metadata", headers=_auth(alex_tok))
    assert meta_get.status_code == 200
    assert secret_text not in meta_get.text

    # Authorized owner decrypts successfully
    dec = client.post("/api/v1/resources/res-alex-brief/decrypt", headers=_auth(alex_tok))
    assert dec.status_code == 200
    assert dec.json()["decision"] == "ALLOW"
    assert dec.json()["plaintext"] == secret_text

    # Cross-user (Blair) and Auditor cannot decrypt and receive zero plaintext
    for tok in (blair_tok, auditor_tok):
        deny_dec = client.post("/api/v1/resources/res-alex-brief/decrypt", headers=_auth(tok))
        assert deny_dec.status_code == 403
        assert secret_text not in deny_dec.text


def test_vault_tamper_aad_nonce_key_revocation_and_keystore_corruption(
    client: TestClient,
    db_engine,
    keystore: LocalEncryptedKeyStore,
) -> None:
    alex_tok = DEMO_SYNTHETIC_TOKENS["sess-alex-valid"]
    secops_tok = DEMO_SYNTHETIC_TOKENS["sess-secops-valid"]
    secret_text = "Tamper-proof test synthetic plaintext"

    assert (
        client.post(
            "/api/v1/resources/res-alex-brief/encrypt",
            json={"plaintext": secret_text},
            headers=_auth(alex_tok),
        ).status_code
        == 201
    )

    factory = create_session_factory(db_engine)

    # 1. Tamper stored ciphertext -> fails closed, zero plaintext
    with factory() as db:
        orig_ct = db.execute(
            text("SELECT ciphertext_ref FROM encrypted_objects WHERE resource_id='res-alex-brief'")
        ).scalar_one()
        raw_ct = bytearray(base64.b64decode(orig_ct))
        raw_ct[0] ^= 0xFF
        bad_ct = base64.b64encode(bytes(raw_ct)).decode("ascii")
        db.execute(
            text("UPDATE encrypted_objects SET ciphertext_ref = :ct WHERE resource_id='res-alex-brief'"),
            {"ct": bad_ct},
        )
        db.commit()

    resp_bad_ct = client.post("/api/v1/resources/res-alex-brief/decrypt", headers=_auth(alex_tok))
    assert resp_bad_ct.status_code == 409 and secret_text not in resp_bad_ct.text

    # Restore ciphertext and verify decrypt works again
    with factory() as db:
        db.execute(
            text("UPDATE encrypted_objects SET ciphertext_ref = :ct WHERE resource_id='res-alex-brief'"),
            {"ct": orig_ct},
        )
        db.commit()
    assert client.post("/api/v1/resources/res-alex-brief/decrypt", headers=_auth(alex_tok)).status_code == 200

    # 2. Tamper nonce -> fails closed
    with factory() as db:
        orig_nonce = db.execute(
            text("SELECT nonce FROM encrypted_objects WHERE resource_id='res-alex-brief'")
        ).scalar_one()
        raw_n = bytearray(base64.b64decode(orig_nonce))
        raw_n[0] ^= 0x01
        db.execute(
            text("UPDATE encrypted_objects SET nonce = :n WHERE resource_id='res-alex-brief'"),
            {"n": base64.b64encode(bytes(raw_n)).decode("ascii")},
        )
        db.commit()
    resp_bad_n = client.post("/api/v1/resources/res-alex-brief/decrypt", headers=_auth(alex_tok))
    assert resp_bad_n.status_code == 409 and secret_text not in resp_bad_n.text

    with factory() as db:
        db.execute(
            text("UPDATE encrypted_objects SET nonce = :n WHERE resource_id='res-alex-brief'"),
            {"n": orig_nonce},
        )
        db.commit()

    # 3. Tamper AAD envelope metadata -> fails closed
    with factory() as db:
        orig_env = db.execute(
            text("SELECT aead_envelope FROM encrypted_objects WHERE resource_id='res-alex-brief'")
        ).scalar_one()
        tampered_env = json.loads(orig_env)
        tampered_env["owner_id"] = "user-blair"
        db.execute(
            text("UPDATE encrypted_objects SET aead_envelope = :e WHERE resource_id='res-alex-brief'"),
            {"e": json.dumps(tampered_env)},
        )
        db.commit()
    resp_bad_aad = client.post("/api/v1/resources/res-alex-brief/decrypt", headers=_auth(alex_tok))
    assert resp_bad_aad.status_code == 409 and secret_text not in resp_bad_aad.text

    with factory() as db:
        db.execute(
            text("UPDATE encrypted_objects SET aead_envelope = :e WHERE resource_id='res-alex-brief'"),
            {"e": orig_env},
        )
        db.commit()

    # 4. Revoke key-v1-active -> policy Step 8 denies decryption without leaking plaintext
    rev = client.post(
        "/api/v1/keys/key-v1-active/transition",
        json={"target_state": "REVOKED", "reason": "Suspected KEK exposure", "confirmation": True},
        headers=_auth(secops_tok),
    )
    assert rev.status_code == 200
    resp_rev = client.post("/api/v1/resources/res-alex-brief/decrypt", headers=_auth(alex_tok))
    assert resp_rev.status_code == 403 and secret_text not in resp_rev.text

    # 5. Missing/corrupt keystore fails closed cleanly on reset & tamper
    keystore.reset()
    assert not keystore.has_key("key-v1-active")
