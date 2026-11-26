"""Black-box FastAPI /api/v1 tests for auth, RBAC, devices, resources, concurrency, and safe errors."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from backend.app.services.seed import DEMO_SYNTHETIC_TOKENS


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_health_ready_and_openapi_contract(client: TestClient) -> None:
    h = client.get("/api/v1/health")
    assert h.status_code == 200
    assert h.json()["demo_mode"] is True
    assert h.json()["offline_mode"] is True
    assert "X-Correlation-Id" in h.headers

    r = client.get("/api/v1/ready")
    assert r.status_code == 200
    assert r.json()["ready"] is True

    schema = client.get("/api/v1/openapi.json")
    assert schema.status_code == 200
    paths = schema.json()["paths"]
    for expected in (
        "/api/v1/auth/demo-login",
        "/api/v1/auth/logout",
        "/api/v1/devices/enroll",
        "/api/v1/devices/{device_id}/revoke",
        "/api/v1/devices/re-enroll",
        "/api/v1/resources/{resource_id}/access",
        "/api/v1/policy/evaluate",
        "/api/v1/simulation/reset",
    ):
        assert expected in paths


def test_demo_login_session_lifecycle_expiry_and_logout(client: TestClient) -> None:
    # Valid login with trusted owned device
    login = client.post("/api/v1/auth/demo-login", json={"actor_id": "user-alex", "device_id": "dev-alex-trusted"})
    assert login.status_code == 200
    body = login.json()
    assert body["synthetic_mode"] is True
    token = body["access_token"]

    me = client.get("/api/v1/auth/me", headers=_auth(token))
    assert me.status_code == 200 and me.json()["actor_id"] == "user-alex"

    # Logout invalidates the token immediately
    out = client.post("/api/v1/auth/logout", headers=_auth(token))
    assert out.status_code == 200 and out.json()["session"]["state"] == "REVOKED"
    me_after = client.get("/api/v1/auth/me", headers=_auth(token))
    assert me_after.status_code == 401

    # Expired and revoked seeded tokens rejected
    assert client.get("/api/v1/auth/me", headers=_auth(DEMO_SYNTHETIC_TOKENS["sess-alex-expired"])).status_code == 401
    assert client.get("/api/v1/auth/me", headers=_auth(DEMO_SYNTHETIC_TOKENS["sess-alex-revoked"])).status_code == 401

    # Non-trusted or unowned devices cannot log in
    for bad_actor, bad_dev in (
        ("user-alex", "dev-alex-pending"),
        ("user-alex", "dev-alex-suspended"),
        ("user-alex", "dev-alex-revoked"),
        ("user-alex", "dev-blair-trusted"),
        ("user-disabled", "dev-alex-trusted"),
    ):
        resp = client.post("/api/v1/auth/demo-login", json={"actor_id": bad_actor, "device_id": bad_dev})
        assert resp.status_code == 403


def test_rbac_least_privilege_and_no_self_escalation(client: TestClient) -> None:
    alex_tok = DEMO_SYNTHETIC_TOKENS["sess-alex-valid"]
    auditor_tok = DEMO_SYNTHETIC_TOKENS["sess-auditor-valid"]
    secops_tok = DEMO_SYNTHETIC_TOKENS["sess-secops-valid"]
    admin_tok = DEMO_SYNTHETIC_TOKENS["sess-admin-valid"]

    # Unauthenticated calls fail closed
    assert client.get("/api/v1/users").status_code == 401
    assert client.get("/api/v1/devices").status_code == 401

    # Owner cannot list all users, cannot approve/revoke devices, cannot reset demo, cannot view Blair's device
    assert client.get("/api/v1/users", headers=_auth(alex_tok)).status_code == 403
    assert client.get("/api/v1/devices/dev-blair-trusted", headers=_auth(alex_tok)).status_code == 403
    assert (
        client.post(
            "/api/v1/devices/dev-alex-pending/approve",
            json={"reason": "self approve", "confirmation": True},
            headers=_auth(alex_tok),
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/v1/simulation/reset",
            json={"reason": "owner reset", "confirmation": True},
            headers=_auth(alex_tok),
        ).status_code
        == 403
    )

    # Auditor can read metadata/roles/history, CANNOT mutate anything or read Alex's protected resource
    assert client.get("/api/v1/users", headers=_auth(auditor_tok)).status_code == 200
    assert client.get("/api/v1/roles", headers=_auth(auditor_tok)).status_code == 200
    assert (
        client.post(
            "/api/v1/devices/dev-alex-trusted/revoke",
            json={"reason": "auditor try", "confirmation": True},
            headers=_auth(auditor_tok),
        ).status_code
        == 403
    )
    assert client.post("/api/v1/resources/res-alex-brief/access", json={"action": "read"}, headers=_auth(auditor_tok)).status_code == 403

    # Security operator cannot manage users or reset simulation, CAN suspend/restore/revoke devices (with confirmation)
    assert (
        client.post(
            "/api/v1/users",
            json={"id": "user-x", "display_name": "X", "role": "admin", "reason": "try", "confirmation": True},
            headers=_auth(secops_tok),
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/v1/devices/dev-alex-trusted/revoke",
            json={"reason": "missing confirm", "confirmation": False},
            headers=_auth(secops_tok),
        ).status_code
        == 400
    )

    # Admin cannot modify own role (no self-escalation/mutation)
    self_patch = client.patch(
        "/api/v1/users/user-admin",
        json={"role": "owner", "reason": "self change", "confirmation": True},
        headers=_auth(admin_tok),
    )
    assert self_patch.status_code == 403


def test_device_lifecycle_permanent_revocation_and_replacement_reenroll(client: TestClient) -> None:
    alex_tok = DEMO_SYNTHETIC_TOKENS["sess-alex-valid"]
    secops_tok = DEMO_SYNTHETIC_TOKENS["sess-secops-valid"]
    blair_tok = DEMO_SYNTHETIC_TOKENS["sess-blair-valid"]

    # Revoked device cannot be approved or restored
    assert (
        client.post(
            "/api/v1/devices/dev-alex-revoked/restore",
            json={"reason": "illegal unrevoke", "confirmation": True},
            headers=_auth(secops_tok),
        ).status_code
        == 409
    )
    assert (
        client.post(
            "/api/v1/devices/dev-alex-revoked/approve",
            json={"reason": "illegal approve", "confirmation": True},
            headers=_auth(secops_tok),
        ).status_code
        == 409
    )

    # Suspend and restore suspended device works cleanly
    susp = client.post(
        "/api/v1/devices/dev-alex-trusted/suspend",
        json={"reason": "temp maintenance", "confirmation": True},
        headers=_auth(secops_tok),
    )
    assert susp.status_code == 200 and susp.json()["device"]["state"] == "SUSPENDED"
    # While suspended, Alex's existing session is rejected
    assert client.post("/api/v1/resources/res-alex-brief/access", json={"action": "read"}, headers=_auth(alex_tok)).status_code == 403

    rest = client.post(
        "/api/v1/devices/dev-alex-trusted/restore",
        json={"reason": "verified clean", "confirmation": True},
        headers=_auth(secops_tok),
    )
    assert rest.status_code == 200 and rest.json()["device"]["state"] == "TRUSTED"

    # Re-enroll replacement for dev-alex-trusted (lost-device scenario)
    reenroll = client.post(
        "/api/v1/devices/re-enroll",
        json={
            "old_device_id": "dev-alex-trusted",
            "new_device_id": "dev-alex-replacement-99",
            "new_credential_fingerprint": "fp-synth-alex-replacement-99",
            "reason": "Laptop stolen at airport",
            "confirmation": True,
        },
        headers=_auth(secops_tok),
    )
    assert reenroll.status_code == 201
    assert reenroll.json()["revoked_device"]["state"] == "REVOKED"
    assert reenroll.json()["replacement_device"]["state"] == "TRUSTED"

    # Old device session is revoked and old device cannot log in; replacement CAN log in and access resource; Blair unaffected
    assert client.post("/api/v1/resources/res-alex-brief/access", json={"action": "read"}, headers=_auth(alex_tok)).status_code == 401
    assert client.post("/api/v1/auth/demo-login", json={"actor_id": "user-alex", "device_id": "dev-alex-trusted"}).status_code == 403

    new_login = client.post(
        "/api/v1/auth/demo-login",
        json={"actor_id": "user-alex", "device_id": "dev-alex-replacement-99"},
    )
    assert new_login.status_code == 200
    new_tok = new_login.json()["access_token"]
    ok_read = client.post("/api/v1/resources/res-alex-brief/access", json={"action": "read"}, headers=_auth(new_tok))
    assert ok_read.status_code == 200 and ok_read.json()["decision"] == "ALLOW"

    blair_read = client.post("/api/v1/resources/res-blair-ledger/access", json={"action": "read"}, headers=_auth(blair_tok))
    assert blair_read.status_code == 200 and blair_read.json()["decision"] == "ALLOW"

    hist = client.get("/api/v1/devices/dev-alex-trusted/history", headers=_auth(secops_tok))
    assert hist.status_code == 200 and len(hist.json()) >= 4


def test_resource_access_no_leakage_and_malformed_input_and_reset(client: TestClient) -> None:
    alex_tok = DEMO_SYNTHETIC_TOKENS["sess-alex-valid"]
    admin_tok = DEMO_SYNTHETIC_TOKENS["sess-admin-valid"]

    # Alex denied Blair's ledger without any metadata leakage
    deny_resp = client.post("/api/v1/resources/res-blair-ledger/access", json={"action": "read"}, headers=_auth(alex_tok))
    assert deny_resp.status_code == 403
    assert "Blair Synthetic Ledger" not in deny_resp.text
    assert "error" in deny_resp.json()

    # Malformed extra field rejected cleanly (422, no traceback)
    bad_payload = client.post(
        "/api/v1/auth/demo-login",
        json={"actor_id": "user-alex", "device_id": "dev-alex-trusted", "unexpected": 1},
    )
    assert bad_payload.status_code == 422
    assert bad_payload.json()["error"]["code"] == "VALIDATION_ERROR"
    assert "Traceback" not in bad_payload.text

    # Admin disables Alex -> Alex's valid token immediately fails
    disable = client.patch(
        "/api/v1/users/user-alex",
        json={"enabled": False, "reason": "Suspected compromise", "confirmation": True},
        headers=_auth(admin_tok),
    )
    assert disable.status_code == 200 and disable.json()["enabled"] is False
    assert client.get("/api/v1/auth/me", headers=_auth(alex_tok)).status_code == 401

    # Admin resets demo database -> Alex is active again
    reset = client.post(
        "/api/v1/simulation/reset",
        json={"reason": "Restore baseline after test", "confirmation": True},
        headers=_auth(admin_tok),
    )
    assert reset.status_code == 200 and reset.json()["reset_completed"] is True
    assert client.get("/api/v1/auth/me", headers=_auth(alex_tok)).status_code == 200


def test_concurrent_resource_access_and_policy_requests(client: TestClient) -> None:
    alex_tok = DEMO_SYNTHETIC_TOKENS["sess-alex-valid"]

    def _call_access(idx: int) -> int:
        res_id = "res-alex-brief" if idx % 2 == 0 else "res-blair-ledger"
        resp = client.post(f"/api/v1/resources/{res_id}/access", json={"action": "read"}, headers=_auth(alex_tok))
        return resp.status_code

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(_call_access, range(18)))

    assert results == [200 if i % 2 == 0 else 403 for i in range(18)]
