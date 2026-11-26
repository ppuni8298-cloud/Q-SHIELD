"""Independent tests for the ordered 10-step Zero-Trust Policy Engine."""

from __future__ import annotations

from sqlalchemy import select

from backend.app.db.models import AccessRequest
from backend.app.policy.engine import ZeroTrustPolicyEngine
from backend.app.policy.interfaces import KeyValidityChecker
from backend.app.schemas.policy import PolicyEvalRequest


class _BrokenKeyChecker(KeyValidityChecker):
    def is_key_version_valid(self, db, key_version: int):
        raise RuntimeError("Simulated crypto metadata outage")


def test_all_ten_policy_steps_in_exact_order(db_session) -> None:
    engine = ZeroTrustPolicyEngine()

    # Step 1: Invalid / malformed request
    r1 = engine.evaluate(
        db_session,
        PolicyEvalRequest(
            actor_id="../etc/passwd",
            session_id="sess-alex-valid",
            device_id="dev-alex-trusted",
            resource_id="res-alex-brief",
            action="read",
        ),
    )
    assert r1.decision == "DENY" and r1.failed_step == 1 and r1.reason_code == "DENY_INVALID_REQUEST"

    # Step 2a: Unknown identity
    r2a = engine.evaluate(
        db_session,
        PolicyEvalRequest(
            actor_id="user-nobody",
            session_id="sess-alex-valid",
            device_id="dev-alex-trusted",
            resource_id="res-alex-brief",
            action="read",
        ),
    )
    assert r2a.decision == "DENY" and r2a.failed_step == 2 and r2a.reason_code == "DENY_UNKNOWN_IDENTITY"

    # Step 2b: Disabled identity
    r2b = engine.evaluate(
        db_session,
        PolicyEvalRequest(
            actor_id="user-disabled",
            session_id="sess-alex-valid",
            device_id="dev-alex-trusted",
            resource_id="res-alex-brief",
            action="read",
        ),
    )
    assert r2b.decision == "DENY" and r2b.failed_step == 2 and r2b.reason_code == "DENY_IDENTITY_DISABLED"

    # Step 3a: Session not found
    r3a = engine.evaluate(
        db_session,
        PolicyEvalRequest(
            actor_id="user-alex",
            session_id="sess-missing",
            device_id="dev-alex-trusted",
            resource_id="res-alex-brief",
            action="read",
        ),
    )
    assert r3a.decision == "DENY" and r3a.failed_step == 3 and r3a.reason_code == "DENY_SESSION_NOT_FOUND"

    # Step 3b: Session identity mismatch (Alex presenting Blair's session)
    r3b = engine.evaluate(
        db_session,
        PolicyEvalRequest(
            actor_id="user-alex",
            session_id="sess-blair-valid",
            device_id="dev-blair-trusted",
            resource_id="res-alex-brief",
            action="read",
        ),
    )
    assert r3b.decision == "DENY" and r3b.failed_step == 3 and r3b.reason_code == "DENY_SESSION_IDENTITY_MISMATCH"

    # Step 4a: Revoked session
    r4a = engine.evaluate(
        db_session,
        PolicyEvalRequest(
            actor_id="user-alex",
            session_id="sess-alex-revoked",
            device_id="dev-alex-trusted",
            resource_id="res-alex-brief",
            action="read",
        ),
    )
    assert r4a.decision == "DENY" and r4a.failed_step == 4 and r4a.reason_code == "DENY_SESSION_REVOKED"

    # Step 4b: Expired session
    r4b = engine.evaluate(
        db_session,
        PolicyEvalRequest(
            actor_id="user-alex",
            session_id="sess-alex-expired",
            device_id="dev-alex-trusted",
            resource_id="res-alex-brief",
            action="read",
        ),
    )
    assert r4b.decision == "DENY" and r4b.failed_step == 4 and r4b.reason_code == "DENY_SESSION_EXPIRED"

    # Step 5a: Session-device mismatch (valid session for trusted device, presenting different device)
    r5a = engine.evaluate(
        db_session,
        PolicyEvalRequest(
            actor_id="user-alex",
            session_id="sess-alex-valid",
            device_id="dev-alex-revoked",
            resource_id="res-alex-brief",
            action="read",
        ),
    )
    assert r5a.decision == "DENY" and r5a.failed_step == 5 and r5a.reason_code == "DENY_SESSION_DEVICE_MISMATCH"

    # Step 6a: Role lacks requested action (owner requesting write/admin)
    r6a = engine.evaluate(
        db_session,
        PolicyEvalRequest(
            actor_id="user-alex",
            session_id="sess-alex-valid",
            device_id="dev-alex-trusted",
            resource_id="res-alex-brief",
            action="write",
        ),
    )
    assert r6a.decision == "DENY" and r6a.failed_step == 6 and r6a.reason_code == "DENY_ROLE_PERMISSION_DENIED"

    # Step 6b: Wrong owner / no explicit permission
    r6b = engine.evaluate(
        db_session,
        PolicyEvalRequest(
            actor_id="user-alex",
            session_id="sess-alex-valid",
            device_id="dev-alex-trusted",
            resource_id="res-blair-ledger",
            action="read",
        ),
    )
    assert r6b.decision == "DENY" and r6b.failed_step == 6 and r6b.reason_code == "DENY_RESOURCE_PERMISSION_DENIED"

    # Step 7a: Resource not found
    r7a = engine.evaluate(
        db_session,
        PolicyEvalRequest(
            actor_id="user-alex",
            session_id="sess-alex-valid",
            device_id="dev-alex-trusted",
            resource_id="res-nonexistent",
            action="read",
        ),
    )
    assert r7a.decision == "DENY" and r7a.failed_step == 7 and r7a.reason_code == "DENY_RESOURCE_NOT_FOUND"

    # Step 7b: Resource disabled
    r7b = engine.evaluate(
        db_session,
        PolicyEvalRequest(
            actor_id="user-alex",
            session_id="sess-alex-valid",
            device_id="dev-alex-trusted",
            resource_id="res-disabled-archive",
            action="read",
        ),
    )
    assert r7b.decision == "DENY" and r7b.failed_step == 7 and r7b.reason_code == "DENY_RESOURCE_DISABLED"

    # Step 8: Revoked key version
    r8 = engine.evaluate(
        db_session,
        PolicyEvalRequest(
            actor_id="user-alex",
            session_id="sess-alex-valid",
            device_id="dev-alex-trusted",
            resource_id="res-revoked-key-doc",
            action="read",
        ),
    )
    assert r8.decision == "DENY" and r8.failed_step == 8 and r8.reason_code == "DENY_KEY_REVOKED"

    # Step 9: Active blocking incident
    r9 = engine.evaluate(
        db_session,
        PolicyEvalRequest(
            actor_id="user-alex",
            session_id="sess-alex-valid",
            device_id="dev-alex-trusted",
            resource_id="res-incident-locked",
            action="read",
        ),
    )
    assert r9.decision == "DENY" and r9.failed_step == 9 and r9.reason_code == "DENY_ACTIVE_INCIDENT"

    # Step 10a: Authorized owner ALLOW
    r10 = engine.evaluate(
        db_session,
        PolicyEvalRequest(
            actor_id="user-alex",
            session_id="sess-alex-valid",
            device_id="dev-alex-trusted",
            resource_id="res-alex-brief",
            action="read",
        ),
    )
    assert r10.decision == "ALLOW" and r10.failed_step is None and r10.reason_code == "ALLOW_AUTHORIZED"
    assert [c.step for c in r10.checks] == list(range(1, 11))

    # Step 10b: Explicit ResourcePermission ALLOW (Alex reading res-shared-policy)
    r_shared = engine.evaluate(
        db_session,
        PolicyEvalRequest(
            actor_id="user-alex",
            session_id="sess-alex-valid",
            device_id="dev-alex-trusted",
            resource_id="res-shared-policy",
            action="read",
        ),
    )
    assert r_shared.decision == "ALLOW"

    # Decisions persisted in access_requests
    persisted = db_session.scalar(select(AccessRequest).where(AccessRequest.request_id == r10.request_id))
    assert persisted is not None and persisted.decision == "ALLOW"


def test_step_precedence_and_fail_closed_on_internal_error(db_session) -> None:
    engine = ZeroTrustPolicyEngine()
    # Disabled identity (Step 2) + missing session (Step 3) + bad resource (Step 7) must fail at Step 2
    res = engine.evaluate(
        db_session,
        PolicyEvalRequest(
            actor_id="user-disabled",
            session_id="nonexistent",
            device_id="nonexistent",
            resource_id="nonexistent",
            action="read",
        ),
    )
    assert res.decision == "DENY" and res.failed_step == 2

    # Internal checker exception must fail closed with DENY_INTERNAL_ERROR
    broken = ZeroTrustPolicyEngine(key_checker=_BrokenKeyChecker())
    res_err = broken.evaluate(
        db_session,
        PolicyEvalRequest(
            actor_id="user-alex",
            session_id="sess-alex-valid",
            device_id="dev-alex-trusted",
            resource_id="res-alex-brief",
            action="read",
        ),
    )
    assert res_err.decision == "DENY" and res_err.reason_code == "DENY_INTERNAL_ERROR"
