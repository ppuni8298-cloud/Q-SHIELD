"""Ordered 10-step deterministic Zero-Trust Policy Evaluation Engine.

Evaluates requests in exact order specified by Master Build Prompt Section 5:
1. Parse and validate
2. Identity active
3. Authenticated session valid and bound to identity
4. Session not expired/revoked
5. Device enrolled, owned by actor, trusted and not revoked
6. Actor has permission for resource and action
7. Resource exists and is not disabled
8. Key version active and not revoked/compromised (via KeyValidityChecker)
9. Incident/policy denies? (via IncidentDenialChecker)
10. Decision ALLOW or DENY, structured reason code and correlation ID

Fails closed on any missing entity, invalid state, or unexpected error.
"""

from __future__ import annotations

import json
import re
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.audit.ledger import append_audit_event, audit_write_lock
from backend.app.auth.tokens import ensure_utc
from backend.app.db.models import (
    AccessRequest,
    Device,
    Resource,
    ResourcePermission,
    RevocationTombstone,
    User,
    UserSession,
    utc_now,
)
from backend.app.identity.roles import role_has_permission
from backend.app.policy.interfaces import (
    IncidentDenialChecker,
    KeyValidityChecker,
    MetadataKeyValidityChecker,
    TableIncidentDenialChecker,
)
from backend.app.schemas.policy import PolicyEvalRequest, PolicyEvalResponse, PolicyStepResult

_OPAQUE_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_ACTION_PERMISSION_MAP: dict[str, str] = {
    "read": "resource:read",
    "write": "resource:write",
    "create": "resource:create",
    "read_meta": "resource:read_meta",
}


class ZeroTrustPolicyEngine:
    """Deterministic, fail-closed 10-step policy evaluator."""

    def __init__(
        self,
        key_checker: KeyValidityChecker | None = None,
        incident_checker: IncidentDenialChecker | None = None,
    ) -> None:
        self._key_checker = key_checker or MetadataKeyValidityChecker()
        self._incident_checker = incident_checker or TableIncidentDenialChecker()

    def evaluate(
        self,
        db: Session,
        request: PolicyEvalRequest,
        *,
        correlation_id: str | None = None,
        record_decision: bool = True,
    ) -> PolicyEvalResponse:
        corr_id = correlation_id or f"corr-{uuid.uuid4().hex[:16]}"
        req_id = f"req-{uuid.uuid4().hex[:16]}"
        checks: list[PolicyStepResult] = []

        def finish_deny(step: int, name: str, code: str, detail: str) -> PolicyEvalResponse:
            checks.append(PolicyStepResult(step=step, name=name, passed=False, reason_code=code, detail=detail))
            checks.append(
                PolicyStepResult(
                    step=10,
                    name="Final policy decision",
                    passed=False,
                    reason_code=code,
                    detail=f"DENY at step {step}: {code}",
                )
            )
            resp = PolicyEvalResponse(
                decision="DENY",
                reason_code=code,
                correlation_id=corr_id,
                request_id=req_id,
                failed_step=step,
                checks=checks,
            )
            if record_decision:
                self._persist_access_request(db, request, resp)
            return resp

        try:
            # Step 1: Parse and validate
            if not (
                _OPAQUE_ID_RE.match(request.actor_id)
                and _OPAQUE_ID_RE.match(request.session_id)
                and _OPAQUE_ID_RE.match(request.device_id)
                and _OPAQUE_ID_RE.match(request.resource_id)
                and _OPAQUE_ID_RE.match(request.action)
            ):
                return finish_deny(
                    1,
                    "Parse and validate request",
                    "DENY_INVALID_REQUEST",
                    "Request identifiers or action failed opaque string validation.",
                )
            checks.append(
                PolicyStepResult(
                    step=1,
                    name="Parse and validate request",
                    passed=True,
                    reason_code="OK_VALID_REQUEST",
                    detail="All request fields passed validation.",
                )
            )

            # Step 2: Identity active
            user = db.get(User, request.actor_id)
            if user is None:
                return finish_deny(2, "Identity active", "DENY_UNKNOWN_IDENTITY", "Actor identity not found.")
            actor_tombstone = db.scalar(
                select(RevocationTombstone).where(
                    RevocationTombstone.target_type == "actor",
                    RevocationTombstone.target_id == user.id,
                )
            )
            if not user.enabled or actor_tombstone is not None:
                return finish_deny(2, "Identity active", "DENY_IDENTITY_DISABLED", "Actor identity is disabled or revoked.")
            checks.append(
                PolicyStepResult(
                    step=2,
                    name="Identity active",
                    passed=True,
                    reason_code="OK_IDENTITY_ACTIVE",
                    detail=f"Identity '{user.id}' ({user.role}) is active.",
                )
            )

            # Step 3: Authenticated session valid and bound to identity
            session = db.get(UserSession, request.session_id)
            if session is None:
                return finish_deny(
                    3, "Session valid and identity-bound", "DENY_SESSION_NOT_FOUND", "Session does not exist."
                )
            if session.actor_id != user.id:
                return finish_deny(
                    3,
                    "Session valid and identity-bound",
                    "DENY_SESSION_IDENTITY_MISMATCH",
                    "Session is bound to a different identity.",
                )
            checks.append(
                PolicyStepResult(
                    step=3,
                    name="Session valid and identity-bound",
                    passed=True,
                    reason_code="OK_SESSION_BOUND",
                    detail=f"Session '{session.id}' is bound to '{user.id}'.",
                )
            )

            # Step 4: Session not expired or revoked
            now = utc_now()
            if session.revoked_at is not None or session.state == "REVOKED":
                return finish_deny(
                    4, "Session not expired or revoked", "DENY_SESSION_REVOKED", "Session has been revoked."
                )
            if ensure_utc(session.expires_at) <= now or session.state == "EXPIRED":
                return finish_deny(
                    4, "Session not expired or revoked", "DENY_SESSION_EXPIRED", "Session has expired."
                )
            if session.state != "ACTIVE":
                return finish_deny(
                    4, "Session not expired or revoked", "DENY_SESSION_INACTIVE", f"Session state is {session.state}."
                )
            checks.append(
                PolicyStepResult(
                    step=4,
                    name="Session not expired or revoked",
                    passed=True,
                    reason_code="OK_SESSION_ACTIVE",
                    detail="Session is active and within validity window.",
                )
            )

            # Step 5: Device enrolled, owned by actor, trusted and not revoked
            if session.device_id != request.device_id:
                return finish_deny(
                    5,
                    "Device enrolled, owned, trusted",
                    "DENY_SESSION_DEVICE_MISMATCH",
                    "Session is bound to a different device.",
                )
            device = db.get(Device, request.device_id)
            if device is None:
                return finish_deny(
                    5, "Device enrolled, owned, trusted", "DENY_DEVICE_NOT_FOUND", "Device is not enrolled."
                )
            if device.owner_id != user.id:
                return finish_deny(
                    5,
                    "Device enrolled, owned, trusted",
                    "DENY_DEVICE_OWNERSHIP_MISMATCH",
                    "Device is owned by a different identity.",
                )
            dev_tombstone = db.scalar(
                select(RevocationTombstone).where(
                    RevocationTombstone.target_type == "device",
                    RevocationTombstone.target_id == device.id,
                )
            )
            if dev_tombstone is not None or device.state == "REVOKED":
                return finish_deny(
                    5, "Device enrolled, owned, trusted", "DENY_DEVICE_REVOKED", "Device is permanently revoked."
                )
            if device.state == "SUSPENDED":
                return finish_deny(
                    5, "Device enrolled, owned, trusted", "DENY_DEVICE_SUSPENDED", "Device is suspended."
                )
            if device.state == "PENDING":
                return finish_deny(
                    5, "Device enrolled, owned, trusted", "DENY_DEVICE_PENDING", "Device enrollment is pending approval."
                )
            if device.state != "TRUSTED":
                return finish_deny(
                    5, "Device enrolled, owned, trusted", "DENY_DEVICE_UNTRUSTED", f"Device state is {device.state}."
                )
            checks.append(
                PolicyStepResult(
                    step=5,
                    name="Device enrolled, owned, trusted",
                    passed=True,
                    reason_code="OK_DEVICE_TRUSTED",
                    detail=f"Device '{device.id}' is owned by '{user.id}' and TRUSTED.",
                )
            )

            # Step 6: Actor has permission for resource and action
            required_perm = _ACTION_PERMISSION_MAP.get(request.action)
            if required_perm is None or not role_has_permission(user.role, required_perm):
                return finish_deny(
                    6,
                    "Actor has resource/action permission",
                    "DENY_ROLE_PERMISSION_DENIED",
                    f"Role '{user.role}' is not permitted to perform '{request.action}'.",
                )

            resource = db.get(Resource, request.resource_id)
            if resource is not None:
                is_owner = resource.owner_id == user.id
                explicit_perm = db.scalar(
                    select(ResourcePermission).where(
                        ResourcePermission.resource_id == resource.id,
                        ResourcePermission.permission == request.action,
                        (
                            ((ResourcePermission.subject_type == "actor") & (ResourcePermission.subject_id == user.id))
                            | ((ResourcePermission.subject_type == "role") & (ResourcePermission.subject_id == user.role))
                        ),
                    )
                )
                if not is_owner and explicit_perm is None:
                    return finish_deny(
                        6,
                        "Actor has resource/action permission",
                        "DENY_RESOURCE_PERMISSION_DENIED",
                        "Actor is neither resource owner nor explicitly granted permission.",
                    )
            checks.append(
                PolicyStepResult(
                    step=6,
                    name="Actor has resource/action permission",
                    passed=True,
                    reason_code="OK_PERMISSION_GRANTED",
                    detail=f"Actor '{user.id}' satisfies role and resource permission checks for '{request.action}'.",
                )
            )

            # Step 7: Resource exists and is not disabled
            if resource is None:
                return finish_deny(
                    7,
                    "Resource exists and enabled",
                    "DENY_RESOURCE_NOT_FOUND",
                    "Requested resource does not exist.",
                )
            if resource.state != "ACTIVE":
                return finish_deny(
                    7,
                    "Resource exists and enabled",
                    "DENY_RESOURCE_DISABLED",
                    f"Resource state is {resource.state}.",
                )
            checks.append(
                PolicyStepResult(
                    step=7,
                    name="Resource exists and enabled",
                    passed=True,
                    reason_code="OK_RESOURCE_ACTIVE",
                    detail=f"Resource '{resource.id}' exists and is ACTIVE.",
                )
            )

            # Step 8: Key version active and not revoked/compromised
            key_ok, key_code, key_detail = self._key_checker.is_key_version_valid(db, resource.key_version)
            if not key_ok:
                return finish_deny(8, "Key version active and valid", key_code, key_detail)
            checks.append(
                PolicyStepResult(
                    step=8,
                    name="Key version active and valid",
                    passed=True,
                    reason_code=key_code,
                    detail=key_detail,
                )
            )

            # Step 9: Incident / policy denial check
            inc_ok, inc_code, inc_detail = self._incident_checker.check_blocking_incident(
                db,
                actor_id=user.id,
                device_id=device.id,
                resource_id=resource.id,
            )
            if not inc_ok:
                return finish_deny(9, "Incident and policy denial check", inc_code, inc_detail)
            checks.append(
                PolicyStepResult(
                    step=9,
                    name="Incident and policy denial check",
                    passed=True,
                    reason_code=inc_code,
                    detail=inc_detail,
                )
            )

            # Step 10: Decision ALLOW
            checks.append(
                PolicyStepResult(
                    step=10,
                    name="Final policy decision",
                    passed=True,
                    reason_code="ALLOW_AUTHORIZED",
                    detail="All zero-trust checks passed.",
                )
            )
            resp = PolicyEvalResponse(
                decision="ALLOW",
                reason_code="ALLOW_AUTHORIZED",
                correlation_id=corr_id,
                request_id=req_id,
                failed_step=None,
                checks=checks,
            )
            if record_decision:
                self._persist_access_request(db, request, resp)
            return resp

        except Exception:
            # Fail closed on any unexpected internal failure without leaking details.
            try:
                db.rollback()
            except Exception:
                pass
            return PolicyEvalResponse(
                decision="DENY",
                reason_code="DENY_INTERNAL_ERROR",
                correlation_id=corr_id,
                request_id=req_id,
                failed_step=10,
                checks=checks
                + [
                    PolicyStepResult(
                        step=10,
                        name="Final policy decision",
                        passed=False,
                        reason_code="DENY_INTERNAL_ERROR",
                        detail="Internal policy evaluation error; failed closed.",
                    )
                ],
            )

    @staticmethod
    def _persist_access_request(
        db: Session,
        request: PolicyEvalRequest,
        resp: PolicyEvalResponse,
    ) -> None:
        try:
            with audit_write_lock():
                db.add(
                    AccessRequest(
                        request_id=resp.request_id,
                        actor_id=request.actor_id[:128],
                        resource_id=request.resource_id[:128],
                        device_id=request.device_id[:128] or None,
                        action=request.action[:64],
                        decision=resp.decision,
                        reason=resp.reason_code,
                        node="control-plane",
                        correlation_id=resp.correlation_id,
                        steps_json=json.dumps([c.model_dump() for c in resp.checks]),
                    )
                )
                append_audit_event(
                    db,
                    event_type="ACCESS_GRANTED" if resp.decision == "ALLOW" else "ACCESS_DENIED",
                    event_category="PROTECTED_ACCESS",
                    actor_id=request.actor_id[:128] or "anonymous",
                    action=request.action[:64],
                    target_type="resource",
                    target_id=request.resource_id[:128] or "unknown",
                    outcome=resp.decision,
                    reason_code=resp.reason_code,
                    correlation_id=resp.correlation_id,
                    source_component="policy_engine",
                    payload={"request_id": resp.request_id, "failed_step": resp.failed_step},
                    commit=False,
                )
                db.commit()
        except Exception:
            db.rollback()
            if resp.decision == "ALLOW":
                raise
