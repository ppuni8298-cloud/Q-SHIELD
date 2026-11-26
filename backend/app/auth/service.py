"""Authentication and session lifecycle services."""

from __future__ import annotations

from datetime import timedelta
import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.audit.ledger import append_audit_event, audit_write_lock, record_audit_safe
from backend.app.auth.tokens import ensure_utc, generate_opaque_token, hash_token
from backend.app.config import settings
from backend.app.db.models import Device, RevocationTombstone, User, UserSession, utc_now


class AuthServiceError(Exception):
    """Domain error for authentication and session lifecycle failures."""

    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


def demo_login(
    db: Session,
    *,
    actor_id: str,
    device_id: str,
    peer_id: str | None = None,
    correlation_id: str = "corr-auth-login",
) -> tuple[str, UserSession, User]:
    """Authenticate synthetic identity + trusted owned device and issue hashed bearer session."""
    user = db.get(User, actor_id)
    if user is None or not user.enabled:
        record_audit_safe(
            db,
            event_type="AUTH_LOGIN_FAILED",
            event_category="IDENTITY",
            actor_id=actor_id,
            action="demo_login",
            target_type="device",
            target_id=device_id,
            outcome="DENY",
            reason_code="IDENTITY_INACTIVE_OR_UNKNOWN",
            correlation_id=correlation_id,
            source_component="auth_service",
            commit=True,
        )
        raise AuthServiceError(403, "IDENTITY_INACTIVE_OR_UNKNOWN", "Identity is missing or disabled.")

    device = db.get(Device, device_id)
    if device is None or device.owner_id != actor_id:
        record_audit_safe(
            db,
            event_type="AUTH_LOGIN_FAILED",
            event_category="IDENTITY",
            actor_id=actor_id,
            action="demo_login",
            target_type="device",
            target_id=device_id,
            outcome="DENY",
            reason_code="DEVICE_INVALID_OR_UNOWNED",
            correlation_id=correlation_id,
            source_component="auth_service",
            commit=True,
        )
        raise AuthServiceError(403, "DEVICE_INVALID_OR_UNOWNED", "Device is missing or not owned by actor.")

    tombstone = db.scalar(
        select(RevocationTombstone).where(
            RevocationTombstone.target_type == "device",
            RevocationTombstone.target_id == device_id,
        )
    )
    if tombstone is not None or device.state != "TRUSTED":
        code = f"DEVICE_NOT_TRUSTED_{device.state}"
        record_audit_safe(
            db,
            event_type="AUTH_LOGIN_FAILED",
            event_category="IDENTITY",
            actor_id=actor_id,
            action="demo_login",
            target_type="device",
            target_id=device_id,
            outcome="DENY",
            reason_code=code,
            correlation_id=correlation_id,
            source_component="auth_service",
            commit=True,
        )
        raise AuthServiceError(403, code, f"Device cannot open a session in state {device.state}.")

    now = utc_now()
    raw_token = generate_opaque_token()
    token_digest = hash_token(raw_token)
    session = UserSession(
        id=f"sess-{uuid.uuid4().hex[:16]}",
        token_hash=token_digest,
        actor_id=actor_id,
        device_id=device_id,
        peer_id=peer_id,
        auth_strength="synthetic_demo",
        version=1,
        state="ACTIVE",
        issued_at=now,
        expires_at=now + timedelta(minutes=settings.session_ttl_minutes),
    )
    device.last_seen_at = now
    with audit_write_lock():
        db.add(session)
        db.flush()
        append_audit_event(
            db,
            event_type="AUTH_LOGIN_SUCCESS",
            event_category="IDENTITY",
            actor_id=actor_id,
            action="demo_login",
            target_type="session",
            target_id=session.id,
            outcome="ALLOW",
            reason_code="AUTH_DEMO_LOGIN_OK",
            correlation_id=correlation_id,
            source_component="auth_service",
            payload={"device_id": device_id, "role": user.role, "peer_id": peer_id},
            commit=False,
        )
        db.commit()
    db.refresh(session)
    return raw_token, session, user


def resolve_active_session_by_token(db: Session, raw_token: str) -> tuple[UserSession, User, Device]:
    """Validate bearer token against hashed session, identity, expiry, and device trust."""
    token_digest = hash_token(raw_token)
    session = db.scalar(select(UserSession).where(UserSession.token_hash == token_digest))
    if session is None:
        raise AuthServiceError(401, "SESSION_NOT_FOUND", "Invalid or unknown session token.")

    now = utc_now()
    if session.revoked_at is not None or session.state == "REVOKED":
        raise AuthServiceError(401, "SESSION_REVOKED", "Session has been revoked.")

    if ensure_utc(session.expires_at) <= now or session.state == "EXPIRED":
        if session.state != "EXPIRED":
            session.state = "EXPIRED"
            db.commit()
        raise AuthServiceError(401, "SESSION_EXPIRED", "Session has expired.")

    if session.state != "ACTIVE":
        raise AuthServiceError(401, "SESSION_INACTIVE", "Session is not active.")

    user = db.get(User, session.actor_id)
    if user is None or not user.enabled:
        raise AuthServiceError(403, "IDENTITY_DISABLED", "Identity is disabled or missing.")

    device = db.get(Device, session.device_id)
    if device is None or device.owner_id != user.id:
        raise AuthServiceError(403, "DEVICE_MISMATCH", "Session device is missing or unowned.")

    if device.state != "TRUSTED":
        raise AuthServiceError(403, f"DEVICE_{device.state}", f"Bound device is {device.state}.")

    return session, user, device


def logout_session(
    db: Session,
    session: UserSession,
    reason: str = "User logout",
    *,
    correlation_id: str = "corr-logout",
) -> UserSession:
    """Revoke the current authenticated session."""
    if session.state != "REVOKED":
        with audit_write_lock():
            session.state = "REVOKED"
            session.revoked_at = utc_now()
            session.revoke_reason = reason
            append_audit_event(
                db,
                event_type="AUTH_LOGOUT",
                event_category="IDENTITY",
                actor_id=session.actor_id,
                action="logout",
                target_type="session",
                target_id=session.id,
                outcome="ALLOW",
                reason_code="SESSION_LOGOUT",
                correlation_id=correlation_id,
                source_component="auth_service",
                payload={"device_id": session.device_id},
                commit=False,
            )
            db.commit()
        db.refresh(session)
    return session


def revoke_session_by_id(
    db: Session,
    session_id: str,
    *,
    reason: str,
    confirmation: bool,
    acting_actor_id: str = "system",
    correlation_id: str = "corr-sess-revoke",
) -> UserSession:
    """Administratively revoke a session by ID with explicit reason and confirmation."""
    if not confirmation:
        raise AuthServiceError(400, "CONFIRMATION_REQUIRED", "Explicit confirmation is required.")
    target = db.get(UserSession, session_id)
    if target is None:
        raise AuthServiceError(404, "SESSION_NOT_FOUND", "Target session does not exist.")
    if target.state != "REVOKED":
        with audit_write_lock():
            target.state = "REVOKED"
            target.revoked_at = utc_now()
            target.revoke_reason = reason
            append_audit_event(
                db,
                event_type="SESSION_REVOKED",
                event_category="IDENTITY",
                actor_id=acting_actor_id,
                action="revoke_session",
                target_type="session",
                target_id=target.id,
                outcome="ALLOW",
                reason_code="SESSION_REVOKED_ADMIN",
                correlation_id=correlation_id,
                source_component="auth_service",
                payload={"subject_actor_id": target.actor_id, "reason": reason},
                commit=False,
            )
            db.commit()
        db.refresh(target)
    return target


def list_sessions(
    db: Session,
    *,
    actor_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[UserSession], int]:
    query = select(UserSession)
    count_q = select(func.count()).select_from(UserSession)
    if actor_id is not None:
        query = query.where(UserSession.actor_id == actor_id)
        count_q = count_q.where(UserSession.actor_id == actor_id)
    total = db.scalar(count_q) or 0
    items = list(db.scalars(query.order_by(UserSession.issued_at.desc()).limit(limit).offset(offset)).all())
    return items, int(total)
