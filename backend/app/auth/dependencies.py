"""FastAPI authentication, RBAC, and correlation ID dependencies."""

from __future__ import annotations

from dataclasses import dataclass
import uuid

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from backend.app.audit.ledger import record_audit_safe
from backend.app.auth.service import AuthServiceError, resolve_active_session_by_token
from backend.app.db.models import Device, User, UserSession
from backend.app.db.session import get_db
from backend.app.identity.roles import role_has_permission


@dataclass(frozen=True)
class AuthContext:
    """Verified server-side authentication context for the current HTTP request."""

    session: UserSession
    user: User
    device: Device
    correlation_id: str


def get_correlation_id(request: Request) -> str:
    """Return correlation ID attached by middleware or generate one safely."""
    existing = getattr(request.state, "correlation_id", None)
    if existing:
        return str(existing)
    corr = f"corr-{uuid.uuid4().hex[:16]}"
    request.state.correlation_id = corr
    return corr


def get_auth_context(
    request: Request,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> AuthContext:
    """Require valid Bearer token bound to active user, active session, and trusted device."""
    corr_id = get_correlation_id(request)
    if not authorization or not authorization.startswith("Bearer "):
        record_audit_safe(
            db,
            event_type="AUTH_TOKEN_MISSING",
            event_category="IDENTITY",
            actor_id="anonymous",
            action="authenticate",
            target_type="session",
            target_id="bearer",
            outcome="DENY",
            reason_code="AUTH_REQUIRED",
            correlation_id=corr_id,
            source_component="auth_dependencies",
            payload={"path": request.url.path},
            commit=True,
        )
        raise HTTPException(
            status_code=401,
            detail={
                "code": "AUTH_REQUIRED",
                "message": "Valid Bearer token is required.",
                "correlation_id": corr_id,
            },
        )
    raw_token = authorization[len("Bearer ") :].strip()
    if not raw_token:
        record_audit_safe(
            db,
            event_type="AUTH_TOKEN_EMPTY",
            event_category="IDENTITY",
            actor_id="anonymous",
            action="authenticate",
            target_type="session",
            target_id="bearer",
            outcome="DENY",
            reason_code="AUTH_REQUIRED",
            correlation_id=corr_id,
            source_component="auth_dependencies",
            payload={"path": request.url.path},
            commit=True,
        )
        raise HTTPException(
            status_code=401,
            detail={
                "code": "AUTH_REQUIRED",
                "message": "Bearer token must not be empty.",
                "correlation_id": corr_id,
            },
        )
    try:
        session, user, device = resolve_active_session_by_token(db, raw_token)
    except AuthServiceError as exc:
        record_audit_safe(
            db,
            event_type="AUTH_SESSION_INVALID",
            event_category="IDENTITY",
            actor_id="unknown",
            action="authenticate",
            target_type="session",
            target_id="token",
            outcome="DENY",
            reason_code=exc.code,
            correlation_id=corr_id,
            source_component="auth_dependencies",
            payload={"path": request.url.path},
            commit=True,
        )
        raise HTTPException(
            status_code=exc.status_code,
            detail={
                "code": exc.code,
                "message": exc.message,
                "correlation_id": corr_id,
            },
        ) from None
    return AuthContext(session=session, user=user, device=device, correlation_id=corr_id)


def require_permission(permission: str):
    """Dependency enforcing backend RBAC permission on every protected endpoint."""

    def _checker(
        ctx: AuthContext = Depends(get_auth_context),
        db: Session = Depends(get_db),
    ) -> AuthContext:
        if not role_has_permission(ctx.user.role, permission):
            record_audit_safe(
                db,
                event_type="AUTHORIZATION_DENIED",
                event_category="AUTHORIZATION",
                actor_id=ctx.user.id,
                action=f"require:{permission}",
                target_type="rbac_permission",
                target_id=permission,
                outcome="DENY",
                reason_code="FORBIDDEN_ROLE_PERMISSION",
                correlation_id=ctx.correlation_id,
                source_component="rbac_guard",
                payload={"role": ctx.user.role, "permission": permission},
                commit=True,
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "FORBIDDEN_ROLE_PERMISSION",
                    "message": f"Role '{ctx.user.role}' lacks required permission '{permission}'.",
                    "correlation_id": ctx.correlation_id,
                },
            )
        return ctx

    return _checker
