"""Synthetic demo authentication and session endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from backend.app.audit.ledger import record_audit_safe
from backend.app.auth.dependencies import (
    AuthContext,
    get_auth_context,
    get_correlation_id,
    require_permission,
)
from backend.app.auth.rate_limit import login_rate_limiter
from backend.app.auth.service import (
    AuthServiceError,
    demo_login,
    list_sessions,
    logout_session,
    revoke_session_by_id,
)
from backend.app.config import settings
from backend.app.db.session import get_db
from backend.app.identity.roles import ROLE_PERMISSION_DEFINITIONS
from backend.app.schemas.auth import (
    AuthMeResponse,
    DemoLoginRequest,
    DemoLoginResponse,
    SessionActionResponse,
    SessionOut,
    SessionRevokeRequest,
)
from backend.app.schemas.common import PaginatedResponse

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/demo-login", response_model=DemoLoginResponse)
def post_demo_login(
    payload: DemoLoginRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> DemoLoginResponse:
    """Authenticate synthetic seeded identity and trusted owned device."""
    corr_id = get_correlation_id(request)
    if not settings.demo_mode:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "DEMO_MODE_DISABLED",
                "message": "Synthetic demo login is disabled.",
                "correlation_id": corr_id,
            },
        )
    client_host = request.client.host if request.client else "local"
    rl_key = f"{client_host}:{payload.actor_id}"
    limited, fail_count = login_rate_limiter.is_limited(rl_key)
    if limited:
        record_audit_safe(
            db,
            event_type="AUTH_RATE_LIMITED",
            event_category="IDENTITY",
            actor_id=payload.actor_id,
            action="demo_login",
            target_type="rate_limit",
            target_id=payload.actor_id,
            outcome="DENY",
            reason_code="AUTH_RATE_LIMITED",
            correlation_id=corr_id,
            source_component="auth_rate_limiter",
            payload={"client_host": client_host, "recent_failures": fail_count},
            commit=True,
        )
        raise HTTPException(
            status_code=429,
            detail={
                "code": "AUTH_RATE_LIMITED",
                "message": "Too many failed authentication attempts; retry after cooldown window.",
                "correlation_id": corr_id,
            },
        )
    try:
        raw_token, session, user = demo_login(
            db,
            actor_id=payload.actor_id,
            device_id=payload.device_id,
            peer_id=payload.peer_id,
            correlation_id=corr_id,
        )
    except AuthServiceError as exc:
        login_rate_limiter.record_failure(rl_key)
        raise HTTPException(
            status_code=exc.status_code,
            detail={
                "code": exc.code,
                "message": exc.message,
                "correlation_id": corr_id,
            },
        ) from None
    login_rate_limiter.reset_key(rl_key)

    return DemoLoginResponse(
        synthetic_mode=True,
        access_token=raw_token,
        session=SessionOut.model_validate(session),
        role=user.role,
        correlation_id=corr_id,
    )


@router.post("/logout", response_model=SessionActionResponse)
def post_logout(
    ctx: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> SessionActionResponse:
    """Revoke the caller's current session."""
    revoked = logout_session(db, ctx.session, correlation_id=ctx.correlation_id)
    return SessionActionResponse(
        session=SessionOut.model_validate(revoked),
        correlation_id=ctx.correlation_id,
    )


@router.get("/me", response_model=AuthMeResponse)
def get_me(ctx: AuthContext = Depends(get_auth_context)) -> AuthMeResponse:
    """Return authenticated synthetic actor, active session, and role permissions."""
    perms = [action for action, _scope, _desc in ROLE_PERMISSION_DEFINITIONS.get(ctx.user.role, [])]
    return AuthMeResponse(
        synthetic_mode=ctx.user.is_synthetic,
        actor_id=ctx.user.id,
        display_name=ctx.user.display_name,
        role=ctx.user.role,
        enabled=ctx.user.enabled,
        session=SessionOut.model_validate(ctx.session),
        permissions=perms,
        correlation_id=ctx.correlation_id,
    )


@router.get("/sessions", response_model=PaginatedResponse[SessionOut])
def get_sessions(
    actor_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    ctx: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> PaginatedResponse[SessionOut]:
    """List sessions; owners are restricted to their own sessions."""
    from backend.app.identity.roles import role_has_permission

    if role_has_permission(ctx.user.role, "session:read"):
        scoped_actor = actor_id
    elif role_has_permission(ctx.user.role, "session:read_own"):
        if actor_id is not None and actor_id != ctx.user.id:
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "FORBIDDEN_CROSS_ACTOR_SESSIONS",
                    "message": "Owners may only inspect their own sessions.",
                    "correlation_id": ctx.correlation_id,
                },
            )
        scoped_actor = ctx.user.id
    else:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "FORBIDDEN_ROLE_PERMISSION",
                "message": "Role lacks session read permission.",
                "correlation_id": ctx.correlation_id,
            },
        )

    items, total = list_sessions(db, actor_id=scoped_actor, limit=limit, offset=offset)
    return PaginatedResponse[SessionOut](
        items=[SessionOut.model_validate(s) for s in items],
        total=total,
        limit=limit,
        offset=offset,
        correlation_id=ctx.correlation_id,
    )


@router.post("/sessions/{session_id}/revoke", response_model=SessionActionResponse)
def post_revoke_session(
    session_id: str,
    payload: SessionRevokeRequest,
    ctx: AuthContext = Depends(require_permission("session:revoke")),
    db: Session = Depends(get_db),
) -> SessionActionResponse:
    """Administratively revoke a session (operator/admin only, requires reason + confirmation)."""
    try:
        revoked = revoke_session_by_id(
            db,
            session_id,
            reason=payload.reason,
            confirmation=payload.confirmation,
            acting_actor_id=ctx.user.id,
            correlation_id=ctx.correlation_id,
        )
    except AuthServiceError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={
                "code": exc.code,
                "message": exc.message,
                "correlation_id": ctx.correlation_id,
            },
        ) from None
    return SessionActionResponse(
        session=SessionOut.model_validate(revoked),
        correlation_id=ctx.correlation_id,
    )
