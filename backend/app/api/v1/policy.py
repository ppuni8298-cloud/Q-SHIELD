"""Zero-trust 10-step policy evaluation endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.auth.dependencies import AuthContext, get_auth_context
from backend.app.db.session import get_db
from backend.app.identity.roles import role_has_permission
from backend.app.policy.engine import ZeroTrustPolicyEngine
from backend.app.schemas.policy import PolicyEvalRequest, PolicyEvalResponse

router = APIRouter(prefix="/policy", tags=["policy"])
_policy_engine = ZeroTrustPolicyEngine()


@router.post("/evaluate", response_model=PolicyEvalResponse)
def post_evaluate_policy(
    payload: PolicyEvalRequest,
    ctx: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> PolicyEvalResponse:
    """Execute deterministic 10-step zero-trust evaluation with RBAC scoping."""
    if role_has_permission(ctx.user.role, "policy:evaluate"):
        pass
    elif role_has_permission(ctx.user.role, "policy:evaluate_own"):
        if payload.actor_id != ctx.user.id:
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "FORBIDDEN_CROSS_ACTOR_POLICY_EVAL",
                    "message": "Owners may only evaluate policy requests for their own actor_id.",
                    "correlation_id": ctx.correlation_id,
                },
            )
    else:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "FORBIDDEN_ROLE_PERMISSION",
                "message": "Role lacks policy evaluation permission.",
                "correlation_id": ctx.correlation_id,
            },
        )

    return _policy_engine.evaluate(db, payload, correlation_id=ctx.correlation_id)
