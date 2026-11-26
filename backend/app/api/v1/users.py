"""Identity and RBAC endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.app.auth.dependencies import AuthContext, get_auth_context, require_permission
from backend.app.db.session import get_db
from backend.app.identity.roles import ROLE_PERMISSION_DEFINITIONS, role_has_permission
from backend.app.identity.service import (
    IdentityServiceError,
    create_user,
    get_user_detail,
    list_role_permissions,
    list_users,
    update_user,
)
from backend.app.schemas.common import PaginatedResponse
from backend.app.schemas.identity import (
    RolePermissionOut,
    RoleSummaryOut,
    UserCreateRequest,
    UserDetailResponse,
    UserOut,
    UserUpdateRequest,
)

router = APIRouter(tags=["identity"])


@router.get("/users", response_model=PaginatedResponse[UserOut])
def get_users(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    ctx: AuthContext = Depends(require_permission("identity:read")),
    db: Session = Depends(get_db),
) -> PaginatedResponse[UserOut]:
    items, total = list_users(db, limit=limit, offset=offset)
    return PaginatedResponse[UserOut](
        items=[UserOut.model_validate(u) for u in items],
        total=total,
        limit=limit,
        offset=offset,
        correlation_id=ctx.correlation_id,
    )


@router.get("/users/{user_id}", response_model=UserDetailResponse)
def get_user(
    user_id: str,
    ctx: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> UserDetailResponse:
    if user_id != ctx.user.id and not role_has_permission(ctx.user.role, "identity:read"):
        raise HTTPException(
            status_code=403,
            detail={
                "code": "FORBIDDEN_CROSS_IDENTITY_READ",
                "message": "Insufficient permissions to view another identity.",
                "correlation_id": ctx.correlation_id,
            },
        )
    try:
        user, device_ids, active_sessions = get_user_detail(db, user_id)
    except IdentityServiceError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": exc.message, "correlation_id": ctx.correlation_id},
        ) from None
    return UserDetailResponse(
        user=UserOut.model_validate(user),
        device_ids=device_ids,
        active_session_count=active_sessions,
        correlation_id=ctx.correlation_id,
    )


@router.post("/users", response_model=UserOut, status_code=201)
def post_user(
    payload: UserCreateRequest,
    ctx: AuthContext = Depends(require_permission("identity:manage")),
    db: Session = Depends(get_db),
) -> UserOut:
    try:
        user = create_user(db, payload, acting_actor_id=ctx.user.id, correlation_id=ctx.correlation_id)
    except IdentityServiceError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": exc.message, "correlation_id": ctx.correlation_id},
        ) from None
    return UserOut.model_validate(user)


@router.patch("/users/{user_id}", response_model=UserOut)
def patch_user(
    user_id: str,
    payload: UserUpdateRequest,
    ctx: AuthContext = Depends(require_permission("identity:manage")),
    db: Session = Depends(get_db),
) -> UserOut:
    try:
        user = update_user(db, user_id, payload, acting_actor_id=ctx.user.id, correlation_id=ctx.correlation_id)
    except IdentityServiceError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": exc.message, "correlation_id": ctx.correlation_id},
        ) from None
    return UserOut.model_validate(user)


@router.get("/roles", response_model=list[RoleSummaryOut])
def get_roles(
    ctx: AuthContext = Depends(require_permission("role:read")),
    db: Session = Depends(get_db),
) -> list[RoleSummaryOut]:
    rows = list_role_permissions(db)
    grouped: dict[str, list[RolePermissionOut]] = {r: [] for r in ROLE_PERMISSION_DEFINITIONS}
    for row in rows:
        grouped.setdefault(row.role, []).append(RolePermissionOut.model_validate(row))
    return [RoleSummaryOut(role=role_name, permissions=perms) for role_name, perms in grouped.items()]  # type: ignore[arg-type]
