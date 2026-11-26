"""Device lifecycle API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.app.auth.dependencies import AuthContext, get_auth_context, require_permission
from backend.app.db.session import get_db
from backend.app.devices.service import (
    DeviceServiceError,
    approve_device,
    enroll_device,
    get_device_history,
    get_device_or_raise,
    list_devices,
    re_enroll_replacement_device,
    restore_device,
    revoke_device,
    suspend_device,
)
from backend.app.identity.roles import role_has_permission
from backend.app.schemas.common import PaginatedResponse
from backend.app.schemas.devices import (
    DeviceActionResponse,
    DeviceEnrollRequest,
    DeviceHistoryOut,
    DeviceOperatorActionRequest,
    DeviceOut,
    DeviceReEnrollRequest,
    DeviceReEnrollResponse,
)

router = APIRouter(prefix="/devices", tags=["devices"])


def _handle_device_error(exc: DeviceServiceError, corr_id: str) -> HTTPException:
    return HTTPException(
        status_code=exc.status_code,
        detail={"code": exc.code, "message": exc.message, "correlation_id": corr_id},
    )


@router.get("", response_model=PaginatedResponse[DeviceOut])
def get_devices(
    owner_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    ctx: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> PaginatedResponse[DeviceOut]:
    if role_has_permission(ctx.user.role, "device:read"):
        scoped_owner = owner_id
    else:
        if owner_id is not None and owner_id != ctx.user.id:
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "FORBIDDEN_CROSS_OWNER_DEVICES",
                    "message": "Owners may only list their own devices.",
                    "correlation_id": ctx.correlation_id,
                },
            )
        scoped_owner = ctx.user.id

    items, total = list_devices(db, owner_id=scoped_owner, limit=limit, offset=offset)
    return PaginatedResponse[DeviceOut](
        items=[DeviceOut.model_validate(d) for d in items],
        total=total,
        limit=limit,
        offset=offset,
        correlation_id=ctx.correlation_id,
    )


@router.get("/{device_id}", response_model=DeviceOut)
def get_device(
    device_id: str,
    ctx: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> DeviceOut:
    try:
        device = get_device_or_raise(db, device_id)
    except DeviceServiceError as exc:
        raise _handle_device_error(exc, ctx.correlation_id) from None
    if device.owner_id != ctx.user.id and not role_has_permission(ctx.user.role, "device:read"):
        raise HTTPException(
            status_code=403,
            detail={
                "code": "FORBIDDEN_DEVICE_READ",
                "message": "Insufficient permissions to view this device.",
                "correlation_id": ctx.correlation_id,
            },
        )
    return DeviceOut.model_validate(device)


@router.get("/{device_id}/history", response_model=list[DeviceHistoryOut])
def get_history(
    device_id: str,
    ctx: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> list[DeviceHistoryOut]:
    try:
        device = get_device_or_raise(db, device_id)
        if device.owner_id != ctx.user.id and not role_has_permission(ctx.user.role, "device:read"):
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "FORBIDDEN_DEVICE_HISTORY",
                    "message": "Insufficient permissions to view this device history.",
                    "correlation_id": ctx.correlation_id,
                },
            )
        rows = get_device_history(db, device_id)
    except DeviceServiceError as exc:
        raise _handle_device_error(exc, ctx.correlation_id) from None
    return [DeviceHistoryOut.model_validate(r) for r in rows]


@router.post("/enroll", response_model=DeviceActionResponse, status_code=201)
def post_enroll(
    payload: DeviceEnrollRequest,
    ctx: AuthContext = Depends(require_permission("device:enroll")),
    db: Session = Depends(get_db),
) -> DeviceActionResponse:
    try:
        device = enroll_device(db, payload, acting_user=ctx.user, correlation_id=ctx.correlation_id)
    except DeviceServiceError as exc:
        raise _handle_device_error(exc, ctx.correlation_id) from None
    return DeviceActionResponse(device=DeviceOut.model_validate(device), correlation_id=ctx.correlation_id)


@router.post("/{device_id}/approve", response_model=DeviceActionResponse)
def post_approve(
    device_id: str,
    payload: DeviceOperatorActionRequest,
    ctx: AuthContext = Depends(require_permission("device:approve")),
    db: Session = Depends(get_db),
) -> DeviceActionResponse:
    try:
        device = approve_device(db, device_id, payload, acting_user=ctx.user, correlation_id=ctx.correlation_id)
    except DeviceServiceError as exc:
        raise _handle_device_error(exc, ctx.correlation_id) from None
    return DeviceActionResponse(device=DeviceOut.model_validate(device), correlation_id=ctx.correlation_id)


@router.post("/{device_id}/suspend", response_model=DeviceActionResponse)
def post_suspend(
    device_id: str,
    payload: DeviceOperatorActionRequest,
    ctx: AuthContext = Depends(require_permission("device:suspend")),
    db: Session = Depends(get_db),
) -> DeviceActionResponse:
    try:
        device = suspend_device(db, device_id, payload, acting_user=ctx.user, correlation_id=ctx.correlation_id)
    except DeviceServiceError as exc:
        raise _handle_device_error(exc, ctx.correlation_id) from None
    return DeviceActionResponse(device=DeviceOut.model_validate(device), correlation_id=ctx.correlation_id)


@router.post("/{device_id}/restore", response_model=DeviceActionResponse)
def post_restore(
    device_id: str,
    payload: DeviceOperatorActionRequest,
    ctx: AuthContext = Depends(require_permission("device:restore")),
    db: Session = Depends(get_db),
) -> DeviceActionResponse:
    try:
        device = restore_device(db, device_id, payload, acting_user=ctx.user, correlation_id=ctx.correlation_id)
    except DeviceServiceError as exc:
        raise _handle_device_error(exc, ctx.correlation_id) from None
    return DeviceActionResponse(device=DeviceOut.model_validate(device), correlation_id=ctx.correlation_id)


@router.post("/{device_id}/revoke", response_model=DeviceActionResponse)
def post_revoke(
    device_id: str,
    payload: DeviceOperatorActionRequest,
    ctx: AuthContext = Depends(require_permission("device:revoke")),
    db: Session = Depends(get_db),
) -> DeviceActionResponse:
    try:
        device = revoke_device(db, device_id, payload, acting_user=ctx.user, correlation_id=ctx.correlation_id)
    except DeviceServiceError as exc:
        raise _handle_device_error(exc, ctx.correlation_id) from None
    return DeviceActionResponse(device=DeviceOut.model_validate(device), correlation_id=ctx.correlation_id)


@router.post("/re-enroll", response_model=DeviceReEnrollResponse, status_code=201)
def post_re_enroll(
    payload: DeviceReEnrollRequest,
    ctx: AuthContext = Depends(require_permission("device:re_enroll")),
    db: Session = Depends(get_db),
) -> DeviceReEnrollResponse:
    try:
        old_dev, new_dev = re_enroll_replacement_device(
            db, payload, acting_user=ctx.user, correlation_id=ctx.correlation_id
        )
    except DeviceServiceError as exc:
        raise _handle_device_error(exc, ctx.correlation_id) from None
    return DeviceReEnrollResponse(
        revoked_device=DeviceOut.model_validate(old_dev),
        replacement_device=DeviceOut.model_validate(new_dev),
        correlation_id=ctx.correlation_id,
    )
