"""Identity and RBAC management services."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.audit.ledger import append_audit_event, audit_write_lock, record_audit_safe
from backend.app.db.models import Device, RevocationTombstone, RolePermission, User, UserSession, utc_now
from backend.app.identity.roles import VALID_ROLES
from backend.app.schemas.identity import UserCreateRequest, UserUpdateRequest


class IdentityServiceError(Exception):
    """Domain error for identity operations with explicit HTTP status and error code."""

    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


def list_users(db: Session, *, limit: int = 50, offset: int = 0) -> tuple[list[User], int]:
    total = db.scalar(select(func.count()).select_from(User)) or 0
    items = list(db.scalars(select(User).order_by(User.id).limit(limit).offset(offset)).all())
    return items, int(total)


def get_user_detail(db: Session, user_id: str) -> tuple[User, list[str], int]:
    user = db.get(User, user_id)
    if user is None:
        raise IdentityServiceError(404, "USER_NOT_FOUND", "Requested user does not exist.")
    device_ids = list(
        db.scalars(select(Device.id).where(Device.owner_id == user_id).order_by(Device.id)).all()
    )
    active_sessions = (
        db.scalar(
            select(func.count())
            .select_from(UserSession)
            .where(UserSession.actor_id == user_id, UserSession.state == "ACTIVE")
        )
        or 0
    )
    return user, device_ids, int(active_sessions)


def create_user(
    db: Session,
    req: UserCreateRequest,
    *,
    acting_actor_id: str,
    correlation_id: str = "corr-identity-create",
) -> User:
    if not req.confirmation:
        raise IdentityServiceError(400, "CONFIRMATION_REQUIRED", "Explicit confirmation is required.")
    if req.role not in VALID_ROLES:
        raise IdentityServiceError(400, "INVALID_ROLE", "Unsupported role requested.")
    if db.get(User, req.id) is not None:
        raise IdentityServiceError(409, "USER_ALREADY_EXISTS", "User ID already exists.")

    user = User(
        id=req.id,
        display_name=req.display_name,
        role=req.role,
        enabled=req.enabled,
        is_synthetic=True,
    )
    with audit_write_lock():
        db.add(user)
        db.flush()
        append_audit_event(
            db,
            event_type="IDENTITY_CREATED",
            event_category="IDENTITY",
            actor_id=acting_actor_id,
            action="create_user",
            target_type="user",
            target_id=user.id,
            outcome="ALLOW",
            reason_code="IDENTITY_CREATED_OK",
            correlation_id=correlation_id,
            source_component="identity_service",
            payload={"role": user.role, "enabled": user.enabled, "reason": req.reason},
            commit=False,
        )
        db.commit()
    db.refresh(user)
    return user


def update_user(
    db: Session,
    target_user_id: str,
    req: UserUpdateRequest,
    *,
    acting_actor_id: str,
    correlation_id: str = "corr-identity-update",
) -> User:
    if not req.confirmation:
        raise IdentityServiceError(400, "CONFIRMATION_REQUIRED", "Explicit confirmation is required.")

    target = db.get(User, target_user_id)
    if target is None:
        raise IdentityServiceError(404, "USER_NOT_FOUND", "Target user does not exist.")

    # Never permit self-role modification or self-elevation.
    if req.role is not None and target_user_id == acting_actor_id and req.role != target.role:
        record_audit_safe(
            db,
            event_type="ROLE_ESCALATION_DENIED",
            event_category="AUTHORIZATION",
            actor_id=acting_actor_id,
            action="update_user_role",
            target_type="user",
            target_id=target_user_id,
            outcome="DENY",
            reason_code="SELF_ESCALATION_FORBIDDEN",
            correlation_id=correlation_id,
            source_component="identity_service",
            payload={"attempted_role": req.role},
            commit=True,
        )
        raise IdentityServiceError(
            403, "SELF_ESCALATION_FORBIDDEN", "Actors cannot modify their own role."
        )

    prev_role = target.role
    prev_enabled = target.enabled
    if req.display_name is not None:
        target.display_name = req.display_name
    if req.role is not None:
        if req.role not in VALID_ROLES:
            raise IdentityServiceError(400, "INVALID_ROLE", "Unsupported role requested.")
        target.role = req.role
    if req.enabled is not None:
        target.enabled = req.enabled
        if not req.enabled:
            # Disabling an identity revokes active sessions and writes an actor tombstone.
            now = utc_now()
            active_sessions = list(
                db.scalars(
                    select(UserSession).where(
                        UserSession.actor_id == target_user_id,
                        UserSession.state == "ACTIVE",
                    )
                ).all()
            )
            for sess in active_sessions:
                sess.state = "REVOKED"
                sess.revoked_at = now
                sess.revoke_reason = f"Identity disabled: {req.reason}"

            existing_tombstone = db.scalar(
                select(RevocationTombstone).where(
                    RevocationTombstone.target_type == "actor",
                    RevocationTombstone.target_id == target_user_id,
                )
            )
            if existing_tombstone is None:
                db.add(
                    RevocationTombstone(
                        target_type="actor",
                        target_id=target_user_id,
                        revocation_epoch=1,
                        reason=req.reason,
                    )
                )
            else:
                existing_tombstone.revocation_epoch += 1
                existing_tombstone.reason = req.reason
        else:
            # Re-enabling an actor clears actor-level tombstone only (revoked devices remain revoked).
            tombstone = db.scalar(
                select(RevocationTombstone).where(
                    RevocationTombstone.target_type == "actor",
                    RevocationTombstone.target_id == target_user_id,
                )
            )
            if tombstone is not None:
                db.delete(tombstone)

    with audit_write_lock():
        if req.role is not None and target.role != prev_role:
            append_audit_event(
                db,
                event_type="ROLE_CHANGED",
                event_category="IDENTITY",
                actor_id=acting_actor_id,
                action="change_role",
                target_type="user",
                target_id=target_user_id,
                outcome="ALLOW",
                reason_code="ROLE_UPDATED",
                correlation_id=correlation_id,
                source_component="identity_service",
                payload={"from_role": prev_role, "to_role": target.role, "reason": req.reason},
                commit=False,
            )
        if req.enabled is not None and target.enabled != prev_enabled:
            append_audit_event(
                db,
                event_type="IDENTITY_REVOKED" if not target.enabled else "IDENTITY_RESTORED",
                event_category="IDENTITY",
                actor_id=acting_actor_id,
                action="disable_identity" if not target.enabled else "enable_identity",
                target_type="user",
                target_id=target_user_id,
                outcome="ALLOW",
                reason_code="IDENTITY_DISABLED" if not target.enabled else "IDENTITY_ENABLED",
                correlation_id=correlation_id,
                source_component="identity_service",
                payload={"enabled": target.enabled, "reason": req.reason},
                commit=False,
            )
        if (req.role is None or target.role == prev_role) and (req.enabled is None or target.enabled == prev_enabled):
            append_audit_event(
                db,
                event_type="IDENTITY_UPDATED",
                event_category="IDENTITY",
                actor_id=acting_actor_id,
                action="update_identity",
                target_type="user",
                target_id=target_user_id,
                outcome="ALLOW",
                reason_code="IDENTITY_METADATA_UPDATED",
                correlation_id=correlation_id,
                source_component="identity_service",
                payload={"reason": req.reason},
                commit=False,
            )
        db.commit()
    db.refresh(target)
    return target


def list_role_permissions(db: Session) -> list[RolePermission]:
    return list(
        db.scalars(select(RolePermission).order_by(RolePermission.role, RolePermission.action)).all()
    )
