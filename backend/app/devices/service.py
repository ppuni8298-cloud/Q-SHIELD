"""Device enrollment, state transitions, tombstone revocation, and replacement re-enrollment."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.audit.ledger import append_audit_event, audit_write_lock
from backend.app.db.models import Device, DeviceStateHistory, RevocationTombstone, User, UserSession, utc_now
from backend.app.schemas.devices import (
    DeviceEnrollRequest,
    DeviceOperatorActionRequest,
    DeviceReEnrollRequest,
)


class DeviceServiceError(Exception):
    """Domain error for device operations."""

    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


def list_devices(
    db: Session,
    *,
    owner_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[Device], int]:
    query = select(Device)
    count_q = select(func.count()).select_from(Device)
    if owner_id is not None:
        query = query.where(Device.owner_id == owner_id)
        count_q = count_q.where(Device.owner_id == owner_id)
    total = db.scalar(count_q) or 0
    items = list(db.scalars(query.order_by(Device.id).limit(limit).offset(offset)).all())
    return items, int(total)


def get_device_or_raise(db: Session, device_id: str) -> Device:
    device = db.get(Device, device_id)
    if device is None:
        raise DeviceServiceError(404, "DEVICE_NOT_FOUND", "Requested device does not exist.")
    return device


def get_device_history(db: Session, device_id: str) -> list[DeviceStateHistory]:
    get_device_or_raise(db, device_id)
    return list(
        db.scalars(
            select(DeviceStateHistory)
            .where(DeviceStateHistory.device_id == device_id)
            .order_by(DeviceStateHistory.state_version.asc(), DeviceStateHistory.id.asc())
        ).all()
    )


def enroll_device(
    db: Session,
    req: DeviceEnrollRequest,
    *,
    acting_user: User,
    correlation_id: str,
) -> Device:
    owner = db.get(User, req.owner_id)
    if owner is None:
        raise DeviceServiceError(404, "OWNER_NOT_FOUND", "Specified owner does not exist.")
    if not owner.enabled:
        raise DeviceServiceError(409, "OWNER_DISABLED", "Cannot enroll device for a disabled identity.")

    if acting_user.role == "owner":
        if req.owner_id != acting_user.id:
            raise DeviceServiceError(403, "FORBIDDEN_CROSS_OWNER_ENROLL", "Owners may only enroll their own devices.")
        if req.initial_state != "PENDING":
            raise DeviceServiceError(403, "FORBIDDEN_SELF_TRUST", "Owners cannot self-approve devices to TRUSTED.")

    if db.get(Device, req.id) is not None:
        raise DeviceServiceError(409, "DEVICE_ALREADY_EXISTS", "Device ID already exists.")

    fp_conflict = db.scalar(
        select(Device).where(Device.credential_fingerprint == req.credential_fingerprint)
    )
    if fp_conflict is not None:
        raise DeviceServiceError(409, "CREDENTIAL_FINGERPRINT_IN_USE", "Device credential fingerprint already registered.")

    device = Device(
        id=req.id,
        owner_id=req.owner_id,
        credential_fingerprint=req.credential_fingerprint,
        state=req.initial_state,
        state_version=1,
    )
    history = DeviceStateHistory(
        device_id=req.id,
        from_state=None,
        to_state=req.initial_state,
        state_version=1,
        changed_by=acting_user.id,
        reason=req.reason,
        correlation_id=correlation_id,
    )
    with audit_write_lock():
        db.add(device)
        db.add(history)
        append_audit_event(
            db,
            event_type="DEVICE_ENROLLED",
            event_category="DEVICE",
            actor_id=acting_user.id,
            action="enroll_device",
            target_type="device",
            target_id=device.id,
            outcome="ALLOW",
            reason_code=f"DEVICE_ENROLLED_{device.state}",
            correlation_id=correlation_id,
            source_component="device_service",
            payload={"owner_id": device.owner_id, "state": device.state, "reason": req.reason},
            commit=False,
        )
        db.commit()
    db.refresh(device)
    return device


def _require_confirmation(req: DeviceOperatorActionRequest | DeviceReEnrollRequest) -> None:
    if not req.confirmation:
        raise DeviceServiceError(400, "CONFIRMATION_REQUIRED", "Explicit confirmation is required for this action.")


def _assert_not_revoked(db: Session, device: Device) -> None:
    tombstone = db.scalar(
        select(RevocationTombstone).where(
            RevocationTombstone.target_type == "device",
            RevocationTombstone.target_id == device.id,
        )
    )
    if device.state == "REVOKED" or tombstone is not None:
        raise DeviceServiceError(
            409,
            "DEVICE_REVOKED_PERMANENT",
            "Revoked devices are permanently blocked and cannot become trusted again.",
        )


def approve_device(
    db: Session,
    device_id: str,
    req: DeviceOperatorActionRequest,
    *,
    acting_user: User,
    correlation_id: str,
) -> Device:
    _require_confirmation(req)
    device = get_device_or_raise(db, device_id)
    _assert_not_revoked(db, device)
    if device.state != "PENDING":
        raise DeviceServiceError(409, "INVALID_DEVICE_TRANSITION", f"Cannot approve device from state {device.state}.")

    prev = device.state
    device.state = "TRUSTED"
    device.state_version += 1
    device.reason = req.reason
    with audit_write_lock():
        db.add(
            DeviceStateHistory(
                device_id=device.id,
                from_state=prev,
                to_state="TRUSTED",
                state_version=device.state_version,
                changed_by=acting_user.id,
                reason=req.reason,
                correlation_id=correlation_id,
            )
        )
        append_audit_event(
            db,
            event_type="DEVICE_APPROVED",
            event_category="DEVICE",
            actor_id=acting_user.id,
            action="approve_device",
            target_type="device",
            target_id=device.id,
            outcome="ALLOW",
            reason_code="DEVICE_APPROVED_TRUSTED",
            correlation_id=correlation_id,
            source_component="device_service",
            payload={"owner_id": device.owner_id, "from_state": prev, "reason": req.reason},
            commit=False,
        )
        db.commit()
    db.refresh(device)
    return device


def suspend_device(
    db: Session,
    device_id: str,
    req: DeviceOperatorActionRequest,
    *,
    acting_user: User,
    correlation_id: str,
) -> Device:
    _require_confirmation(req)
    device = get_device_or_raise(db, device_id)
    _assert_not_revoked(db, device)
    if device.state != "TRUSTED":
        raise DeviceServiceError(409, "INVALID_DEVICE_TRANSITION", f"Only TRUSTED devices can be suspended (current: {device.state}).")

    prev = device.state
    device.state = "SUSPENDED"
    device.state_version += 1
    device.reason = req.reason
    with audit_write_lock():
        db.add(
            DeviceStateHistory(
                device_id=device.id,
                from_state=prev,
                to_state="SUSPENDED",
                state_version=device.state_version,
                changed_by=acting_user.id,
                reason=req.reason,
                correlation_id=correlation_id,
            )
        )
        append_audit_event(
            db,
            event_type="DEVICE_SUSPENDED",
            event_category="DEVICE",
            actor_id=acting_user.id,
            action="suspend_device",
            target_type="device",
            target_id=device.id,
            outcome="ALLOW",
            reason_code="DEVICE_SUSPENDED",
            correlation_id=correlation_id,
            source_component="device_service",
            payload={"owner_id": device.owner_id, "from_state": prev, "reason": req.reason},
            commit=False,
        )
        db.commit()
    db.refresh(device)
    return device


def restore_device(
    db: Session,
    device_id: str,
    req: DeviceOperatorActionRequest,
    *,
    acting_user: User,
    correlation_id: str,
) -> Device:
    _require_confirmation(req)
    device = get_device_or_raise(db, device_id)
    _assert_not_revoked(db, device)
    if device.state != "SUSPENDED":
        raise DeviceServiceError(409, "INVALID_DEVICE_TRANSITION", f"Only SUSPENDED devices can be restored (current: {device.state}).")

    prev = device.state
    device.state = "TRUSTED"
    device.state_version += 1
    device.reason = req.reason
    with audit_write_lock():
        db.add(
            DeviceStateHistory(
                device_id=device.id,
                from_state=prev,
                to_state="TRUSTED",
                state_version=device.state_version,
                changed_by=acting_user.id,
                reason=req.reason,
                correlation_id=correlation_id,
            )
        )
        append_audit_event(
            db,
            event_type="DEVICE_APPROVED",
            event_category="DEVICE",
            actor_id=acting_user.id,
            action="approve_device",
            target_type="device",
            target_id=device.id,
            outcome="ALLOW",
            reason_code="DEVICE_APPROVED_TRUSTED",
            correlation_id=correlation_id,
            source_component="device_service",
            payload={"owner_id": device.owner_id, "from_state": prev, "reason": req.reason},
            commit=False,
        )
        db.commit()
    db.refresh(device)
    return device


def _apply_device_revocation(
    db: Session,
    device: Device,
    *,
    acting_actor_id: str,
    reason: str,
    correlation_id: str,
) -> None:
    """Mutate device -> REVOKED, write durable tombstone, and revoke bound sessions inside transaction."""
    now = utc_now()
    if device.state != "REVOKED":
        prev = device.state
        device.state = "REVOKED"
        device.state_version += 1
        device.revoked_at = now
        device.reason = reason
        db.add(
            DeviceStateHistory(
                device_id=device.id,
                from_state=prev,
                to_state="REVOKED",
                state_version=device.state_version,
                changed_by=acting_actor_id,
                reason=reason,
                correlation_id=correlation_id,
            )
        )

    existing_tombstone = db.scalar(
        select(RevocationTombstone).where(
            RevocationTombstone.target_type == "device",
            RevocationTombstone.target_id == device.id,
        )
    )
    if existing_tombstone is None:
        db.add(
            RevocationTombstone(
                target_type="device",
                target_id=device.id,
                revocation_epoch=1,
                reason=reason,
            )
        )

    active_sessions = list(
        db.scalars(
            select(UserSession).where(
                UserSession.device_id == device.id,
                UserSession.state == "ACTIVE",
            )
        ).all()
    )
    for sess in active_sessions:
        sess.state = "REVOKED"
        sess.revoked_at = now
        sess.revoke_reason = f"Device revoked: {reason}"


def revoke_device(
    db: Session,
    device_id: str,
    req: DeviceOperatorActionRequest,
    *,
    acting_user: User,
    correlation_id: str,
) -> Device:
    _require_confirmation(req)
    device = get_device_or_raise(db, device_id)
    with audit_write_lock():
        _apply_device_revocation(
            db,
            device,
            acting_actor_id=acting_user.id,
            reason=req.reason,
            correlation_id=correlation_id,
        )
        append_audit_event(
            db,
            event_type="DEVICE_REVOKED",
            event_category="DEVICE",
            actor_id=acting_user.id,
            action="revoke_device",
            target_type="device",
            target_id=device.id,
            outcome="ALLOW",
            reason_code="DEVICE_REVOKED_PERMANENT",
            correlation_id=correlation_id,
            source_component="device_service",
            payload={"owner_id": device.owner_id, "reason": req.reason},
            commit=False,
        )
        db.commit()
    db.refresh(device)
    return device


def re_enroll_replacement_device(
    db: Session,
    req: DeviceReEnrollRequest,
    *,
    acting_user: User,
    correlation_id: str,
) -> tuple[Device, Device]:
    """Revoke lost device (preserving tombstone) and enroll a distinct replacement device."""
    _require_confirmation(req)
    old_device = get_device_or_raise(db, req.old_device_id)
    if acting_user.role == "owner" and old_device.owner_id != acting_user.id:
        raise DeviceServiceError(403, "FORBIDDEN_CROSS_OWNER_REENROLL", "Owners may only re-enroll their own lost devices.")

    if req.new_device_id == req.old_device_id:
        raise DeviceServiceError(409, "SAME_DEVICE_ID_FORBIDDEN", "Replacement device must have a distinct device ID.")
    if db.get(Device, req.new_device_id) is not None:
        raise DeviceServiceError(409, "DEVICE_ALREADY_EXISTS", "Replacement device ID already exists.")
    if req.new_credential_fingerprint == old_device.credential_fingerprint:
        raise DeviceServiceError(409, "REVOKED_CREDENTIAL_REUSE_FORBIDDEN", "Cannot reuse revoked device credential fingerprint.")

    fp_conflict = db.scalar(
        select(Device).where(Device.credential_fingerprint == req.new_credential_fingerprint)
    )
    if fp_conflict is not None:
        raise DeviceServiceError(409, "CREDENTIAL_FINGERPRINT_IN_USE", "Replacement credential fingerprint already registered.")

    with audit_write_lock():
        _apply_device_revocation(
            db,
            old_device,
            acting_actor_id=acting_user.id,
            reason=f"Lost-device replacement: {req.reason}",
            correlation_id=correlation_id,
        )

        # Operator/admin recovery can issue TRUSTED directly; owner self-request starts PENDING for verification.
        replacement_state = "TRUSTED" if acting_user.role in ("security_operator", "admin") else "PENDING"
        new_device = Device(
            id=req.new_device_id,
            owner_id=old_device.owner_id,
            credential_fingerprint=req.new_credential_fingerprint,
            state=replacement_state,
            state_version=1,
            reason=f"Replacement for {old_device.id}: {req.reason}",
        )
        old_device.replaced_by_device_id = new_device.id
        db.add(new_device)
        db.add(
            DeviceStateHistory(
                device_id=new_device.id,
                from_state=None,
                to_state=replacement_state,
                state_version=1,
                changed_by=acting_user.id,
                reason=f"Replacement for {old_device.id}: {req.reason}",
                correlation_id=correlation_id,
            )
        )
        append_audit_event(
            db,
            event_type="DEVICE_RE_ENROLLED",
            event_category="DEVICE",
            actor_id=acting_user.id,
            action="re_enroll_device",
            target_type="device",
            target_id=new_device.id,
            outcome="ALLOW",
            reason_code=f"DEVICE_RE_ENROLLED_{replacement_state}",
            correlation_id=correlation_id,
            source_component="device_service",
            payload={
                "old_device_id": old_device.id,
                "new_device_id": new_device.id,
                "owner_id": old_device.owner_id,
                "reason": req.reason,
            },
            commit=False,
        )
        db.commit()
    db.refresh(old_device)
    db.refresh(new_device)
    return old_device, new_device
