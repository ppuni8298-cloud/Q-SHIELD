"""Phase 5 API routes: Key Rotation, In-Flight Transfers, Crash Recovery & Backups."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.app.auth.dependencies import AuthContext, require_permission
from backend.app.backups.service import (
    BackupError,
    create_backup,
    get_backup_dir,
    list_backups,
    restore_backup,
    verify_backup,
)
from backend.app.config import settings
from backend.app.crypto.keystore import LocalEncryptedKeyStore, get_keystore
from backend.app.db.session import get_db
from backend.app.keys.rotation import (
    CRASH_INJECTION_POINTS,
    RotationError,
    SimulatedCrashError,
    advance_rotation,
    complete_in_flight_transfer,
    execute_rotation,
    get_rotation_or_raise,
    list_rotations,
    start_in_flight_transfer,
)
from backend.app.recovery.manager import recover_rotations
from backend.app.schemas.rotation_backup import (
    BackupCreateRequest,
    BackupManifestOut,
    BackupRestoreOut,
    BackupRestoreRequest,
    BackupVerificationOut,
    CrashInjectionConfigRequest,
    RecoveryOutcomeOut,
    RecoveryRunRequest,
    RecoveryRunResponse,
    RotationActionResponse,
    RotationAdvanceRequest,
    RotationOperationOut,
    RotationStartRequest,
    TransferCompleteResponse,
    TransferOut,
    TransferStartRequest,
)

router = APIRouter(tags=["rotation-recovery-backups"])


def _err(status_code: int, code: str, message: str, corr_id: str) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={"code": code, "message": message, "correlation_id": corr_id},
    )


@router.post("/keys/rotate", response_model=RotationActionResponse, status_code=201)
def post_rotate_key(
    payload: RotationStartRequest,
    ctx: AuthContext = Depends(require_permission("key:manage")),
    db: Session = Depends(get_db),
    keystore: LocalEncryptedKeyStore = Depends(get_keystore),
    backup_dir: Path = Depends(get_backup_dir),
) -> RotationActionResponse:
    try:
        op = execute_rotation(
            db,
            keystore,
            purpose=payload.purpose,
            actor_id=ctx.user.id,
            reason=payload.reason,
            grace_policy=payload.grace_policy,
            new_key_id=payload.new_key_id,
            correlation_id=ctx.correlation_id,
            auto_advance=payload.auto_advance,
            crash_at=payload.crash_at,
            backup_dir=backup_dir,
        )
    except SimulatedCrashError as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "SIMULATED_CRASH_INJECTED",
                "crash_point": exc.crash_point,
                "operation_id": exc.operation_id,
                "phase": exc.phase,
                "message": str(exc),
                "correlation_id": ctx.correlation_id,
            },
        ) from None
    except RotationError as exc:
        raise _err(exc.status_code, exc.code, exc.message, ctx.correlation_id) from None
    return RotationActionResponse(operation=RotationOperationOut.model_validate(op), correlation_id=ctx.correlation_id)


@router.get("/keys/rotations", response_model=list[RotationOperationOut])
def get_rotations(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    ctx: AuthContext = Depends(require_permission("key:read")),
    db: Session = Depends(get_db),
) -> list[RotationOperationOut]:
    ops = list_rotations(db, limit=limit, offset=offset)
    return [RotationOperationOut.model_validate(o) for o in ops]


@router.get("/keys/rotations/{operation_id}", response_model=RotationActionResponse)
def get_rotation(
    operation_id: str,
    ctx: AuthContext = Depends(require_permission("key:read")),
    db: Session = Depends(get_db),
) -> RotationActionResponse:
    try:
        op = get_rotation_or_raise(db, operation_id)
    except RotationError as exc:
        raise _err(exc.status_code, exc.code, exc.message, ctx.correlation_id) from None
    return RotationActionResponse(operation=RotationOperationOut.model_validate(op), correlation_id=ctx.correlation_id)


@router.post("/keys/rotations/{operation_id}/advance", response_model=RotationActionResponse)
def post_advance_rotation(
    operation_id: str,
    payload: RotationAdvanceRequest,
    ctx: AuthContext = Depends(require_permission("key:manage")),
    db: Session = Depends(get_db),
    keystore: LocalEncryptedKeyStore = Depends(get_keystore),
) -> RotationActionResponse:
    try:
        op = advance_rotation(
            db,
            keystore,
            operation_id=operation_id,
            actor_id=ctx.user.id,
            target_phase=payload.target_phase,
            crash_at=payload.crash_at,
        )
    except SimulatedCrashError as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "SIMULATED_CRASH_INJECTED",
                "crash_point": exc.crash_point,
                "operation_id": exc.operation_id,
                "phase": exc.phase,
                "message": str(exc),
                "correlation_id": ctx.correlation_id,
            },
        ) from None
    except RotationError as exc:
        raise _err(exc.status_code, exc.code, exc.message, ctx.correlation_id) from None
    return RotationActionResponse(operation=RotationOperationOut.model_validate(op), correlation_id=ctx.correlation_id)


@router.post("/keys/rotations/{operation_id}/recover", response_model=RecoveryRunResponse)
def post_recover_single_rotation(
    operation_id: str,
    ctx: AuthContext = Depends(require_permission("recovery:run")),
    db: Session = Depends(get_db),
    keystore: LocalEncryptedKeyStore = Depends(get_keystore),
) -> RecoveryRunResponse:
    try:
        get_rotation_or_raise(db, operation_id)
    except RotationError as exc:
        raise _err(exc.status_code, exc.code, exc.message, ctx.correlation_id) from None
    outcomes = recover_rotations(db, keystore, operation_id=operation_id)
    return RecoveryRunResponse(
        outcomes=[RecoveryOutcomeOut(**o.__dict__) for o in outcomes],
        correlation_id=ctx.correlation_id,
    )


@router.post("/keys/recovery/run", response_model=RecoveryRunResponse)
def post_recover_all(
    payload: RecoveryRunRequest | None = None,
    ctx: AuthContext = Depends(require_permission("recovery:run")),
    db: Session = Depends(get_db),
    keystore: LocalEncryptedKeyStore = Depends(get_keystore),
) -> RecoveryRunResponse:
    op_id = payload.operation_id if payload is not None else None
    outcomes = recover_rotations(db, keystore, operation_id=op_id)
    return RecoveryRunResponse(
        outcomes=[RecoveryOutcomeOut(**o.__dict__) for o in outcomes],
        correlation_id=ctx.correlation_id,
    )


@router.post("/keys/transfers/start", response_model=TransferOut, status_code=201)
def post_start_transfer(
    payload: TransferStartRequest,
    ctx: AuthContext = Depends(require_permission("resource:read")),
    db: Session = Depends(get_db),
) -> TransferOut:
    try:
        tx = start_in_flight_transfer(
            db,
            actor_id=ctx.user.id,
            resource_id=payload.resource_id,
            allow_post_cutoff=payload.allow_post_cutoff,
        )
    except RotationError as exc:
        raise _err(exc.status_code, exc.code, exc.message, ctx.correlation_id) from None
    return TransferOut.model_validate(tx)


@router.post("/keys/transfers/{transfer_id}/complete", response_model=TransferCompleteResponse)
def post_complete_transfer(
    transfer_id: str,
    ctx: AuthContext = Depends(require_permission("resource:read")),
    db: Session = Depends(get_db),
) -> TransferCompleteResponse:
    try:
        tx, decision = complete_in_flight_transfer(db, transfer_id=transfer_id, actor_id=ctx.user.id)
    except RotationError as exc:
        raise _err(exc.status_code, exc.code, exc.message, ctx.correlation_id) from None
    return TransferCompleteResponse(
        transfer=TransferOut.model_validate(tx),
        decision=decision,
        correlation_id=ctx.correlation_id,
    )


@router.get("/keys/backups", response_model=list[BackupManifestOut])
def get_backups_list(
    ctx: AuthContext = Depends(require_permission("backup:read")),
    db: Session = Depends(get_db),
) -> list[BackupManifestOut]:
    return [BackupManifestOut.model_validate(m) for m in list_backups(db)]


@router.post("/keys/backups/create", response_model=BackupManifestOut, status_code=201)
def post_create_backup(
    payload: BackupCreateRequest | None = None,
    ctx: AuthContext = Depends(require_permission("backup:manage")),
    db: Session = Depends(get_db),
    keystore: LocalEncryptedKeyStore = Depends(get_keystore),
    backup_dir: Path = Depends(get_backup_dir),
) -> BackupManifestOut:
    version_tag = payload.version_tag if payload is not None else None
    try:
        manifest = create_backup(
            db,
            keystore,
            actor_id=ctx.user.id,
            backup_dir=backup_dir,
            version_tag=version_tag,
        )
    except BackupError as exc:
        raise _err(exc.status_code, exc.code, exc.message, ctx.correlation_id) from None
    return BackupManifestOut.model_validate(manifest)


@router.post("/keys/backups/{backup_id}/verify", response_model=BackupVerificationOut)
def post_verify_backup(
    backup_id: str,
    ctx: AuthContext = Depends(require_permission("backup:read")),
    db: Session = Depends(get_db),
    keystore: LocalEncryptedKeyStore = Depends(get_keystore),
) -> BackupVerificationOut:
    try:
        res = verify_backup(db, keystore, backup_id, actor_id=ctx.user.id)
    except BackupError as exc:
        raise _err(exc.status_code, exc.code, exc.message, ctx.correlation_id) from None
    return BackupVerificationOut(
        backup_id=res.backup_id,
        valid=res.valid,
        status=res.status,
        reason=res.reason,
        manifest_sha256=res.manifest_sha256,
        max_revocation_epoch=res.max_revocation_epoch,
        active_epoch=res.active_epoch,
        correlation_id=ctx.correlation_id,
    )


@router.post("/keys/backups/{backup_id}/restore", response_model=BackupRestoreOut)
def post_restore_backup(
    backup_id: str,
    payload: BackupRestoreRequest,
    ctx: AuthContext = Depends(require_permission("backup:manage")),
    db: Session = Depends(get_db),
    keystore: LocalEncryptedKeyStore = Depends(get_keystore),
) -> BackupRestoreOut:
    try:
        res, count = restore_backup(db, keystore, backup_id, confirmation=payload.confirmation, actor_id=ctx.user.id)
    except BackupError as exc:
        raise _err(exc.status_code, exc.code, exc.message, ctx.correlation_id) from None
    return BackupRestoreOut(
        verification=BackupVerificationOut(
            backup_id=res.backup_id,
            valid=res.valid,
            status=res.status,
            reason=res.reason,
            manifest_sha256=res.manifest_sha256,
            max_revocation_epoch=res.max_revocation_epoch,
            active_epoch=res.active_epoch,
            correlation_id=ctx.correlation_id,
        ),
        restored_keys_count=count,
        correlation_id=ctx.correlation_id,
    )


@router.post("/keys/crash-injection", response_model=RotationActionResponse)
def post_crash_injection(
    payload: CrashInjectionConfigRequest,
    ctx: AuthContext = Depends(require_permission("key:manage")),
    db: Session = Depends(get_db),
    keystore: LocalEncryptedKeyStore = Depends(get_keystore),
) -> RotationActionResponse:
    """Explicit crash-injection endpoint strictly gated on demo_mode=True."""
    if not settings.demo_mode:
        raise _err(403, "CRASH_INJECTION_DISABLED", "Crash injection is allowed only when demo_mode=true.", ctx.correlation_id)
    if payload.crash_at not in CRASH_INJECTION_POINTS:
        raise _err(400, "INVALID_CRASH_POINT", f"Unknown crash injection point: {payload.crash_at}", ctx.correlation_id)
    try:
        op = advance_rotation(
            db,
            keystore,
            operation_id=payload.operation_id,
            actor_id=ctx.user.id,
            crash_at=payload.crash_at,
        )
    except SimulatedCrashError as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "code": "SIMULATED_CRASH_INJECTED",
                "crash_point": exc.crash_point,
                "operation_id": exc.operation_id,
                "phase": exc.phase,
                "message": str(exc),
                "correlation_id": ctx.correlation_id,
            },
        ) from None
    except RotationError as exc:
        raise _err(exc.status_code, exc.code, exc.message, ctx.correlation_id) from None
    return RotationActionResponse(operation=RotationOperationOut.model_validate(op), correlation_id=ctx.correlation_id)
