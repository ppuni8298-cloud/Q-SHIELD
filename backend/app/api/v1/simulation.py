"""Safe demo-mode seed/reset and 14-scenario live orchestrator endpoints."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.auth.dependencies import AuthContext, require_permission
from backend.app.backups.service import get_backup_dir
from backend.app.config import settings
from backend.app.crypto.keystore import LocalEncryptedKeyStore, get_keystore
from backend.app.db.session import get_db
from backend.app.schemas.seed import SeedResetRequest, SeedResetResponse
from backend.app.services.scenarios import SCENARIO_CATALOG, run_demo_scenario
from backend.app.services.seed import seed_database

router = APIRouter(prefix="/simulation", tags=["simulation"])


@router.get("/scenarios")
def get_simulation_scenarios(
    ctx: AuthContext = Depends(require_permission("audit:read")),
) -> dict[str, Any]:
    """List the 14 resettable verification scenarios."""
    return {"items": SCENARIO_CATALOG, "total": len(SCENARIO_CATALOG), "correlation_id": ctx.correlation_id}


@router.post("/scenarios/{scenario_id}/run")
def post_run_simulation_scenario(
    scenario_id: str,
    ctx: AuthContext = Depends(require_permission("simulation:run")),
    db: Session = Depends(get_db),
    keystore: LocalEncryptedKeyStore = Depends(get_keystore),
    backup_dir: Path = Depends(get_backup_dir),
) -> dict[str, Any]:
    """Execute one of the 14 scenarios against live backend services with reset isolation."""
    if not settings.demo_mode:
        raise HTTPException(
            status_code=403,
            detail={"code": "DEMO_MODE_DISABLED", "message": "Scenarios require demo_mode.", "correlation_id": ctx.correlation_id},
        )
    try:
        return run_demo_scenario(
            db, keystore, backup_dir, scenario_id=scenario_id, actor_id=ctx.user.id, correlation_id=ctx.correlation_id
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail={"code": "SCENARIO_NOT_FOUND", "message": str(exc), "correlation_id": ctx.correlation_id},
        ) from None


@router.post("/reset", response_model=SeedResetResponse)
def post_simulation_reset(
    payload: SeedResetRequest,
    ctx: AuthContext = Depends(require_permission("simulation:reset")),
    db: Session = Depends(get_db),
    keystore: LocalEncryptedKeyStore = Depends(get_keystore),
) -> SeedResetResponse:
    """Reset synthetic demo database to known initial state (admin + demo_mode only)."""
    if not settings.demo_mode:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "DEMO_MODE_DISABLED",
                "message": "Simulation reset is permitted only in demo mode.",
                "correlation_id": ctx.correlation_id,
            },
        )
    if not payload.confirmation:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "CONFIRMATION_REQUIRED",
                "message": "Explicit confirmation is required to reset demo state.",
                "correlation_id": ctx.correlation_id,
            },
        )
    summary = seed_database(db, reset=True, keystore=keystore)
    return SeedResetResponse(
        synthetic_mode=True,
        reset_completed=True,
        users_seeded=summary.users_seeded,
        devices_seeded=summary.devices_seeded,
        sessions_seeded=summary.sessions_seeded,
        resources_seeded=summary.resources_seeded,
        correlation_id=ctx.correlation_id,
    )
