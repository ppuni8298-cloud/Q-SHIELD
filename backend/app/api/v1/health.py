"""Health and readiness endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from backend.app.auth.dependencies import get_correlation_id
from backend.app.config import settings
from backend.app.crypto.selftest import run_crypto_selftest
from backend.app.db.session import get_db, verify_database_health

router = APIRouter(tags=["health"])


@router.get("/health")
def get_health(request: Request) -> dict[str, object]:
    """Liveness check reporting synthetic/offline mode flags."""
    return {
        "status": "ok",
        "service": settings.app_name,
        "demo_mode": settings.demo_mode,
        "offline_mode": settings.offline_mode,
        "correlation_id": get_correlation_id(request),
    }


@router.get("/ready")
def get_ready(request: Request, db: Session = Depends(get_db)) -> dict[str, object]:
    """Readiness check verifying SQLite integrity, required tables, and crypto self-test."""
    corr_id = get_correlation_id(request)
    bind: Engine = db.get_bind()  # type: ignore[assignment]
    ok, detail = verify_database_health(bind)
    if not ok:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "DATABASE_NOT_READY",
                "message": detail,
                "correlation_id": corr_id,
            },
        )
    crypto_report = run_crypto_selftest()
    if not crypto_report.passed:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "CRYPTO_SELFTEST_FAILED",
                "message": crypto_report.detail,
                "correlation_id": corr_id,
            },
        )
    return {
        "ready": True,
        "database": "ok",
        "crypto": "ok",
        "correlation_id": corr_id,
    }
