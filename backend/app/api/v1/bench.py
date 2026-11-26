"""Empirical Benchmark Lab API routes (/api/v1/bench/*)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.auth.dependencies import AuthContext, require_permission
from backend.app.db.models import BenchmarkRun
from backend.app.db.session import get_db

router = APIRouter(prefix="/bench", tags=["benchmarks"])
LATEST_BENCH_PATH = Path(__file__).resolve().parents[3] / "reports" / "benchmarks" / "latest.json"


@router.get("/latest")
def get_latest_benchmark(
    ctx: AuthContext = Depends(require_permission("bench:read")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    row = db.scalars(select(BenchmarkRun).order_by(BenchmarkRun.created_at.desc()).limit(1)).first()
    if row is not None:
        data = json.loads(row.stats_json)
        data["correlation_id"] = ctx.correlation_id
        return data
    if LATEST_BENCH_PATH.is_file():
        data = json.loads(LATEST_BENCH_PATH.read_text(encoding="utf-8"))
        data["correlation_id"] = ctx.correlation_id
        return data
    return {"run_id": None, "results": [], "environment": {}, "correlation_id": ctx.correlation_id}


@router.post("/run")
def post_run_benchmark(
    ctx: AuthContext = Depends(require_permission("bench:run")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    from scripts.benchmark import run_benchmark_suite

    report = run_benchmark_suite(persist_db=db, write_reports=True)
    report["correlation_id"] = ctx.correlation_id
    return report
