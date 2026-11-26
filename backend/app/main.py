"""Q-SHIELD FastAPI application factory, middleware, and sanitized error handling."""

from __future__ import annotations

import uuid

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError

from backend.app.api.v1.router import api_v1_router
from backend.app.config import settings


def create_app() -> FastAPI:
    """Create and configure the Q-SHIELD control-plane FastAPI app."""
    app = FastAPI(
        title=settings.app_name,
        version="1.0.0",
        description=(
            "Q-SHIELD Quantum-Ready Trust & Revocation Control Plane. "
            "Deterministic zero-trust policy, ML-KEM/ML-DSA/AES-GCM cryptography, node simulator, audit ledger, detector, and E2E messaging."
        ),
        openapi_url=f"{settings.api_prefix}/openapi.json",
        docs_url=f"{settings.api_prefix}/docs",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "PUT", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Correlation-Id"],
    )

    @app.middleware("http")
    async def attach_correlation_id_and_security_headers(request: Request, call_next):
        corr_id = request.headers.get("X-Correlation-Id") or f"corr-{uuid.uuid4().hex[:16]}"
        request.state.correlation_id = corr_id
        response = await call_next(request)
        response.headers["X-Correlation-Id"] = corr_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = "default-src 'self'; object-src 'none'; frame-ancestors 'none'"
        if request.url.path.startswith(settings.api_prefix):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        corr_id = getattr(request.state, "correlation_id", f"corr-{uuid.uuid4().hex[:16]}")
        if isinstance(exc.detail, dict) and "code" in exc.detail and "message" in exc.detail:
            payload = {
                "error": {
                    "code": str(exc.detail["code"]),
                    "message": str(exc.detail["message"]),
                    "correlation_id": str(exc.detail.get("correlation_id", corr_id)),
                }
            }
        else:
            payload = {
                "error": {
                    "code": f"HTTP_{exc.status_code}",
                    "message": str(exc.detail) if isinstance(exc.detail, str) else "Request rejected.",
                    "correlation_id": corr_id,
                }
            }
        return JSONResponse(status_code=exc.status_code, content=payload)

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, _exc: RequestValidationError) -> JSONResponse:
        corr_id = getattr(request.state, "correlation_id", f"corr-{uuid.uuid4().hex[:16]}")
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": "Request payload failed schema validation.",
                    "correlation_id": corr_id,
                }
            },
        )

    @app.exception_handler(SQLAlchemyError)
    async def db_exception_handler(request: Request, _exc: SQLAlchemyError) -> JSONResponse:
        corr_id = getattr(request.state, "correlation_id", f"corr-{uuid.uuid4().hex[:16]}")
        return JSONResponse(
            status_code=503,
            content={
                "error": {
                    "code": "DATABASE_UNAVAILABLE",
                    "message": "Database operation failed safely.",
                    "correlation_id": corr_id,
                }
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, _exc: Exception) -> JSONResponse:
        corr_id = getattr(request.state, "correlation_id", f"corr-{uuid.uuid4().hex[:16]}")
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": "An unexpected error occurred.",
                    "correlation_id": corr_id,
                }
            },
        )

    app.include_router(api_v1_router, prefix=settings.api_prefix)
    return app


app = create_app()
