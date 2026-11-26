"""Cryptographic key metadata, lifecycle transitions, and self-test endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.app.auth.dependencies import AuthContext, require_permission
from backend.app.crypto.keystore import LocalEncryptedKeyStore, get_keystore
from backend.app.crypto.selftest import run_crypto_selftest
from backend.app.db.session import get_db
from backend.app.keys.lifecycle import KeyLifecycleError
from backend.app.keys.service import (
    generate_managed_key,
    get_key_or_raise,
    list_keys,
    transition_key_state,
)
from backend.app.schemas.common import PaginatedResponse
from backend.app.schemas.keys import (
    CryptoSelfTestOut,
    KeyActionResponse,
    KeyGenerateRequest,
    KeyMetadataOut,
    KeyTransitionRequest,
)

router = APIRouter(tags=["keys"])


def _handle_key_error(exc: KeyLifecycleError, corr_id: str) -> HTTPException:
    return HTTPException(
        status_code=exc.status_code,
        detail={"code": exc.code, "message": exc.message, "correlation_id": corr_id},
    )


@router.get("/keys", response_model=PaginatedResponse[KeyMetadataOut])
def get_keys(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    ctx: AuthContext = Depends(require_permission("key:read")),
    db: Session = Depends(get_db),
) -> PaginatedResponse[KeyMetadataOut]:
    items, total = list_keys(db, limit=limit, offset=offset)
    return PaginatedResponse[KeyMetadataOut](
        items=[KeyMetadataOut.model_validate(k) for k in items],
        total=total,
        limit=limit,
        offset=offset,
        correlation_id=ctx.correlation_id,
    )


@router.get("/keys/{key_id}", response_model=KeyMetadataOut)
def get_key(
    key_id: str,
    ctx: AuthContext = Depends(require_permission("key:read")),
    db: Session = Depends(get_db),
) -> KeyMetadataOut:
    try:
        rec = get_key_or_raise(db, key_id)
    except KeyLifecycleError as exc:
        raise _handle_key_error(exc, ctx.correlation_id) from None
    return KeyMetadataOut.model_validate(rec)


@router.post("/keys/generate", response_model=KeyActionResponse, status_code=201)
def post_generate_key(
    payload: KeyGenerateRequest,
    ctx: AuthContext = Depends(require_permission("key:manage")),
    db: Session = Depends(get_db),
    keystore: LocalEncryptedKeyStore = Depends(get_keystore),
) -> KeyActionResponse:
    try:
        rec = generate_managed_key(
            db,
            keystore,
            key_id=payload.key_id,
            purpose=payload.purpose,
            version=payload.version,
            activate_immediately=payload.activate_immediately,
        )
    except KeyLifecycleError as exc:
        raise _handle_key_error(exc, ctx.correlation_id) from None
    return KeyActionResponse(key=KeyMetadataOut.model_validate(rec), correlation_id=ctx.correlation_id)


@router.post("/keys/{key_id}/transition", response_model=KeyActionResponse)
def post_transition_key(
    key_id: str,
    payload: KeyTransitionRequest,
    ctx: AuthContext = Depends(require_permission("key:manage")),
    db: Session = Depends(get_db),
) -> KeyActionResponse:
    try:
        rec = transition_key_state(
            db,
            key_id=key_id,
            target_state=payload.target_state,
            reason=payload.reason,
            confirmation=payload.confirmation,
        )
    except KeyLifecycleError as exc:
        raise _handle_key_error(exc, ctx.correlation_id) from None
    return KeyActionResponse(key=KeyMetadataOut.model_validate(rec), correlation_id=ctx.correlation_id)


@router.get("/crypto/selftest", response_model=CryptoSelfTestOut)
def get_crypto_selftest(
    ctx: AuthContext = Depends(require_permission("crypto:selftest")),
) -> CryptoSelfTestOut:
    report = run_crypto_selftest()
    return CryptoSelfTestOut(
        passed=report.passed,
        checks=report.checks,
        libraries=report.libraries,
        detail=report.detail,
        correlation_id=ctx.correlation_id,
    )
