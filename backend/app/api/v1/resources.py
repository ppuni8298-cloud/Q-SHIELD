"""Protected-resource metadata and policy-gated access endpoints."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.app.auth.dependencies import AuthContext, get_auth_context, require_permission
from backend.app.crypto.keystore import LocalEncryptedKeyStore, get_keystore
from backend.app.db.models import EncryptedObject, Resource
from backend.app.db.session import get_db
from backend.app.identity.roles import role_has_permission
from backend.app.policy.engine import ZeroTrustPolicyEngine
from backend.app.schemas.common import PaginatedResponse
from backend.app.schemas.policy import PolicyEvalRequest
from backend.app.schemas.vault import (
    ResourceAccessRequest,
    ResourceAccessResponse,
    ResourceCreateRequest,
    ResourceCryptoMetadataOut,
    ResourceDecryptResponse,
    ResourceEncryptRequest,
    ResourceEncryptResponse,
    ResourceOut,
)
from backend.app.vault.crypto_vault import (
    CryptoVaultError,
    decrypt_resource_content,
    encrypt_resource_content,
    get_encrypted_metadata_or_raise,
)
from backend.app.vault.service import (
    VaultServiceError,
    create_resource,
    get_resource_or_raise,
    list_resources,
    parse_resource_metadata,
)

router = APIRouter(prefix="/resources", tags=["resources"])
_policy_engine = ZeroTrustPolicyEngine()


def _to_resource_out(res: Resource) -> ResourceOut:
    return ResourceOut(
        id=res.id,
        owner_id=res.owner_id,
        type=res.type,
        metadata=parse_resource_metadata(res),
        key_version=res.key_version,
        state=res.state,  # type: ignore[arg-type]
        created_at=res.created_at,
        updated_at=res.updated_at,
    )


@router.get("", response_model=PaginatedResponse[ResourceOut])
def get_resources(
    owner_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    ctx: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> PaginatedResponse[ResourceOut]:
    if role_has_permission(ctx.user.role, "resource:read_meta"):
        scoped_owner = owner_id
    else:
        if owner_id is not None and owner_id != ctx.user.id:
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "FORBIDDEN_CROSS_OWNER_RESOURCES",
                    "message": "Owners may only list their own resource metadata.",
                    "correlation_id": ctx.correlation_id,
                },
            )
        scoped_owner = ctx.user.id

    items, total = list_resources(db, owner_id=scoped_owner, limit=limit, offset=offset)
    return PaginatedResponse[ResourceOut](
        items=[_to_resource_out(r) for r in items],
        total=total,
        limit=limit,
        offset=offset,
        correlation_id=ctx.correlation_id,
    )


@router.post("", response_model=ResourceOut, status_code=201)
def post_resource(
    payload: ResourceCreateRequest,
    ctx: AuthContext = Depends(require_permission("resource:create")),
    db: Session = Depends(get_db),
) -> ResourceOut:
    try:
        res = create_resource(db, payload, acting_user=ctx.user)
    except VaultServiceError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": exc.message, "correlation_id": ctx.correlation_id},
        ) from None
    return _to_resource_out(res)


@router.get("/{resource_id}", response_model=ResourceOut)
def get_resource(
    resource_id: str,
    ctx: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> ResourceOut:
    try:
        res = get_resource_or_raise(db, resource_id)
    except VaultServiceError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": exc.message, "correlation_id": ctx.correlation_id},
        ) from None
    if res.owner_id != ctx.user.id and not role_has_permission(ctx.user.role, "resource:read_meta"):
        raise HTTPException(
            status_code=403,
            detail={
                "code": "FORBIDDEN_RESOURCE_META",
                "message": "Insufficient permissions to view this resource.",
                "correlation_id": ctx.correlation_id,
            },
        )
    return _to_resource_out(res)


@router.post("/{resource_id}/access", response_model=ResourceAccessResponse)
def post_resource_access(
    resource_id: str,
    payload: ResourceAccessRequest,
    ctx: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> ResourceAccessResponse:
    """Evaluate 10-step zero-trust policy for authenticated actor/session/device; leak nothing on deny."""
    decision = _policy_engine.evaluate(
        db,
        PolicyEvalRequest(
            actor_id=ctx.user.id,
            session_id=ctx.session.id,
            device_id=ctx.device.id,
            resource_id=resource_id,
            action=payload.action,
        ),
        correlation_id=ctx.correlation_id,
    )
    if decision.decision != "ALLOW":
        raise HTTPException(
            status_code=403,
            detail={
                "code": decision.reason_code,
                "message": "Access denied by zero-trust policy.",
                "correlation_id": decision.correlation_id,
            },
        )
    res = get_resource_or_raise(db, resource_id)
    return ResourceAccessResponse(
        decision="ALLOW",
        reason_code=decision.reason_code,
        correlation_id=decision.correlation_id,
        request_id=decision.request_id,
        resource=_to_resource_out(res),
    )


def _to_crypto_metadata_out(enc_obj: EncryptedObject) -> ResourceCryptoMetadataOut:
    env = json.loads(enc_obj.aead_envelope)
    return ResourceCryptoMetadataOut(
        resource_id=enc_obj.resource_id,
        key_version=enc_obj.version,
        algorithm=str(env.get("algorithm", "AES-256-GCM")),
        nonce_b64=enc_obj.nonce,
        integrity_sha256=enc_obj.integrity,
        aad_metadata={
            "schema_version": env.get("schema_version"),
            "resource_id": env.get("resource_id"),
            "owner_id": env.get("owner_id"),
            "resource_type": env.get("resource_type"),
            "algorithm": env.get("algorithm"),
            "key_version": env.get("key_version"),
            "timestamp_utc": env.get("timestamp_utc"),
            "expires_at_utc": env.get("expires_at_utc"),
        },
        created_at=enc_obj.created_at,
    )


@router.post("/{resource_id}/encrypt", response_model=ResourceEncryptResponse, status_code=201)
def post_resource_encrypt(
    resource_id: str,
    payload: ResourceEncryptRequest,
    ctx: AuthContext = Depends(require_permission("resource:encrypt")),
    db: Session = Depends(get_db),
    keystore: LocalEncryptedKeyStore = Depends(get_keystore),
) -> ResourceEncryptResponse:
    """Encrypt synthetic resource plaintext using AES-256-GCM + AAD and wrapped random DEK."""
    try:
        enc_obj = encrypt_resource_content(
            db,
            keystore,
            ctx=ctx,
            resource_id=resource_id,
            plaintext=payload.plaintext,
            expires_at_utc=payload.expires_at_utc,
        )
    except CryptoVaultError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": exc.message, "correlation_id": ctx.correlation_id},
        ) from None
    return ResourceEncryptResponse(
        encrypted=True,
        crypto_metadata=_to_crypto_metadata_out(enc_obj),
        correlation_id=ctx.correlation_id,
    )


@router.post("/{resource_id}/decrypt", response_model=ResourceDecryptResponse)
def post_resource_decrypt(
    resource_id: str,
    ctx: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
    keystore: LocalEncryptedKeyStore = Depends(get_keystore),
) -> ResourceDecryptResponse:
    """Authorize via 10-step policy, authenticate AEAD tag/AAD, and release plaintext only on success."""
    try:
        plaintext, enc_obj, request_id = decrypt_resource_content(
            db,
            keystore,
            ctx=ctx,
            resource_id=resource_id,
        )
    except CryptoVaultError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": exc.message, "correlation_id": ctx.correlation_id},
        ) from None
    return ResourceDecryptResponse(
        decision="ALLOW",
        resource_id=resource_id,
        plaintext=plaintext,
        crypto_metadata=_to_crypto_metadata_out(enc_obj),
        request_id=request_id,
        correlation_id=ctx.correlation_id,
    )


@router.get("/{resource_id}/crypto-metadata", response_model=ResourceCryptoMetadataOut)
def get_resource_crypto_metadata(
    resource_id: str,
    ctx: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
) -> ResourceCryptoMetadataOut:
    """Return non-secret encryption metadata (never DEKs, KEKs, or plaintext)."""
    try:
        res = get_resource_or_raise(db, resource_id)
    except VaultServiceError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": exc.message, "correlation_id": ctx.correlation_id},
        ) from None
    if res.owner_id != ctx.user.id and not role_has_permission(ctx.user.role, "resource:read_meta"):
        raise HTTPException(
            status_code=403,
            detail={
                "code": "FORBIDDEN_RESOURCE_CRYPTO_META",
                "message": "Insufficient permissions to view resource encryption metadata.",
                "correlation_id": ctx.correlation_id,
            },
        )
    try:
        enc_obj = get_encrypted_metadata_or_raise(db, res)
    except CryptoVaultError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": exc.message, "correlation_id": ctx.correlation_id},
        ) from None
    return _to_crypto_metadata_out(enc_obj)
