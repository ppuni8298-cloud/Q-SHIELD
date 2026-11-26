"""Protected-resource metadata and policy evaluation Pydantic v2 schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from backend.app.schemas.common import StrictBaseModel


class ResourceOut(StrictBaseModel):
    id: str
    owner_id: str
    type: str
    metadata: dict[str, str]
    key_version: int
    state: Literal["ACTIVE", "DISABLED"]
    created_at: datetime
    updated_at: datetime


class ResourceCreateRequest(StrictBaseModel):
    id: str = Field(min_length=2, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    owner_id: str = Field(min_length=2, max_length=128)
    type: str = Field(default="synthetic_document", min_length=1, max_length=64)
    metadata: dict[str, str] = Field(default_factory=dict)
    key_version: int = Field(default=1, ge=0)


class ResourceAccessRequest(StrictBaseModel):
    action: str = Field(default="read", min_length=1, max_length=64)


class ResourceAccessResponse(StrictBaseModel):
    decision: Literal["ALLOW", "DENY"]
    reason_code: str
    correlation_id: str
    request_id: str
    resource: ResourceOut | None = None


class ResourceEncryptRequest(StrictBaseModel):
    plaintext: str = Field(min_length=1, max_length=1048576)
    expires_at_utc: str | None = Field(default=None, max_length=64)


class ResourceCryptoMetadataOut(StrictBaseModel):
    resource_id: str
    key_version: int
    algorithm: str
    nonce_b64: str
    integrity_sha256: str
    aad_metadata: dict[str, str | int | None]
    created_at: datetime


class ResourceEncryptResponse(StrictBaseModel):
    encrypted: bool = True
    crypto_metadata: ResourceCryptoMetadataOut
    correlation_id: str


class ResourceDecryptResponse(StrictBaseModel):
    decision: Literal["ALLOW"] = "ALLOW"
    resource_id: str
    plaintext: str
    crypto_metadata: ResourceCryptoMetadataOut
    request_id: str
    correlation_id: str
