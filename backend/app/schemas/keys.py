"""Key metadata and crypto self-test Pydantic v2 schemas (no secret material)."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from backend.app.schemas.common import StrictBaseModel

KeyState = Literal["PREPARED", "ACTIVE", "ROTATING", "ACTIVE_NEW", "RETIRED", "REVOKED", "COMPROMISED"]
KeyPurpose = Literal["kem", "signing", "vault_kek", "vault_dek", "session", "audit"]


class KeyMetadataOut(StrictBaseModel):
    key_id: str
    purpose: str
    algorithm: str
    version: int
    state: KeyState
    created_at: datetime
    activated_at: datetime | None
    revoked_at: datetime | None


class KeyGenerateRequest(StrictBaseModel):
    key_id: str = Field(min_length=2, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    purpose: KeyPurpose
    version: int = Field(ge=1)
    activate_immediately: bool = False
    reason: str = Field(min_length=3, max_length=512)


class KeyTransitionRequest(StrictBaseModel):
    target_state: KeyState
    reason: str = Field(min_length=3, max_length=512)
    confirmation: bool = False


class KeyActionResponse(StrictBaseModel):
    key: KeyMetadataOut
    correlation_id: str


class CryptoSelfTestOut(StrictBaseModel):
    passed: bool
    checks: dict[str, bool]
    libraries: dict[str, str]
    detail: str
    correlation_id: str
