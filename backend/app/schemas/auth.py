"""Authentication and session Pydantic v2 schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from backend.app.schemas.common import StrictBaseModel


class DemoLoginRequest(StrictBaseModel):
    actor_id: str = Field(min_length=1, max_length=128)
    device_id: str = Field(min_length=1, max_length=128)
    peer_id: str | None = Field(default=None, max_length=128)


class SessionOut(StrictBaseModel):
    id: str
    actor_id: str
    device_id: str
    peer_id: str | None
    auth_strength: str
    version: int
    state: Literal["ACTIVE", "EXPIRED", "REVOKED"]
    issued_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    revoke_reason: str | None


class DemoLoginResponse(StrictBaseModel):
    synthetic_mode: bool = True
    access_token: str
    token_type: Literal["bearer"] = "bearer"
    session: SessionOut
    role: str
    correlation_id: str


class AuthMeResponse(StrictBaseModel):
    synthetic_mode: bool = True
    actor_id: str
    display_name: str
    role: str
    enabled: bool
    session: SessionOut
    permissions: list[str]
    correlation_id: str


class SessionRevokeRequest(StrictBaseModel):
    reason: str = Field(min_length=3, max_length=512)
    confirmation: bool = False


class SessionActionResponse(StrictBaseModel):
    session: SessionOut
    correlation_id: str
