"""Device lifecycle Pydantic v2 schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from backend.app.schemas.common import StrictBaseModel

DeviceState = Literal["PENDING", "TRUSTED", "SUSPENDED", "REVOKED"]


class DeviceOut(StrictBaseModel):
    id: str
    owner_id: str
    credential_fingerprint: str
    state: DeviceState
    state_version: int
    enrolled_at: datetime
    last_seen_at: datetime | None
    revoked_at: datetime | None
    reason: str | None
    replaced_by_device_id: str | None


class DeviceEnrollRequest(StrictBaseModel):
    id: str = Field(min_length=2, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    owner_id: str = Field(min_length=2, max_length=128)
    credential_fingerprint: str = Field(min_length=6, max_length=128)
    initial_state: Literal["PENDING", "TRUSTED"] = "PENDING"
    reason: str = Field(min_length=3, max_length=512)


class DeviceOperatorActionRequest(StrictBaseModel):
    reason: str = Field(min_length=3, max_length=512)
    confirmation: bool = False


class DeviceReEnrollRequest(StrictBaseModel):
    old_device_id: str = Field(min_length=2, max_length=128)
    new_device_id: str = Field(min_length=2, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    new_credential_fingerprint: str = Field(min_length=6, max_length=128)
    reason: str = Field(min_length=3, max_length=512)
    confirmation: bool = False


class DeviceHistoryOut(StrictBaseModel):
    id: int
    device_id: str
    from_state: str | None
    to_state: str
    state_version: int
    changed_by: str
    reason: str
    correlation_id: str
    created_at: datetime


class DeviceActionResponse(StrictBaseModel):
    device: DeviceOut
    correlation_id: str


class DeviceReEnrollResponse(StrictBaseModel):
    revoked_device: DeviceOut
    replacement_device: DeviceOut
    correlation_id: str
