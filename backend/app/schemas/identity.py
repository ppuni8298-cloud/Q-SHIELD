"""Identity and RBAC Pydantic v2 schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from backend.app.schemas.common import StrictBaseModel

RoleName = Literal["owner", "security_operator", "admin", "auditor"]


class UserOut(StrictBaseModel):
    id: str
    display_name: str
    role: RoleName
    enabled: bool
    is_synthetic: bool
    created_at: datetime
    updated_at: datetime


class UserCreateRequest(StrictBaseModel):
    id: str = Field(min_length=2, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    display_name: str = Field(min_length=1, max_length=256)
    role: RoleName
    enabled: bool = True
    reason: str = Field(min_length=3, max_length=512)
    confirmation: bool = False


class UserUpdateRequest(StrictBaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=256)
    role: RoleName | None = None
    enabled: bool | None = None
    reason: str = Field(min_length=3, max_length=512)
    confirmation: bool = False


class UserDetailResponse(StrictBaseModel):
    user: UserOut
    device_ids: list[str]
    active_session_count: int
    correlation_id: str


class RolePermissionOut(StrictBaseModel):
    role: RoleName
    action: str
    scope: str
    description: str


class RoleSummaryOut(StrictBaseModel):
    role: RoleName
    permissions: list[RolePermissionOut]
