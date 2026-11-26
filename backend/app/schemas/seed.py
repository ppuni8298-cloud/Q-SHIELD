"""Demo seed and reset schemas."""

from __future__ import annotations

from pydantic import Field

from backend.app.schemas.common import StrictBaseModel


class SeedResetRequest(StrictBaseModel):
    reason: str = Field(min_length=3, max_length=512)
    confirmation: bool = False


class SeedResetResponse(StrictBaseModel):
    synthetic_mode: bool = True
    reset_completed: bool
    users_seeded: int
    devices_seeded: int
    sessions_seeded: int
    resources_seeded: int
    correlation_id: str
