"""Zero-trust 10-step policy evaluation Pydantic v2 schemas."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from backend.app.schemas.common import StrictBaseModel


class PolicyEvalRequest(StrictBaseModel):
    actor_id: str = Field(default="", max_length=128)
    session_id: str = Field(default="", max_length=128)
    device_id: str = Field(default="", max_length=128)
    resource_id: str = Field(default="", max_length=128)
    action: str = Field(default="read", max_length=64)


class PolicyStepResult(StrictBaseModel):
    step: int
    name: str
    passed: bool
    reason_code: str
    detail: str


class PolicyEvalResponse(StrictBaseModel):
    decision: Literal["ALLOW", "DENY"]
    reason_code: str
    correlation_id: str
    request_id: str
    failed_step: int | None = None
    checks: list[PolicyStepResult]
