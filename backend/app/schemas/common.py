"""Shared Pydantic v2 response wrappers and error contracts."""

from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class StrictBaseModel(BaseModel):
    """Base schema rejecting unexpected extra fields."""

    model_config = ConfigDict(extra="forbid", from_attributes=True)


class ErrorDetail(StrictBaseModel):
    code: str
    message: str
    correlation_id: str


class ErrorResponse(StrictBaseModel):
    error: ErrorDetail


class PaginatedResponse(BaseModel, Generic[T]):
    model_config = ConfigDict(from_attributes=True)

    items: list[T]
    total: int
    limit: int = Field(ge=1, le=200)
    offset: int = Field(ge=0)
    correlation_id: str
