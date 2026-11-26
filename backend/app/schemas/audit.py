"""Pydantic schemas for Phase 6 Tamper-Evident Audit Ledger, Checkpoints, Receipts & Exports."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AuditEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    sequence: int
    event_id: str
    event_type: str
    event_category: str
    timestamp_utc: datetime
    actor_id: str
    action: str
    target_type: str
    target_id: str
    outcome: str
    decision: str
    reason_code: str
    correlation_id: str
    source_component: str
    payload: dict[str, Any]
    prev_hash: str
    event_hash: str
    hash_algorithm: str
    schema_version: str


class AuditVerifyRequest(BaseModel):
    start_sequence: int | None = Field(default=None, ge=1)
    end_sequence: int | None = Field(default=None, ge=1)


class AuditVerificationOut(BaseModel):
    valid: bool
    ledger_id: str
    verified_event_count: int
    total_events_inspected: int
    first_sequence: int | None = None
    last_sequence: int | None = None
    head_hash: str | None = None
    first_invalid_sequence: int | None = None
    first_invalid_event_id: str | None = None
    failure_category: str | None = None
    expected_hash: str | None = None
    actual_hash: str | None = None
    detail: str
    verified_at: datetime


class AuditCheckpointCreateRequest(BaseModel):
    up_to_sequence: int | None = Field(default=None, ge=1)


class AuditCheckpointOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    sequence: int
    checkpoint_id: str
    first_sequence: int
    last_sequence: int
    root_hash: str
    schema_version: str
    signature_algorithm: str
    signer_key_id: str
    signature_b64: str
    created_by: str
    created_at: datetime


class AuditReceiptOut(BaseModel):
    receipt_id: str
    receipt_type: str
    ledger_id: str
    schema_version: str
    event_id: str | None = None
    sequence: int
    first_sequence: int
    last_sequence: int
    event_hash: str
    chain_head_hash: str
    signature_algorithm: str
    signer_key_id: str
    signature_b64: str
    created_by: str
    created_at: str


class AuditReceiptVerifyRequest(BaseModel):
    receipt: dict[str, Any]
    public_key_b64: str | None = None


class AuditReceiptVerifyOut(BaseModel):
    valid: bool
    receipt_id: str | None = None
    detail: str
    correlation_id: str


class AuditExportRequest(BaseModel):
    first_sequence: int = Field(default=1, ge=1)
    last_sequence: int | None = Field(default=None, ge=1)


class AuditExportPackageOut(BaseModel):
    export_schema_version: str
    ledger_id: str
    hash_algorithm: str
    export_created_at: str
    first_sequence: int
    last_sequence: int
    expected_prev_hash: str
    genesis_hash: str
    previous_checkpoint: dict[str, Any] | None = None
    final_chain_head_hash: str
    signer_public_key_b64: str
    receipt: AuditReceiptOut
    events: list[dict[str, Any]]


class AuditExportVerifyRequest(BaseModel):
    package: dict[str, Any]
    public_key_b64: str | None = None
