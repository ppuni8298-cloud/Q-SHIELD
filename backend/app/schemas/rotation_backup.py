"""Pydantic schemas for Phase 5 Key Rotation, Transfers, Crash Recovery & Backups."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class RotationStartRequest(BaseModel):
    purpose: str = Field(default="vault_kek", min_length=2, max_length=64)
    new_key_id: str | None = Field(default=None, min_length=3, max_length=128)
    grace_policy: str = Field(default="ZERO_GRACE", min_length=3, max_length=32)
    reason: str = Field(..., min_length=3, max_length=512)
    auto_advance: bool = Field(default=True)
    crash_at: str | None = Field(default=None, max_length=64)


class RotationAdvanceRequest(BaseModel):
    target_phase: str | None = Field(default=None, max_length=32)
    crash_at: str | None = Field(default=None, max_length=64)


class RotationOperationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    operation_id: str
    purpose: str
    from_key_id: str
    to_key_id: str
    from_version: int
    to_version: int
    phase: str
    status: str
    grace_policy: str
    actor_id: str
    reason: str
    correlation_id: str
    backup_id: str | None = None
    committed: bool
    commit_at: datetime | None = None
    node_acks_json: str
    failure_info: str | None = None
    recovery_notes: str | None = None
    journal_hash: str
    created_at: datetime
    updated_at: datetime


class RotationActionResponse(BaseModel):
    operation: RotationOperationOut
    correlation_id: str


class TransferStartRequest(BaseModel):
    resource_id: str = Field(..., min_length=1, max_length=128)
    allow_post_cutoff: bool = Field(default=True)


class TransferOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    transfer_id: str
    actor_id: str
    resource_id: str
    key_version: int
    state: str
    allow_post_cutoff: bool
    started_at: datetime
    completed_at: datetime | None = None


class TransferCompleteResponse(BaseModel):
    transfer: TransferOut
    decision: str
    correlation_id: str


class RecoveryRunRequest(BaseModel):
    operation_id: str | None = Field(default=None, max_length=128)


class RecoveryOutcomeOut(BaseModel):
    operation_id: str
    previous_phase: str
    previous_status: str
    final_status: str
    action_taken: str
    idempotent_noop: bool
    notes: str


class RecoveryRunResponse(BaseModel):
    outcomes: list[RecoveryOutcomeOut]
    correlation_id: str


class BackupCreateRequest(BaseModel):
    reason: str = Field(default="Scheduled operator backup", min_length=3, max_length=512)
    version_tag: int | None = Field(default=None, ge=0)


class BackupManifestOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    backup_id: str
    schema_version: str
    version: int
    active_epoch: int
    max_revocation_epoch: int
    tombstone_count: int
    backup_path: str
    manifest_sha256: str
    signature_b64: str
    verification_status: str
    verified: bool
    created_by: str
    created_at: datetime


class BackupVerificationOut(BaseModel):
    backup_id: str
    valid: bool
    status: str
    reason: str
    manifest_sha256: str
    max_revocation_epoch: int
    active_epoch: int
    correlation_id: str


class BackupRestoreRequest(BaseModel):
    confirmation: bool = Field(...)


class BackupRestoreOut(BaseModel):
    verification: BackupVerificationOut
    restored_keys_count: int
    correlation_id: str


class CrashInjectionConfigRequest(BaseModel):
    operation_id: str = Field(..., min_length=3, max_length=128)
    crash_at: str = Field(..., min_length=3, max_length=64)
