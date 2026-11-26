"""Pydantic schemas for Phase 7 Explainable Deterministic Threat Detector."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class DetectorRuleOut(BaseModel):
    rule_id: str
    category: str
    title: str
    severity: str
    base_weight: float
    recommended_response: str
    description: str


class DetectorRulesCatalogOut(BaseModel):
    rule_set_version: str
    active_config: dict[str, Any]
    rules: list[DetectorRuleOut]


class DetectorConfigUpdateRequest(BaseModel):
    rule_set_version: str | None = Field(default=None, max_length=32)
    auth_failure_threshold: int | None = Field(default=None, ge=1, le=100)
    auth_failure_window_sec: int | None = Field(default=None, ge=10, le=86400)
    excessive_reads_threshold: int | None = Field(default=None, ge=2, le=1000)
    mad_z_threshold: float | None = Field(default=None, ge=1.0, le=20.0)
    clock_skew_tolerance_ms: int | None = Field(default=None, ge=100, le=60000)
    stale_node_threshold_ms: int | None = Field(default=None, ge=50, le=60000)
    max_legitimate_retries: int | None = Field(default=None, ge=0, le=10)
    reason: str = Field(..., min_length=3, max_length=512)
    confirmation: bool = Field(...)


class DetectorEvaluateRequest(BaseModel):
    source: str = Field(default="audit_ledger")
    start_sequence: int | None = Field(default=None, ge=1)
    end_sequence: int | None = Field(default=None, ge=1)
    seed: int = Field(default=20261126, ge=0)
    custom_events: list[dict[str, Any]] | None = Field(default=None, max_length=5000)
    approvals: list[dict[str, Any]] | None = Field(default=None, max_length=500)


class AlertOut(BaseModel):
    id: str
    rule_id: str
    rule_version: str
    fingerprint: str
    severity: str
    confidence: float
    explanation: str
    actor_id: str
    device_id: str | None = None
    session_id: str | None = None
    node_id: str | None = None
    resource_id: str | None = None
    services: list[str]
    event_refs: list[str]
    reason_codes: list[str]
    recommended_response: str
    detection_window_sec: int
    first_observed_at: datetime
    last_observed_at: datetime
    run_id: str | None = None
    status: str
    resolution_note: str | None = None
    reviewed_by: str | None = None
    reviewed_at: datetime | None = None
    alert_time: datetime


class DetectionRunOut(BaseModel):
    run_id: str
    dataset_name: str
    dataset_version: str
    rule_set_version: str
    events_inspected: int
    alerts_created: int
    alerts_deduplicated: int
    audit_chain_verified: bool
    status: str
    metrics: dict[str, Any]
    summary_detail: str
    created_by: str
    created_at: datetime


class DetectorEvaluateResponse(BaseModel):
    run: DetectionRunOut
    alerts: list[AlertOut]
    metrics: dict[str, Any] | None = None
    correlation_id: str


class AlertTransitionRequest(BaseModel):
    reason: str = Field(..., min_length=3, max_length=512)
    confirmation: bool = Field(...)


class AlertActionResponse(BaseModel):
    alert: AlertOut
    correlation_id: str
