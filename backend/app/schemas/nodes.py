"""Pydantic v2 schemas for Phase 4 simulated nodes, revocation events, and convergence."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from backend.app.schemas.common import StrictBaseModel

SubjectType = Literal["actor", "device", "key", "session"]
NodeFaultMode = Literal["NONE", "OFFLINE", "PARTITIONED", "DROP_EVENTS", "PROCESSING_ERROR", "STALE_TRUST"]


class NodeStateOut(StrictBaseModel):
    node_id: str
    service: str
    health: str
    available: bool
    current_epoch: int
    latency_profile: str
    latency_ms: int
    last_event_seq: int
    last_applied_event_id: str | None
    sync_status: str
    fault_mode: str
    local_revocations: dict[str, list[str]]
    last_heartbeat: datetime


class NodeInboxItemOut(StrictBaseModel):
    id: int
    node_id: str
    event_id: str
    sequence_number: int
    delivery_status: str
    enqueued_at_ms: int
    delivered_at_ms: int | None
    processed_at_ms: int | None
    detail: str


class NodeSyncStateOut(StrictBaseModel):
    node: NodeStateOut
    latest_global_sequence: int
    pending_inbox_count: int
    inbox: list[NodeInboxItemOut]
    correlation_id: str


class NodeConfigureRequest(StrictBaseModel):
    node_count: int = Field(ge=3, le=7)
    latencies_ms: list[int] | None = None
    reason: str = Field(min_length=3, max_length=512)


class NodeAvailabilityRequest(StrictBaseModel):
    available: bool
    fault_mode: NodeFaultMode = "NONE"
    reason: str = Field(min_length=3, max_length=512)


class RevocationIssueRequest(StrictBaseModel):
    subject_type: SubjectType
    subject_id: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=3, max_length=512)
    confirmation: bool = False
    sim_clock_ms: int | None = Field(default=None, ge=0)
    auto_propagate: bool = True


class RevocationEventOut(StrictBaseModel):
    event_id: str
    sequence_number: int
    event_type: str
    subject_type: SubjectType
    subject_id: str
    reason: str
    issued_by: str
    correlation_id: str
    sim_clock_ms: int
    created_at: datetime
    integrity_sha256: str


class PropagateRequest(StrictBaseModel):
    sim_clock_ms: int = Field(ge=0)
    node_ids: list[str] | None = None
    extra_delays_ms: dict[str, int] = Field(default_factory=dict)
    deliver_out_of_order: bool = False
    replay_event_id: str | None = None


class NodePropagationOutcome(StrictBaseModel):
    node_id: str
    event_id: str
    sequence_number: int
    outcome: str
    enforced_at_ms: int | None
    lag_ms: int | None


class PropagateResponse(StrictBaseModel):
    processed_count: int
    outcomes: list[NodePropagationOutcome]
    nodes: list[NodeStateOut]
    correlation_id: str


class NodeConvergenceDetail(StrictBaseModel):
    node_id: str
    service: str
    available: bool
    health: str
    sync_status: str
    enforced: bool
    enforced_at_ms: int | None
    lag_ms: int | None


class ConvergenceReportOut(StrictBaseModel):
    event_id: str
    sequence_number: int
    created_sim_clock_ms: int
    total_nodes: int
    converged_nodes: int
    unsynchronized_nodes: int
    converged: bool
    convergence_time_ms: int | None
    partial_max_lag_ms: int | None
    p50_ms: float | None
    p95_ms: float | None
    p99_ms: float | None
    per_node: list[NodeConvergenceDetail]
    correlation_id: str


class RevocationIssueResponse(StrictBaseModel):
    event: RevocationEventOut
    convergence: ConvergenceReportOut
    correlation_id: str


class NodeAccessRequest(StrictBaseModel):
    resource_id: str = Field(min_length=1, max_length=128)
    action: str = Field(default="read", min_length=1, max_length=64)
    decrypt: bool = False


class NodeAccessResponse(StrictBaseModel):
    node_id: str
    decision: Literal["ALLOW", "DENY"]
    reason_code: str
    request_id: str
    correlation_id: str
    plaintext: str | None = None


class ScenarioRunResponse(StrictBaseModel):
    scenario: str
    status: Literal["COMPLETED", "PARTIAL", "FAILED"]
    summary: str
    events: list[RevocationEventOut]
    convergence: ConvergenceReportOut | None
    access_checks: list[dict[str, str]]
    nodes: list[NodeStateOut]
    correlation_id: str
