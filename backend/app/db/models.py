"""Normalized SQLAlchemy 2 ORM models for Q-SHIELD.

Implements all 23 tables specified in Master Build Prompt Section 12 plus 2
Phase-2 normalized domain support tables (`role_permissions` and
`device_state_history`) = 25 tables total. Later-phase tables are defined here
for clean Alembic schema migration without prematurely implementing Phase 3+
business logic.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.db.base import Base


def utc_now() -> datetime:
    """Return timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Phase 2 Core Identity, RBAC, Device, Session, Resource & Policy Tables
# ---------------------------------------------------------------------------


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint(
            "role IN ('owner', 'security_operator', 'admin', 'auditor')",
            name="ck_users_role",
        ),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(256), nullable=False)
    role: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )

    devices: Mapped[list[Device]] = relationship(back_populates="owner")
    sessions: Mapped[list[UserSession]] = relationship(back_populates="actor")


class RolePermission(Base):
    """Phase 2 support table mapping RBAC roles to allowed actions/scopes."""

    __tablename__ = "role_permissions"
    __table_args__ = (
        UniqueConstraint("role", "action", "scope", name="uq_role_action_scope"),
        CheckConstraint(
            "role IN ('owner', 'security_operator', 'admin', 'auditor')",
            name="ck_role_permissions_role",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    role: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    scope: Mapped[str] = mapped_column(String(64), nullable=False, default="resource")
    description: Mapped[str] = mapped_column(String(256), nullable=False, default="")


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (
        CheckConstraint(
            "state IN ('PENDING', 'TRUSTED', 'SUSPENDED', 'REVOKED')",
            name="ck_devices_state",
        ),
        UniqueConstraint("credential_fingerprint", name="uq_devices_credential_fingerprint"),
        Index("ix_devices_owner_state", "owner_id", "state"),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    owner_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    credential_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="PENDING")
    state_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    enrolled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reason: Mapped[str | None] = mapped_column(String(512), nullable=True)
    replaced_by_device_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

    owner: Mapped[User] = relationship(back_populates="devices")
    history: Mapped[list[DeviceStateHistory]] = relationship(back_populates="device")


class DeviceStateHistory(Base):
    """Phase 2 support table recording immutable device lifecycle transitions."""

    __tablename__ = "device_state_history"
    __table_args__ = (Index("ix_device_history_device_seq", "device_id", "state_version"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True
    )
    from_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    to_state: Mapped[str] = mapped_column(String(32), nullable=False)
    state_version: Mapped[int] = mapped_column(Integer, nullable=False)
    changed_by: Mapped[str] = mapped_column(String(128), nullable=False)
    reason: Mapped[str] = mapped_column(String(512), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    device: Mapped[Device] = relationship(back_populates="history")


class UserSession(Base):
    __tablename__ = "sessions"
    __table_args__ = (
        CheckConstraint("state IN ('ACTIVE', 'EXPIRED', 'REVOKED')", name="ck_sessions_state"),
        UniqueConstraint("token_hash", name="uq_sessions_token_hash"),
        Index("ix_sessions_actor_device", "actor_id", "device_id"),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    device_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("devices.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    peer_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    auth_strength: Mapped[str] = mapped_column(String(64), nullable=False, default="synthetic_demo")
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="ACTIVE")
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoke_reason: Mapped[str | None] = mapped_column(String(512), nullable=True)

    actor: Mapped[User] = relationship(back_populates="sessions")


class Resource(Base):
    __tablename__ = "resources"
    __table_args__ = (
        CheckConstraint("state IN ('ACTIVE', 'DISABLED')", name="ck_resources_state"),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    owner_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    type: Mapped[str] = mapped_column(String(64), nullable=False, default="synthetic_document")
    metadata_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    key_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="ACTIVE")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )


class ResourcePermission(Base):
    __tablename__ = "resource_permissions"
    __table_args__ = (
        UniqueConstraint("resource_id", "subject_type", "subject_id", "permission", name="uq_res_perm"),
        CheckConstraint("subject_type IN ('actor', 'role')", name="ck_res_perm_subject_type"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    resource_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("resources.id", ondelete="CASCADE"), nullable=False, index=True
    )
    subject_type: Mapped[str] = mapped_column(String(16), nullable=False)
    subject_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    permission: Mapped[str] = mapped_column(String(64), nullable=False)
    granted_by: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class AccessRequest(Base):
    __tablename__ = "access_requests"
    __table_args__ = (
        CheckConstraint("decision IN ('ALLOW', 'DENY')", name="ck_access_requests_decision"),
        Index("ix_access_requests_actor_ts", "actor_id", "timestamp"),
    )

    request_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    actor_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    resource_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    device_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False, default="read")
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    reason: Mapped[str] = mapped_column(String(128), nullable=False)
    node: Mapped[str] = mapped_column(String(128), nullable=False, default="control-plane")
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    steps_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class KeyMetadata(Base):
    __tablename__ = "key_metadata"
    __table_args__ = (
        CheckConstraint(
            "state IN ('PREPARED', 'ACTIVE', 'ROTATING', 'ACTIVE_NEW', 'RETIRED', 'REVOKED', 'COMPROMISED')",
            name="ck_key_metadata_state",
        ),
        UniqueConstraint("purpose", "version", name="uq_key_purpose_version"),
    )

    key_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    purpose: Mapped[str] = mapped_column(String(64), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(64), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="PREPARED")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class RevocationTombstone(Base):
    __tablename__ = "revocation_tombstones"
    __table_args__ = (
        CheckConstraint("target_type IN ('actor', 'device', 'key', 'session')", name="ck_tombstone_target_type"),
        UniqueConstraint("target_type", "target_id", name="uq_tombstone_target"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_type: Mapped[str] = mapped_column(String(32), nullable=False)
    target_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    revocation_epoch: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    reason: Mapped[str] = mapped_column(String(512), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    signature_hash: Mapped[str] = mapped_column(String(128), nullable=False, default="")


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        CheckConstraint("severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')", name="ck_incidents_severity"),
        CheckConstraint("state IN ('OPEN', 'CONTAINING', 'RESOLVED', 'CLOSED')", name="ck_incidents_state"),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    type: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="OPEN")
    actor_or_target: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    blocks_access: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    reason: Mapped[str] = mapped_column(String(512), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# ---------------------------------------------------------------------------
# Phase 3–10 Schema Tables (Migrated cleanly now per 23-table specification)
# ---------------------------------------------------------------------------


class EncryptedObject(Base):
    __tablename__ = "encrypted_objects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    resource_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("resources.id", ondelete="CASCADE"), nullable=False, index=True
    )
    ciphertext_ref: Mapped[str] = mapped_column(Text, nullable=False)
    nonce: Mapped[str] = mapped_column(String(128), nullable=False)
    aead_envelope: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    integrity: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class RotationOperation(Base):
    __tablename__ = "rotation_operations"
    __table_args__ = (
        CheckConstraint(
            "phase IN ('PREPARE', 'DISTRIBUTE', 'COMMIT', 'RETIRE')",
            name="ck_rotation_phase",
        ),
        CheckConstraint(
            "status IN ('IN_PROGRESS', 'COMMITTED', 'COMPLETED', 'RECOVERED_PRE_COMMIT', 'RECOVERED_POST_COMMIT', 'FAILED_CLOSED')",
            name="ck_rotation_status",
        ),
        Index(
            "uq_active_rotation_per_purpose",
            "purpose",
            unique=True,
            sqlite_where=(text("status = 'IN_PROGRESS'")),
        ),
    )

    operation_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    purpose: Mapped[str] = mapped_column(String(64), nullable=False, index=True, default="vault_kek")
    from_key_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    to_key_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    from_version: Mapped[int] = mapped_column(Integer, nullable=False)
    to_version: Mapped[int] = mapped_column(Integer, nullable=False)
    phase: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="IN_PROGRESS")
    grace_policy: Mapped[str] = mapped_column(String(32), nullable=False, default="ZERO_GRACE")
    actor_id: Mapped[str] = mapped_column(String(128), nullable=False)
    reason: Mapped[str] = mapped_column(String(512), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    backup_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    committed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    commit_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    node_acks_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    failure_info: Mapped[str | None] = mapped_column(Text, nullable=True)
    recovery_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    journal_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class InFlightTransfer(Base):
    """Tracks explicitly identified pre-cutoff transfers for continuity policy verification."""

    __tablename__ = "in_flight_transfers"
    __table_args__ = (
        CheckConstraint(
            "state IN ('STARTED', 'COMPLETED', 'ABORTED')",
            name="ck_inflight_state",
        ),
    )

    transfer_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    actor_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    resource_id: Mapped[str] = mapped_column(String(128), nullable=False)
    key_version: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="STARTED")
    allow_post_cutoff: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class NodeRegistry(Base):
    __tablename__ = "node_registry"
    __table_args__ = (
        CheckConstraint(
            "health IN ('HEALTHY', 'DEGRADED', 'OFFLINE', 'PARTITIONED')",
            name="ck_node_registry_health",
        ),
        CheckConstraint(
            "sync_status IN ('CONVERGED', 'PENDING', 'UNSYNCHRONIZED', 'FAILED')",
            name="ck_node_registry_sync_status",
        ),
        CheckConstraint(
            "fault_mode IN ('NONE', 'OFFLINE', 'PARTITIONED', 'DROP_EVENTS', 'PROCESSING_ERROR', 'STALE_TRUST')",
            name="ck_node_registry_fault_mode",
        ),
    )

    node_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    service: Mapped[str] = mapped_column(String(128), nullable=False)
    health: Mapped[str] = mapped_column(String(32), nullable=False, default="HEALTHY")
    available: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    current_epoch: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    accepted_key_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    staged_key_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cutoff_epoch: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    latency_profile: Mapped[str] = mapped_column(String(64), nullable=False, default="nominal")
    latency_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=15)
    last_event_seq: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_applied_event_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    sync_status: Mapped[str] = mapped_column(String(32), nullable=False, default="CONVERGED")
    fault_mode: Mapped[str] = mapped_column(String(32), nullable=False, default="NONE")
    local_revocations_json: Mapped[str] = mapped_column(
        Text, nullable=False, default='{"actor":[],"device":[],"key":[],"session":[]}'
    )
    last_heartbeat: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class RevocationEvent(Base):
    """Durable ordered revocation control event broadcast to simulated nodes."""

    __tablename__ = "revocation_events"
    __table_args__ = (
        CheckConstraint(
            "subject_type IN ('actor', 'device', 'key', 'session')",
            name="ck_revocation_events_subject_type",
        ),
    )

    event_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    sequence_number: Mapped[int] = mapped_column(Integer, nullable=False, unique=True, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, default="REVOCATION_ISSUED")
    subject_type: Mapped[str] = mapped_column(String(32), nullable=False)
    subject_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    reason: Mapped[str] = mapped_column(String(512), nullable=False)
    issued_by: Mapped[str] = mapped_column(String(128), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    sim_clock_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    integrity_sha256: Mapped[str] = mapped_column(String(128), nullable=False)
    signature_b64: Mapped[str] = mapped_column(Text, nullable=False, default="")


class NodeEventInbox(Base):
    """Per-node event delivery queue and processing log."""

    __tablename__ = "node_event_inbox"
    __table_args__ = (
        CheckConstraint(
            "delivery_status IN ('QUEUED', 'DELIVERED', 'APPLIED', 'DUPLICATE_IGNORED', 'STALE_IGNORED', 'FAILED', 'DROPPED')",
            name="ck_node_inbox_status",
        ),
        Index("ix_node_inbox_node_seq", "node_id", "sequence_number"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    node_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("node_registry.node_id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("revocation_events.event_id", ondelete="CASCADE"), nullable=False, index=True
    )
    sequence_number: Mapped[int] = mapped_column(Integer, nullable=False)
    delivery_status: Mapped[str] = mapped_column(String(32), nullable=False, default="QUEUED")
    enqueued_at_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    delivered_at_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    processed_at_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    detail: Mapped[str] = mapped_column(String(512), nullable=False, default="")


class NodeAcknowledgement(Base):
    __tablename__ = "node_acknowledgements"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    operation_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    node_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("node_registry.node_id", ondelete="CASCADE"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    ack_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    enforced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    event_sequence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        CheckConstraint("sequence >= 1", name="ck_audit_events_seq_pos"),
        CheckConstraint("hash_algorithm IN ('SHA-256')", name="ck_audit_events_alg"),
        CheckConstraint("length(prev_hash) = 64 AND length(event_hash) = 64", name="ck_audit_events_hash_len"),
    )

    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False, default="CONTROL_PLANE_EVENT")
    event_category: Mapped[str] = mapped_column(String(64), nullable=False, default="GENERAL")
    timestamp_utc: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    actor_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    target_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target_id: Mapped[str] = mapped_column(String(128), nullable=False)
    decision: Mapped[str] = mapped_column(String(32), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(128), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    source_component: Mapped[str] = mapped_column(String(64), nullable=False, default="control_plane")
    payload_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    prev_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    event_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    hash_algorithm: Mapped[str] = mapped_column(String(32), nullable=False, default="SHA-256")
    schema_version: Mapped[str] = mapped_column(String(64), nullable=False, default="qshield.audit.v1")

    @property
    def outcome(self) -> str:
        return self.decision


class AuditCheckpoint(Base):
    __tablename__ = "audit_checkpoints"

    sequence: Mapped[int] = mapped_column(Integer, primary_key=True)
    checkpoint_id: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, default="")
    first_sequence: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    last_sequence: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    root_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(64), nullable=False, default="qshield.audit.checkpoint.v1")
    signature_algorithm: Mapped[str] = mapped_column(String(32), nullable=False, default="ML-DSA-65")
    signer_key_id: Mapped[str] = mapped_column(String(128), nullable=False, default="key-audit-signer-v1")
    signature_b64: Mapped[str] = mapped_column(Text, nullable=False, default="")
    signature_metadata: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_by: Mapped[str] = mapped_column(String(128), nullable=False, default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class AuditEvidenceReceipt(Base):
    """Signed ML-DSA-65 evidence receipts bound to audit events, checkpoints, or exports."""

    __tablename__ = "audit_evidence_receipts"
    __table_args__ = (
        CheckConstraint(
            "receipt_type IN ('EVENT', 'CHECKPOINT', 'EXPORT')",
            name="ck_audit_receipt_type",
        ),
    )

    receipt_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    receipt_type: Mapped[str] = mapped_column(String(32), nullable=False)
    ledger_id: Mapped[str] = mapped_column(String(128), nullable=False, default="qshield-control-plane-audit-v1")
    event_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    first_sequence: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    last_sequence: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    event_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    chain_head_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(64), nullable=False, default="qshield.audit.receipt.v1")
    signature_algorithm: Mapped[str] = mapped_column(String(32), nullable=False, default="ML-DSA-65")
    signer_key_id: Mapped[str] = mapped_column(String(128), nullable=False, default="key-audit-signer-v1")
    signature_b64: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[str] = mapped_column(String(128), nullable=False, default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class MessageRecord(Base):
    __tablename__ = "messages"
    __table_args__ = (
        CheckConstraint(
            "status IN ('QUEUED', 'IN_TRANSIT', 'DELIVERED', 'ACKED', 'EXPIRED', 'REJECTED', 'DEAD_LETTER')",
            name="ck_messages_status",
        ),
        UniqueConstraint("session_id", "nonce_b64", name="uq_messages_session_nonce"),
        UniqueConstraint("session_id", "session_generation", "sequence", name="uq_messages_session_gen_seq"),
    )

    message_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    sender_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    recipient_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    session_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    session_generation: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    key_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    nonce_b64: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    encrypted_envelope: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="QUEUED")
    ack_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CryptoSession(Base):
    __tablename__ = "sessions_crypto"
    __table_args__ = (
        CheckConstraint(
            "state IN ('NEW', 'NEGOTIATING', 'ESTABLISHED', 'SUSPENDED', 'RESUMING', 'EXPIRED', 'REVOKED', 'COMPROMISED')",
            name="ck_sessions_crypto_state",
        ),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    initiator_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True, default="")
    recipient_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True, default="")
    initiator_device_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    recipient_device_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    peer_binding: Mapped[str] = mapped_column(String(256), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="NEW")
    key_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    generation: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    send_sequence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    recv_expected_sequence: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    kem_algorithm: Mapped[str] = mapped_column(String(64), nullable=False, default="ML-KEM-768")
    aead_algorithm: Mapped[str] = mapped_column(String(64), nullable=False, default="AES-256-GCM")
    kdf_algorithm: Mapped[str] = mapped_column(String(64), nullable=False, default="HKDF-SHA-256")
    resumption_token_hash: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    resumption_counter: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ephemeral_key_erased: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    forward_secrecy_status: Mapped[str] = mapped_column(String(64), nullable=False, default="PARTIAL_LOCAL_KEYSTORE")
    protocol_state_metadata: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    suspended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class ReplayRecord(Base):
    __tablename__ = "replay_records"
    __table_args__ = (
        UniqueConstraint("recipient_id", "session_id", "sequence_or_msg_id", name="uq_replay_key"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    recipient_id: Mapped[str] = mapped_column(String(128), nullable=False)
    session_id: Mapped[str] = mapped_column(String(128), nullable=False)
    sequence_or_msg_id: Mapped[str] = mapped_column(String(128), nullable=False)
    accepted: Mapped[bool] = mapped_column(Boolean, nullable=False)
    reason_code: Mapped[str] = mapped_column(String(128), nullable=False, default="ACCEPTED")
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class MessageDelivery(Base):
    """Simulated node-relay delivery telemetry & reliability state per message."""

    __tablename__ = "message_deliveries"
    __table_args__ = (
        CheckConstraint(
            "status IN ('QUEUED', 'IN_TRANSIT', 'DROPPED', 'DELAYED', 'REORDERED', 'DISCONNECTED', 'DELIVERED', 'ACKED', 'DUPLICATE_ACK_IGNORED', 'REJECTED', 'DEAD_LETTER')",
            name="ck_msg_delivery_status",
        ),
    )

    delivery_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    message_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("messages.message_id", ondelete="CASCADE"), nullable=False, index=True
    )
    session_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    relay_node_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("node_registry.node_id", ondelete="RESTRICT"), nullable=False, index=True
    )
    simulation_mode: Mapped[str] = mapped_column(String(64), nullable=False, default="NORMAL")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="QUEUED")
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_retries: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    simulated_delay_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    delivery_order_rank: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    ack_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    duplicate_acks_ignored: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    acked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class DetectorEvent(Base):
    __tablename__ = "detector_events"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    event_source: Mapped[str] = mapped_column(String(128), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(32), nullable=False, default="v1")
    ingest_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    label: Mapped[str | None] = mapped_column(String(64), nullable=True)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")


class AlertRecord(Base):
    __tablename__ = "alerts"
    __table_args__ = (
        CheckConstraint(
            "status IN ('OPEN', 'ACKNOWLEDGED', 'RESOLVED', 'FALSE_POSITIVE')",
            name="ck_alerts_status",
        ),
    )

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    rule_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False, index=True, default="")
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[float] = mapped_column(nullable=False, default=0.8)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    actor_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    device_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    session_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    node_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    services_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    event_refs_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    reason_codes_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    recommended_response: Mapped[str] = mapped_column(Text, nullable=False, default="")
    detection_window_sec: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    run_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    resolution_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    alert_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="OPEN")


class DetectionRun(Base):
    """Persisted deterministic detection and benchmark evaluation run record."""

    __tablename__ = "detection_runs"

    run_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    dataset_name: Mapped[str] = mapped_column(String(128), nullable=False)
    dataset_version: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_set_version: Mapped[str] = mapped_column(String(32), nullable=False)
    config_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    events_inspected: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    alerts_created: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    alerts_deduplicated: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    audit_chain_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="COMPLETED")
    metrics_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    summary_detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_by: Mapped[str] = mapped_column(String(128), nullable=False, default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class BenchmarkRun(Base):
    __tablename__ = "benchmarks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    environment_metadata: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    operation: Mapped[str] = mapped_column(String(128), nullable=False)
    stats_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class BackupManifest(Base):
    __tablename__ = "backup_manifests"

    backup_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    schema_version: Mapped[str] = mapped_column(String(64), nullable=False, default="qshield.backup.v1")
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    active_epoch: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_revocation_epoch: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    tombstone_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    backup_path: Mapped[str] = mapped_column(Text, nullable=False, default="")
    integrity_auth_data: Mapped[str] = mapped_column(Text, nullable=False)
    manifest_sha256: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    signature_b64: Mapped[str] = mapped_column(Text, nullable=False, default="")
    verified_status: Mapped[str] = mapped_column(String(32), nullable=False, default="UNVERIFIED")
    created_by: Mapped[str] = mapped_column(String(128), nullable=False, default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    @property
    def verification_status(self) -> str:
        return self.verified_status

    @property
    def verified(self) -> bool:
        return self.verified_status == "VERIFIED"


class SettingEntry(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
