"""Pydantic v2 schemas for Phase 8 End-to-End Secure Messaging & Session Resumption."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class SessionEstablishRequest(BaseModel):
    recipient_id: str = Field(..., min_length=1, max_length=128)
    recipient_device_id: str = Field(..., min_length=1, max_length=128)
    ttl_seconds: int = Field(default=3600, ge=30, le=86400)
    recipient_kem_public_key_b64: str | None = Field(default=None, max_length=4096)


class SessionTransitionRequest(BaseModel):
    reason: str = Field(..., min_length=3, max_length=512)
    confirmation: bool = Field(...)
    compromised: bool = False


class SessionResumeRequest(BaseModel):
    peer_id: str = Field(..., min_length=1, max_length=128)
    resumption_token: str = Field(..., min_length=16, max_length=2048)


class CryptoSessionOut(BaseModel):
    id: str
    initiator_id: str
    recipient_id: str
    initiator_device_id: str
    recipient_device_id: str
    peer_binding: str
    state: str
    key_version: int
    generation: int
    send_sequence: int
    recv_expected_sequence: int
    kem_algorithm: str
    aead_algorithm: str
    kdf_algorithm: str
    resumption_counter: int
    ephemeral_key_erased: bool
    forward_secrecy_status: str
    expires_at: datetime
    suspended_at: datetime | None = None
    resumed_at: datetime | None = None
    revoked_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class SessionEstablishResponse(BaseModel):
    session: CryptoSessionOut
    resumption_token: str
    kem_ciphertext_b64: str
    forward_secrecy_note: str
    correlation_id: str


class SessionResumeResponse(BaseModel):
    session: CryptoSessionOut
    next_resumption_token: str
    kem_ciphertext_b64: str
    correlation_id: str


class MessageSendRequest(BaseModel):
    session_id: str = Field(..., min_length=1, max_length=128)
    plaintext: str = Field(..., min_length=1, max_length=32768)
    ttl_seconds: int = Field(default=300, ge=1, le=86400)
    relay_node_id: str | None = Field(default=None, max_length=128)


class MessageDeliveryOut(BaseModel):
    delivery_id: str
    message_id: str
    session_id: str
    sequence: int
    relay_node_id: str
    simulation_mode: str
    status: str
    attempt_count: int
    max_retries: int
    simulated_delay_ms: int
    delivery_order_rank: int
    ack_count: int
    duplicate_acks_ignored: int
    last_error_code: str | None = None
    detail: str
    created_at: datetime
    updated_at: datetime
    acked_at: datetime | None = None


class MessageMetadataOut(BaseModel):
    message_id: str
    sender_id: str
    recipient_id: str
    session_id: str
    sequence: int
    session_generation: int
    key_version: int
    nonce_b64: str
    status: str
    ack_count: int
    encrypted_envelope: dict[str, Any]
    expires_at: datetime
    created_at: datetime
    delivered_at: datetime | None = None
    acknowledged_at: datetime | None = None


class MessageSendResponse(BaseModel):
    message: MessageMetadataOut
    delivery: MessageDeliveryOut
    correlation_id: str


class MessageReceiveRequest(BaseModel):
    message_id: str = Field(..., min_length=1, max_length=128)


class MessageReceiveResponse(BaseModel):
    message: MessageMetadataOut
    plaintext: str
    per_message_key_erased: bool
    correlation_id: str


class MessageVerifyOut(BaseModel):
    message_id: str
    session_id: str
    sender_id: str
    recipient_id: str
    key_version: int
    sequence: int
    aad_valid: bool
    already_consumed: bool
    verified: bool
    failure_reasons: list[str]
    correlation_id: str


class MessageAckResponse(BaseModel):
    message: MessageMetadataOut
    delivery: MessageDeliveryOut
    duplicate_ack_ignored: bool
    correlation_id: str


class SimulateLossRequest(BaseModel):
    drop_attempts: int = Field(default=1, ge=0, le=20)
    max_retries: int = Field(default=3, ge=1, le=20)
    delay_ms: int = Field(default=0, ge=0, le=30000)
    disconnect_node_first: bool = False
    reconnect_after: bool = False


class SimulateReorderRequest(BaseModel):
    message_ids_arrival_order: list[str] = Field(..., min_length=1, max_length=32)


class SimulateReorderResponse(BaseModel):
    arrival_order: list[str]
    delivered_order: list[str]
    discarded: list[dict[str, str]]
    correlation_id: str


class ReplayRecordOut(BaseModel):
    id: int
    recipient_id: str
    session_id: str
    sequence_or_msg_id: str
    accepted: bool
    reason_code: str
    attempt_count: int
    recorded_at: datetime
    expires_at: datetime
