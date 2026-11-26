"""Deterministic 3-7 logical node simulator, inbox processing, fault injection, and fail-closed access."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import json
import math
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from backend.app.audit.ledger import append_audit_event, audit_write_lock
from backend.app.auth.dependencies import AuthContext
from backend.app.crypto.hmac_hash import sha256_hex
from backend.app.crypto.keystore import LocalEncryptedKeyStore
from backend.app.crypto.mldsa import MLDSA65Provider
from backend.app.db.models import (
    AccessRequest,
    InFlightTransfer,
    KeyMetadata,
    NodeAcknowledgement,
    NodeEventInbox,
    NodeRegistry,
    Resource,
    RevocationEvent,
    RotationOperation,
    SettingEntry,
    utc_now,
)
from backend.app.policy.engine import ZeroTrustPolicyEngine
from backend.app.schemas.nodes import (
    ConvergenceReportOut,
    NodeConvergenceDetail,
    NodePropagationOutcome,
    NodeStateOut,
)
from backend.app.schemas.policy import PolicyEvalRequest
from backend.app.vault.crypto_vault import CryptoVaultError, decrypt_resource_content

MIN_NODE_COUNT = 3
MAX_NODE_COUNT = 7
DEFAULT_LATENCIES_MS = [10, 25, 45, 70, 95, 120, 150]
DEFAULT_SERVICES = [
    "portal-gateway",
    "reports-node-a",
    "reports-node-b",
    "vault-replica-1",
    "vault-replica-2",
    "auth-edge-1",
    "audit-relay-1",
]
EMPTY_REVOCATIONS: dict[str, list[str]] = {"actor": [], "device": [], "key": [], "session": []}


class NodeSimulatorError(Exception):
    """Domain error for node simulator and convergence operations."""

    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


def parse_local_revocations(raw_json: str) -> dict[str, list[str]]:
    try:
        parsed = json.loads(raw_json)
        if isinstance(parsed, dict):
            return {
                k: [str(item) for item in parsed.get(k, [])]
                for k in ("actor", "device", "key", "session")
            }
    except ValueError:
        pass
    return {"actor": [], "device": [], "key": [], "session": []}


def serialize_local_revocations(data: dict[str, list[str]]) -> str:
    normalized = {k: sorted(set(data.get(k, []))) for k in ("actor", "device", "key", "session")}
    return json.dumps(normalized, separators=(",", ":"), sort_keys=True)


def node_to_out(node: NodeRegistry) -> NodeStateOut:
    return NodeStateOut(
        node_id=node.node_id,
        service=node.service,
        health=node.health,
        available=node.available,
        current_epoch=node.current_epoch,
        latency_profile=node.latency_profile,
        latency_ms=node.latency_ms,
        last_event_seq=node.last_event_seq,
        last_applied_event_id=node.last_applied_event_id,
        sync_status=node.sync_status,
        fault_mode=node.fault_mode,
        local_revocations=parse_local_revocations(node.local_revocations_json),
        last_heartbeat=node.last_heartbeat,
    )


def get_latest_global_sequence(db: Session) -> int:
    val = db.scalar(select(func.max(RevocationEvent.sequence_number)))
    return int(val or 0)


def compute_canonical_event_digest(event: RevocationEvent) -> str:
    canonical = json.dumps(
        {
            "event_id": event.event_id,
            "sequence_number": event.sequence_number,
            "event_type": event.event_type,
            "subject_type": event.subject_type,
            "subject_id": event.subject_id,
            "reason": event.reason,
            "issued_by": event.issued_by,
            "correlation_id": event.correlation_id,
            "sim_clock_ms": event.sim_clock_ms,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return sha256_hex(canonical)


def verify_revocation_event(db: Session, event: RevocationEvent) -> tuple[bool, str]:
    """Verify event SHA-256 integrity digest and ML-DSA-65 control-plane signature."""
    expected_digest = compute_canonical_event_digest(event)
    if expected_digest != event.integrity_sha256:
        return False, "Event SHA-256 integrity digest mismatch."

    pk_entry = db.get(SettingEntry, "revocation_signer_public_key_b64")
    if pk_entry is None or not pk_entry.value:
        return False, "Control-plane signer public key missing."
    try:
        pk_bytes = base64.b64decode(pk_entry.value, validate=True)
        sig_bytes = base64.b64decode(event.signature_b64, validate=True)
        ok = MLDSA65Provider.verify(pk_bytes, event.integrity_sha256.encode("utf-8"), sig_bytes)
        return (True, "ok") if ok else (False, "ML-DSA-65 signature verification failed.")
    except Exception:
        return False, "Malformed event signature."


def _refresh_node_sync_status(db: Session, node: NodeRegistry, latest_seq: int) -> None:
    if node.fault_mode == "PROCESSING_ERROR" or node.health == "DEGRADED":
        node.sync_status = "FAILED"
        return
    if not node.available or node.fault_mode in ("OFFLINE", "PARTITIONED"):
        node.sync_status = "UNSYNCHRONIZED"
        return
    if node.fault_mode == "STALE_TRUST":
        node.sync_status = "UNSYNCHRONIZED"
        return
    unapplied_count = (
        db.scalar(
            select(func.count())
            .select_from(NodeEventInbox)
            .where(
                NodeEventInbox.node_id == node.node_id,
                NodeEventInbox.delivery_status.in_(("QUEUED", "DROPPED", "FAILED")),
            )
        )
        or 0
    )
    if unapplied_count > 0 or node.last_event_seq < latest_seq:
        node.sync_status = "UNSYNCHRONIZED"
    else:
        node.sync_status = "CONVERGED"


def configure_nodes(
    db: Session,
    *,
    node_count: int,
    latencies_ms: list[int] | None = None,
) -> list[NodeRegistry]:
    """Configure 3-7 simulated logical nodes, resetting node registries deterministically."""
    if node_count < MIN_NODE_COUNT or node_count > MAX_NODE_COUNT:
        raise NodeSimulatorError(
            400,
            "INVALID_NODE_COUNT",
            f"Simulated node count must be between {MIN_NODE_COUNT} and {MAX_NODE_COUNT}.",
        )
    if latencies_ms is not None:
        if len(latencies_ms) != node_count or any(v < 0 for v in latencies_ms):
            raise NodeSimulatorError(400, "INVALID_LATENCIES", "Latencies list must match node_count with non-negative ints.")
        chosen_latencies = latencies_ms
    else:
        chosen_latencies = DEFAULT_LATENCIES_MS[:node_count]

    db.execute(delete(NodeAcknowledgement))
    db.execute(delete(NodeEventInbox))
    db.execute(delete(NodeRegistry))
    db.flush()

    now = utc_now()
    nodes: list[NodeRegistry] = []
    for idx in range(node_count):
        lat = chosen_latencies[idx]
        profile = "nominal" if lat <= 25 else "elevated" if lat <= 75 else "degraded"
        node = NodeRegistry(
            node_id=f"node-{idx + 1}",
            service=DEFAULT_SERVICES[idx],
            health="HEALTHY",
            available=True,
            current_epoch=0,
            latency_profile=profile,
            latency_ms=lat,
            last_event_seq=0,
            last_applied_event_id=None,
            sync_status="CONVERGED",
            fault_mode="NONE",
            local_revocations_json=serialize_local_revocations(EMPTY_REVOCATIONS),
            last_heartbeat=now,
        )
        nodes.append(node)
        db.add(node)

    # Flush new nodes before inserting child NodeEventInbox rows (FK node_registry.node_id).
    db.flush()

    # Re-enqueue any existing revocation events as QUEUED/UNSYNCHRONIZED for the new topology
    existing_events = list(
        db.scalars(select(RevocationEvent).order_by(RevocationEvent.sequence_number.asc())).all()
    )
    if existing_events:
        for node in nodes:
            node.sync_status = "UNSYNCHRONIZED"
            for ev in existing_events:
                db.add(
                    NodeEventInbox(
                        node_id=node.node_id,
                        event_id=ev.event_id,
                        sequence_number=ev.sequence_number,
                        delivery_status="QUEUED",
                        enqueued_at_ms=ev.sim_clock_ms,
                        detail="Enqueued on cluster reconfiguration",
                    )
                )

    with audit_write_lock():
        append_audit_event(
            db,
            event_type="NODES_CONFIGURED",
            event_category="NODE",
            actor_id="system",
            action="configure_nodes",
            target_type="node_cluster",
            target_id=f"{node_count}-nodes",
            outcome="ALLOW",
            reason_code="NODES_CONFIGURED_OK",
            correlation_id="corr-nodes-config",
            source_component="node_simulator",
            payload={"node_count": node_count, "latencies_ms": chosen_latencies},
            commit=False,
        )
        db.commit()
    for n in nodes:
        db.refresh(n)
    return nodes


def list_nodes(db: Session) -> list[NodeRegistry]:
    return list(db.scalars(select(NodeRegistry).order_by(NodeRegistry.node_id.asc())).all())


def get_node_or_raise(db: Session, node_id: str) -> NodeRegistry:
    node = db.get(NodeRegistry, node_id)
    if node is None:
        raise NodeSimulatorError(404, "NODE_NOT_FOUND", f"Simulated node '{node_id}' does not exist.")
    return node


def set_node_availability(
    db: Session,
    *,
    node_id: str,
    available: bool,
    fault_mode: str,
) -> NodeRegistry:
    node = get_node_or_raise(db, node_id)
    node.available = available
    node.fault_mode = fault_mode
    if not available or fault_mode == "OFFLINE":
        node.health = "OFFLINE"
        node.available = False
    elif fault_mode == "PARTITIONED":
        node.health = "PARTITIONED"
        node.available = False
    elif fault_mode == "PROCESSING_ERROR":
        node.health = "DEGRADED"
    else:
        node.health = "HEALTHY"
    node.last_heartbeat = utc_now()
    _refresh_node_sync_status(db, node, get_latest_global_sequence(db))
    with audit_write_lock():
        append_audit_event(
            db,
            event_type="NODE_AVAILABILITY_CHANGED",
            event_category="NODE",
            actor_id="system",
            action="set_node_availability",
            target_type="node",
            target_id=node.node_id,
            outcome="ALLOW",
            reason_code=f"NODE_{node.health}",
            correlation_id="corr-node-avail",
            source_component="node_simulator",
            payload={"available": node.available, "fault_mode": node.fault_mode, "sync_status": node.sync_status},
            commit=False,
        )
        db.commit()
    db.refresh(node)
    return node


def restart_node(db: Session, node_id: str) -> NodeRegistry:
    """Simulate process restart: reload persisted local revocations & sequences cleanly."""
    node = get_node_or_raise(db, node_id)
    # Persisted local_revocations_json, last_event_seq, and current_epoch are retained.
    node.available = True
    node.fault_mode = "NONE"
    node.health = "HEALTHY"
    node.last_heartbeat = utc_now()
    _refresh_node_sync_status(db, node, get_latest_global_sequence(db))
    with audit_write_lock():
        append_audit_event(
            db,
            event_type="NODE_RESTARTED",
            event_category="NODE",
            actor_id="system",
            action="restart_node",
            target_type="node",
            target_id=node.node_id,
            outcome="ALLOW",
            reason_code=f"NODE_RESTART_{node.sync_status}",
            correlation_id="corr-node-restart",
            source_component="node_simulator",
            payload={"last_event_seq": node.last_event_seq, "sync_status": node.sync_status},
            commit=False,
        )
        db.commit()
    db.refresh(node)
    return node


def process_single_event_on_node(
    db: Session,
    node: NodeRegistry,
    event: RevocationEvent,
    *,
    sim_clock_ms: int,
    extra_delay_ms: int = 0,
    inbox_row: NodeEventInbox | None = None,
    force_out_of_order_rollback_check: bool = False,
) -> NodePropagationOutcome:
    """Independently verify and process one revocation event on a single simulated node."""
    latest_seq = get_latest_global_sequence(db)

    def _update_inbox(status: str, detail: str, delivered_ms: int | None, processed_ms: int | None) -> None:
        if inbox_row is not None:
            inbox_row.delivery_status = status
            inbox_row.delivered_at_ms = delivered_ms
            inbox_row.processed_at_ms = processed_ms
            inbox_row.detail = detail
        else:
            db.add(
                NodeEventInbox(
                    node_id=node.node_id,
                    event_id=event.event_id,
                    sequence_number=event.sequence_number,
                    delivery_status=status,
                    enqueued_at_ms=event.sim_clock_ms,
                    delivered_at_ms=delivered_ms,
                    processed_at_ms=processed_ms,
                    detail=detail,
                )
            )

    # 1. Unavailable / partitioned nodes cannot receive or acknowledge the event
    if not node.available or node.fault_mode in ("OFFLINE", "PARTITIONED"):
        _refresh_node_sync_status(db, node, latest_seq)
        return NodePropagationOutcome(
            node_id=node.node_id,
            event_id=event.event_id,
            sequence_number=event.sequence_number,
            outcome="DEFERRED_OFFLINE",
            enforced_at_ms=None,
            lag_ms=None,
        )

    # 2. Simulated event drop (node never receives event)
    if node.fault_mode == "DROP_EVENTS":
        _update_inbox("DROPPED", "Simulated network drop prevented delivery.", None, None)
        _refresh_node_sync_status(db, node, latest_seq)
        return NodePropagationOutcome(
            node_id=node.node_id,
            event_id=event.event_id,
            sequence_number=event.sequence_number,
            outcome="DROPPED",
            enforced_at_ms=None,
            lag_ms=None,
        )

    # 3. Simulated processing error
    if node.fault_mode == "PROCESSING_ERROR":
        _update_inbox("FAILED", "Simulated node processing failure.", sim_clock_ms, None)
        node.health = "DEGRADED"
        node.sync_status = "FAILED"
        return NodePropagationOutcome(
            node_id=node.node_id,
            event_id=event.event_id,
            sequence_number=event.sequence_number,
            outcome="FAILED_PROCESSING",
            enforced_at_ms=None,
            lag_ms=None,
        )

    # 4. Integrity & ML-DSA-65 signature verification
    sig_ok, sig_detail = verify_revocation_event(db, event)
    if not sig_ok:
        _update_inbox("FAILED", sig_detail, sim_clock_ms, None)
        node.health = "DEGRADED"
        node.sync_status = "FAILED"
        return NodePropagationOutcome(
            node_id=node.node_id,
            event_id=event.event_id,
            sequence_number=event.sequence_number,
            outcome="FAILED_SIGNATURE",
            enforced_at_ms=None,
            lag_ms=None,
        )

    # 5. Out-of-order check: never roll back epoch/sequence or drop newer revocations
    if force_out_of_order_rollback_check and event.sequence_number < node.last_event_seq:
        _update_inbox(
            "STALE_IGNORED",
            f"Stale sequence {event.sequence_number} < node seq {node.last_event_seq}; no rollback.",
            sim_clock_ms,
            sim_clock_ms,
        )
        db.flush()
        _refresh_node_sync_status(db, node, latest_seq)
        return NodePropagationOutcome(
            node_id=node.node_id,
            event_id=event.event_id,
            sequence_number=event.sequence_number,
            outcome="STALE_IGNORED",
            enforced_at_ms=None,
            lag_ms=None,
        )

    # 6. Duplicate delivery check (idempotency)
    existing_ack = db.scalar(
        select(NodeAcknowledgement).where(
            NodeAcknowledgement.operation_id == event.event_id,
            NodeAcknowledgement.node_id == node.node_id,
            NodeAcknowledgement.status == "ENFORCED",
        )
    )
    if existing_ack is not None:
        _update_inbox("DUPLICATE_IGNORED", "Duplicate delivery ignored idempotently.", sim_clock_ms, sim_clock_ms)
        db.flush()
        _refresh_node_sync_status(db, node, latest_seq)
        return NodePropagationOutcome(
            node_id=node.node_id,
            event_id=event.event_id,
            sequence_number=event.sequence_number,
            outcome="DUPLICATE_IGNORED",
            enforced_at_ms=None,
            lag_ms=None,
        )

    # 7. Apply revocation monotonically to node-local state
    local_rev = parse_local_revocations(node.local_revocations_json)
    bucket = local_rev.setdefault(event.subject_type, [])
    if event.subject_id not in bucket:
        bucket.append(event.subject_id)
    node.local_revocations_json = serialize_local_revocations(local_rev)

    if event.sequence_number > node.last_event_seq:
        node.last_event_seq = event.sequence_number
        node.current_epoch = event.sequence_number
        node.last_applied_event_id = event.event_id

    enforced_ms = max(sim_clock_ms, event.sim_clock_ms) + node.latency_ms + max(0, extra_delay_ms)
    lag_ms = enforced_ms - event.sim_clock_ms

    ack_dt = event.created_at + timedelta(milliseconds=lag_ms)
    db.add(
        NodeAcknowledgement(
            operation_id=event.event_id,
            node_id=node.node_id,
            status="ENFORCED",
            ack_at=ack_dt,
            enforced_at=ack_dt,
            event_sequence=event.sequence_number,
        )
    )
    _update_inbox("APPLIED", f"Enforced at +{lag_ms}ms", max(sim_clock_ms, event.sim_clock_ms), enforced_ms)
    node.last_heartbeat = utc_now()
    db.flush()
    _refresh_node_sync_status(db, node, latest_seq)

    return NodePropagationOutcome(
        node_id=node.node_id,
        event_id=event.event_id,
        sequence_number=event.sequence_number,
        outcome="APPLIED",
        enforced_at_ms=enforced_ms,
        lag_ms=lag_ms,
    )


def propagate_pending_events(
    db: Session,
    *,
    sim_clock_ms: int,
    node_ids: list[str] | None = None,
    extra_delays_ms: dict[str, int] | None = None,
    deliver_out_of_order: bool = False,
    replay_event_id: str | None = None,
) -> list[NodePropagationOutcome]:
    """Run one deterministic propagation cycle across queued/replayable node inbox entries."""
    nodes = list_nodes(db)
    if node_ids is not None:
        target_set = set(node_ids)
        nodes = [n for n in nodes if n.node_id in target_set]
    delays = extra_delays_ms or {}
    outcomes: list[NodePropagationOutcome] = []

    if replay_event_id is not None:
        event = db.get(RevocationEvent, replay_event_id)
        if event is None:
            raise NodeSimulatorError(404, "EVENT_NOT_FOUND", f"Revocation event '{replay_event_id}' not found.")
        for node in nodes:
            outcomes.append(
                process_single_event_on_node(
                    db,
                    node,
                    event,
                    sim_clock_ms=sim_clock_ms,
                    extra_delay_ms=delays.get(node.node_id, 0),
                    inbox_row=None,
                    force_out_of_order_rollback_check=deliver_out_of_order,
                )
            )
        db.commit()
        return outcomes

    for node in nodes:
        order_col = (
            NodeEventInbox.sequence_number.desc()
            if deliver_out_of_order
            else NodeEventInbox.sequence_number.asc()
        )
        pending_items = list(
            db.scalars(
                select(NodeEventInbox)
                .where(
                    NodeEventInbox.node_id == node.node_id,
                    NodeEventInbox.delivery_status.in_(("QUEUED", "DROPPED")),
                )
                .order_by(order_col, NodeEventInbox.id.asc())
            ).all()
        )
        for item in pending_items:
            event = db.get(RevocationEvent, item.event_id)
            if event is None:
                continue
            outcomes.append(
                process_single_event_on_node(
                    db,
                    node,
                    event,
                    sim_clock_ms=sim_clock_ms,
                    extra_delay_ms=delays.get(node.node_id, 0),
                    inbox_row=item,
                    force_out_of_order_rollback_check=False,
                )
            )
        _refresh_node_sync_status(db, node, get_latest_global_sequence(db))

    with audit_write_lock():
        append_audit_event(
            db,
            event_type="REVOCATION_PROPAGATION",
            event_category="NODE",
            actor_id="system",
            action="propagate_pending_events",
            target_type="node_cluster",
            target_id="all_nodes",
            outcome="ALLOW",
            reason_code="PROPAGATION_PROCESSED",
            correlation_id="corr-node-propagate",
            source_component="node_simulator",
            payload={
                "processed_count": len(outcomes),
                "sim_clock_ms": sim_clock_ms,
                "outcomes": [
                    {"node_id": o.node_id, "event_id": o.event_id, "outcome": o.outcome}
                    for o in outcomes[:25]
                ],
            },
            commit=False,
        )
        db.commit()
    return outcomes


def _percentile(sorted_vals: list[int], pct: float) -> float | None:
    if not sorted_vals:
        return None
    if len(sorted_vals) == 1:
        return float(sorted_vals[0])
    idx = (len(sorted_vals) - 1) * (pct / 100.0)
    lo = int(math.floor(idx))
    hi = int(math.ceil(idx))
    if lo == hi:
        return float(sorted_vals[lo])
    frac = idx - lo
    return round(sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * frac, 2)


def measure_event_convergence(
    db: Session,
    event_id: str,
    *,
    correlation_id: str = "corr-convergence",
) -> ConvergenceReportOut:
    """Measure per-node enforcement and convergence_time_ms = last_enforced_at - created_sim_clock."""
    event = db.get(RevocationEvent, event_id)
    if event is None:
        raise NodeSimulatorError(404, "EVENT_NOT_FOUND", f"Revocation event '{event_id}' not found.")

    nodes = list_nodes(db)
    acks = {
        ack.node_id: ack
        for ack in db.scalars(
            select(NodeAcknowledgement).where(
                NodeAcknowledgement.operation_id == event_id,
                NodeAcknowledgement.status == "ENFORCED",
            )
        ).all()
    }

    per_node: list[NodeConvergenceDetail] = []
    lags: list[int] = []
    converged_count = 0

    for node in nodes:
        ack = acks.get(node.node_id)
        local_rev = parse_local_revocations(node.local_revocations_json)
        has_local_rev = event.subject_id in local_rev.get(event.subject_type, [])
        enforced = ack is not None and has_local_rev

        enforced_ms: int | None = None
        lag_ms: int | None = None
        if enforced and ack is not None and ack.enforced_at is not None:
            dt_ev = event.created_at.replace(tzinfo=timezone.utc) if event.created_at.tzinfo is None else event.created_at
            dt_enf = ack.enforced_at.replace(tzinfo=timezone.utc) if ack.enforced_at.tzinfo is None else ack.enforced_at
            lag_ms = int(round((dt_enf - dt_ev).total_seconds() * 1000))
            enforced_ms = event.sim_clock_ms + lag_ms
            lags.append(lag_ms)
            converged_count += 1

        per_node.append(
            NodeConvergenceDetail(
                node_id=node.node_id,
                service=node.service,
                available=node.available,
                health=node.health,
                sync_status=node.sync_status,
                enforced=enforced,
                enforced_at_ms=enforced_ms,
                lag_ms=lag_ms,
            )
        )

    total = len(nodes)
    fully_converged = total >= MIN_NODE_COUNT and converged_count == total
    sorted_lags = sorted(lags)
    partial_max = max(sorted_lags) if sorted_lags else None

    return ConvergenceReportOut(
        event_id=event.event_id,
        sequence_number=event.sequence_number,
        created_sim_clock_ms=event.sim_clock_ms,
        total_nodes=total,
        converged_nodes=converged_count,
        unsynchronized_nodes=total - converged_count,
        converged=fully_converged,
        convergence_time_ms=partial_max if fully_converged else None,
        partial_max_lag_ms=partial_max,
        p50_ms=_percentile(sorted_lags, 50.0),
        p95_ms=_percentile(sorted_lags, 95.0),
        p99_ms=_percentile(sorted_lags, 99.0),
        per_node=per_node,
        correlation_id=correlation_id,
    )


_policy_engine = ZeroTrustPolicyEngine()


def node_evaluate_access(
    db: Session,
    keystore: LocalEncryptedKeyStore,
    *,
    node_id: str,
    ctx: AuthContext,
    resource_id: str,
    action: str = "read",
    decrypt: bool = False,
    transfer_id: str | None = None,
) -> tuple[str, str, str, str | None]:
    """Evaluate protected access at a specific simulated node, failing closed on stale/offline state."""
    node = db.get(NodeRegistry, node_id)
    if node is None:
        return "DENY", "DENY_NODE_NOT_FOUND", "req-node-missing", None

    def _record_node_denial(code: str) -> tuple[str, str, str, str | None]:
        req_id = f"req-node-{node.node_id}-{int(utc_now().timestamp() * 1000)}"
        with audit_write_lock():
            db.add(
                AccessRequest(
                    request_id=req_id,
                    actor_id=ctx.user.id,
                    resource_id=resource_id,
                    device_id=ctx.device.id,
                    action=action,
                    decision="DENY",
                    reason=code,
                    node=node.node_id,
                    correlation_id=ctx.correlation_id,
                    steps_json=json.dumps([{"node": node.node_id, "reason_code": code}]),
                )
            )
            append_audit_event(
                db,
                event_type="STALE_NODE_DENIAL" if "STALE" in code else ("OLD_KEY_CUTOFF_DENIAL" if "CUTOFF" in code else "NODE_ACCESS_DENIED"),
                event_category="NODE",
                actor_id=ctx.user.id,
                action=f"node_access:{action}",
                target_type="resource",
                target_id=resource_id,
                outcome="DENY",
                reason_code=code,
                correlation_id=ctx.correlation_id,
                source_component="node_simulator",
                payload={"node_id": node.node_id, "sync_status": node.sync_status, "cutoff_epoch": node.cutoff_epoch},
                commit=False,
            )
            db.commit()
        return "DENY", code, req_id, None

    # 1. Unavailable / unhealthy / faulty nodes MUST fail closed
    if not node.available or node.health != "HEALTHY" or node.fault_mode != "NONE":
        return _record_node_denial("DENY_NODE_UNAVAILABLE")

    # 2. Check node-local revocations FIRST
    local_rev = parse_local_revocations(node.local_revocations_json)
    if ctx.user.id in local_rev["actor"]:
        return _record_node_denial("DENY_NODE_LOCAL_REVOKED_ACTOR")
    if ctx.device.id in local_rev["device"]:
        return _record_node_denial("DENY_NODE_LOCAL_REVOKED_DEVICE")
    if ctx.session.id in local_rev["session"]:
        return _record_node_denial("DENY_NODE_LOCAL_REVOKED_SESSION")

    resource = db.get(Resource, resource_id)
    if resource is not None:
        key_ids = list(
            db.scalars(select(KeyMetadata.key_id).where(KeyMetadata.version == resource.key_version)).all()
        )
        if any(kid in local_rev["key"] for kid in key_ids) or f"version:{resource.key_version}" in local_rev["key"]:
            return _record_node_denial("DENY_NODE_LOCAL_REVOKED_KEY")

        # 2b. Old-key cutoff enforcement across every simulated node
        if node.cutoff_epoch > 0 and resource.key_version < node.cutoff_epoch:
            transfer_allowed = False
            if transfer_id:
                transfer = db.get(InFlightTransfer, transfer_id)
                latest_rot = db.scalar(
                    select(RotationOperation)
                    .where(RotationOperation.purpose == "vault_kek")
                    .order_by(RotationOperation.created_at.desc())
                )
                if (
                    transfer is not None
                    and transfer.state == "STARTED"
                    and transfer.allow_post_cutoff
                    and transfer.actor_id == ctx.user.id
                    and transfer.resource_id == resource.id
                    and transfer.key_version == resource.key_version
                    and latest_rot is not None
                    and latest_rot.grace_policy == "CONTROLLED_IN_FLIGHT_ONLY"
                ):
                    transfer_allowed = True
            if not transfer_allowed:
                return _record_node_denial("DENY_NODE_OLD_KEY_CUTOFF")

        if resource.key_version > node.accepted_key_version:
            return _record_node_denial("DENY_NODE_KEY_NOT_ACCEPTED")

    # 3. Stale trust state / unsynchronized node MUST fail closed (never silently allow)
    latest_seq = get_latest_global_sequence(db)
    if node.sync_status != "CONVERGED" or node.last_event_seq < latest_seq:
        return _record_node_denial("DENY_NODE_STALE_TRUST_STATE")

    # 4. Run full 10-step central zero-trust policy evaluation
    decision = _policy_engine.evaluate(
        db,
        PolicyEvalRequest(
            actor_id=ctx.user.id,
            session_id=ctx.session.id,
            device_id=ctx.device.id,
            resource_id=resource_id,
            action=action,
        ),
        correlation_id=ctx.correlation_id,
    )
    if decision.decision != "ALLOW":
        return "DENY", decision.reason_code, decision.request_id, None

    # 5. Optional Phase 3 AEAD decryption only after all node + policy checks pass
    plaintext: str | None = None
    if decrypt:
        try:
            plaintext, _enc, _req = decrypt_resource_content(
                db, keystore, ctx=ctx, resource_id=resource_id
            )
        except CryptoVaultError as exc:
            return "DENY", exc.code, decision.request_id, None

    return "ALLOW", decision.reason_code, decision.request_id, plaintext


def list_ordered_nodes(db: Session) -> list[NodeRegistry]:
    """Return all registered simulated nodes in deterministic order."""
    return list(db.scalars(select(NodeRegistry).order_by(NodeRegistry.node_id)).all())


def stage_key_on_nodes(
    db: Session,
    *,
    operation_id: str,
    target_version: int,
    max_ack_nodes: int | None = None,
) -> dict[str, str]:
    """Stage new key version across nodes during DISTRIBUTE and record per-node acks.

    If ``max_ack_nodes`` is specified (deterministic crash simulation), only that
    many healthy nodes acknowledge before the caller injects a crash; the rest
    remain ``PENDING``. Offline/faulty nodes record ``DEFERRED``.
    """
    nodes = list_ordered_nodes(db)
    acks: dict[str, str] = {}
    acked_count = 0
    now = utc_now()
    for node in nodes:
        if not node.available or node.fault_mode != "NONE" or node.health != "HEALTHY":
            acks[node.node_id] = "DEFERRED"
            status = "DEFERRED"
        elif max_ack_nodes is not None and acked_count >= max_ack_nodes:
            acks[node.node_id] = "PENDING"
            status = "PENDING"
        else:
            node.staged_key_version = target_version
            node.last_heartbeat = now
            acks[node.node_id] = "ACKED"
            status = "ACKED"
            acked_count += 1

        existing_ack = db.scalar(
            select(NodeAcknowledgement).where(
                NodeAcknowledgement.operation_id == operation_id,
                NodeAcknowledgement.node_id == node.node_id,
            )
        )
        if existing_ack is None:
            db.add(
                NodeAcknowledgement(
                    operation_id=operation_id,
                    node_id=node.node_id,
                    status=status,
                    ack_at=now if status == "ACKED" else None,
                    enforced_at=None,
                    event_sequence=node.last_event_seq,
                )
            )
        else:
            existing_ack.status = status
            existing_ack.ack_at = now if status == "ACKED" else existing_ack.ack_at
            existing_ack.event_sequence = node.last_event_seq
    db.flush()
    return acks


def commit_cutoff_on_nodes(
    db: Session,
    *,
    operation_id: str,
    new_version: int,
    cutoff_epoch: int,
) -> dict[str, str]:
    """Enforce new accepted key version and old-key cutoff epoch on all nodes."""
    nodes = list_ordered_nodes(db)
    acks: dict[str, str] = {}
    now = utc_now()
    for node in nodes:
        if not node.available or node.fault_mode != "NONE" or node.health != "HEALTHY":
            # Keep offline/faulty node fail-closed by leaving it un-cut-over until recovery/resync,
            # while recording DEFERRED_CUTOFF or enforcing cutoff if node was partitioned.
            # Actually: advancing cutoff_epoch guarantees fail-closed on old keys once restored,
            # while accepted_key_version stays un-updated until node reconciles.
            node.cutoff_epoch = max(node.cutoff_epoch, cutoff_epoch)
            acks[node.node_id] = "DEFERRED_CUTOFF"
            status = "DEFERRED"
        else:
            node.staged_key_version = None
            node.accepted_key_version = new_version
            node.cutoff_epoch = max(node.cutoff_epoch, cutoff_epoch)
            node.current_epoch = max(node.current_epoch, new_version)
            node.last_heartbeat = now
            acks[node.node_id] = "ENFORCED"
            status = "ENFORCED"

        existing_ack = db.scalar(
            select(NodeAcknowledgement).where(
                NodeAcknowledgement.operation_id == operation_id,
                NodeAcknowledgement.node_id == node.node_id,
            )
        )
        if existing_ack is None:
            db.add(
                NodeAcknowledgement(
                    operation_id=operation_id,
                    node_id=node.node_id,
                    status=status,
                    ack_at=now if status == "ENFORCED" else None,
                    enforced_at=now if status == "ENFORCED" else None,
                    event_sequence=node.last_event_seq,
                )
            )
        else:
            existing_ack.status = status
            if status == "ENFORCED":
                existing_ack.ack_at = existing_ack.ack_at or now
                existing_ack.enforced_at = now
            existing_ack.event_sequence = node.last_event_seq
    db.flush()
    return acks


def rollback_staged_key_on_nodes(
    db: Session,
    *,
    operation_id: str,
    restore_version: int,
) -> dict[str, str]:
    """Clear staged key versions on nodes during pre-commit crash rollback."""
    nodes = list_ordered_nodes(db)
    acks: dict[str, str] = {}
    now = utc_now()
    for node in nodes:
        node.staged_key_version = None
        if node.accepted_key_version > restore_version and node.cutoff_epoch <= restore_version:
            node.accepted_key_version = restore_version
        node.last_heartbeat = now
        acks[node.node_id] = "ROLLED_BACK"
        existing_ack = db.scalar(
            select(NodeAcknowledgement).where(
                NodeAcknowledgement.operation_id == operation_id,
                NodeAcknowledgement.node_id == node.node_id,
            )
        )
        if existing_ack is not None:
            existing_ack.status = "ROLLED_BACK"
    db.flush()
    return acks
