"""Simulated node cluster, revocation event broadcast, convergence, and node access routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.auth.dependencies import AuthContext, get_auth_context, require_permission
from backend.app.crypto.keystore import LocalEncryptedKeyStore, get_keystore
from backend.app.db.models import NodeEventInbox, RevocationEvent
from backend.app.db.session import get_db
from backend.app.nodes.simulator import (
    NodeSimulatorError,
    configure_nodes,
    get_latest_global_sequence,
    get_node_or_raise,
    list_nodes,
    measure_event_convergence,
    node_evaluate_access,
    node_to_out,
    propagate_pending_events,
    restart_node,
    set_node_availability,
)
from backend.app.revocation.coordinator import issue_revocation_event
from backend.app.schemas.common import PaginatedResponse
from backend.app.schemas.nodes import (
    ConvergenceReportOut,
    NodeAccessRequest,
    NodeAccessResponse,
    NodeAvailabilityRequest,
    NodeConfigureRequest,
    NodeInboxItemOut,
    NodeStateOut,
    NodeSyncStateOut,
    PropagateRequest,
    PropagateResponse,
    RevocationEventOut,
    RevocationIssueRequest,
    RevocationIssueResponse,
    ScenarioRunResponse,
)

router = APIRouter(tags=["nodes", "revocations"])


def _handle_sim_error(exc: NodeSimulatorError, corr_id: str) -> HTTPException:
    return HTTPException(
        status_code=exc.status_code,
        detail={"code": exc.code, "message": exc.message, "correlation_id": corr_id},
    )


@router.get("/nodes", response_model=list[NodeStateOut])
def get_nodes(
    _ctx: AuthContext = Depends(require_permission("node:read")),
    db: Session = Depends(get_db),
) -> list[NodeStateOut]:
    return [node_to_out(n) for n in list_nodes(db)]


@router.get("/nodes/{node_id}", response_model=NodeStateOut)
def get_node(
    node_id: str,
    ctx: AuthContext = Depends(require_permission("node:read")),
    db: Session = Depends(get_db),
) -> NodeStateOut:
    try:
        node = get_node_or_raise(db, node_id)
    except NodeSimulatorError as exc:
        raise _handle_sim_error(exc, ctx.correlation_id) from None
    return node_to_out(node)


@router.get("/nodes/{node_id}/sync", response_model=NodeSyncStateOut)
def get_node_sync(
    node_id: str,
    ctx: AuthContext = Depends(require_permission("node:read")),
    db: Session = Depends(get_db),
) -> NodeSyncStateOut:
    try:
        node = get_node_or_raise(db, node_id)
    except NodeSimulatorError as exc:
        raise _handle_sim_error(exc, ctx.correlation_id) from None
    inbox = list(
        db.scalars(
            select(NodeEventInbox)
            .where(NodeEventInbox.node_id == node_id)
            .order_by(NodeEventInbox.id.desc())
            .limit(100)
        ).all()
    )
    pending_count = sum(1 for item in inbox if item.delivery_status in ("QUEUED", "DROPPED", "FAILED"))
    return NodeSyncStateOut(
        node=node_to_out(node),
        latest_global_sequence=get_latest_global_sequence(db),
        pending_inbox_count=pending_count,
        inbox=[NodeInboxItemOut.model_validate(i) for i in inbox],
        correlation_id=ctx.correlation_id,
    )


@router.post("/nodes/configure", response_model=list[NodeStateOut])
def post_configure_nodes(
    payload: NodeConfigureRequest,
    ctx: AuthContext = Depends(require_permission("node:manage")),
    db: Session = Depends(get_db),
) -> list[NodeStateOut]:
    try:
        nodes = configure_nodes(db, node_count=payload.node_count, latencies_ms=payload.latencies_ms)
    except NodeSimulatorError as exc:
        raise _handle_sim_error(exc, ctx.correlation_id) from None
    return [node_to_out(n) for n in nodes]


@router.post("/nodes/{node_id}/availability", response_model=NodeStateOut)
def post_node_availability(
    node_id: str,
    payload: NodeAvailabilityRequest,
    ctx: AuthContext = Depends(require_permission("node:manage")),
    db: Session = Depends(get_db),
) -> NodeStateOut:
    try:
        node = set_node_availability(
            db,
            node_id=node_id,
            available=payload.available,
            fault_mode=payload.fault_mode,
        )
    except NodeSimulatorError as exc:
        raise _handle_sim_error(exc, ctx.correlation_id) from None
    return node_to_out(node)


@router.post("/nodes/{node_id}/restart", response_model=NodeStateOut)
def post_node_restart(
    node_id: str,
    ctx: AuthContext = Depends(require_permission("node:manage")),
    db: Session = Depends(get_db),
) -> NodeStateOut:
    try:
        node = restart_node(db, node_id)
    except NodeSimulatorError as exc:
        raise _handle_sim_error(exc, ctx.correlation_id) from None
    return node_to_out(node)


@router.post("/nodes/propagate", response_model=PropagateResponse)
def post_propagate(
    payload: PropagateRequest,
    ctx: AuthContext = Depends(require_permission("node:manage")),
    db: Session = Depends(get_db),
) -> PropagateResponse:
    try:
        outcomes = propagate_pending_events(
            db,
            sim_clock_ms=payload.sim_clock_ms,
            node_ids=payload.node_ids,
            extra_delays_ms=payload.extra_delays_ms,
            deliver_out_of_order=payload.deliver_out_of_order,
            replay_event_id=payload.replay_event_id,
        )
    except NodeSimulatorError as exc:
        raise _handle_sim_error(exc, ctx.correlation_id) from None
    return PropagateResponse(
        processed_count=len(outcomes),
        outcomes=outcomes,
        nodes=[node_to_out(n) for n in list_nodes(db)],
        correlation_id=ctx.correlation_id,
    )


@router.post("/nodes/{node_id}/access", response_model=NodeAccessResponse)
def post_node_access(
    node_id: str,
    payload: NodeAccessRequest,
    ctx: AuthContext = Depends(get_auth_context),
    db: Session = Depends(get_db),
    keystore: LocalEncryptedKeyStore = Depends(get_keystore),
) -> NodeAccessResponse:
    decision, reason_code, req_id, plaintext = node_evaluate_access(
        db,
        keystore,
        node_id=node_id,
        ctx=ctx,
        resource_id=payload.resource_id,
        action=payload.action,
        decrypt=payload.decrypt,
    )
    if decision != "ALLOW":
        raise HTTPException(
            status_code=403,
            detail={
                "code": reason_code,
                "message": f"Access denied at simulated node '{node_id}'.",
                "correlation_id": ctx.correlation_id,
            },
        )
    return NodeAccessResponse(
        node_id=node_id,
        decision="ALLOW",
        reason_code=reason_code,
        request_id=req_id,
        correlation_id=ctx.correlation_id,
        plaintext=plaintext,
    )


@router.post("/revocations", response_model=RevocationIssueResponse, status_code=201)
def post_issue_revocation(
    payload: RevocationIssueRequest,
    ctx: AuthContext = Depends(require_permission("revocation:issue")),
    db: Session = Depends(get_db),
    keystore: LocalEncryptedKeyStore = Depends(get_keystore),
) -> RevocationIssueResponse:
    try:
        event, convergence = issue_revocation_event(
            db,
            keystore,
            subject_type=payload.subject_type,
            subject_id=payload.subject_id,
            reason=payload.reason,
            confirmation=payload.confirmation,
            acting_user=ctx.user,
            correlation_id=ctx.correlation_id,
            sim_clock_ms=payload.sim_clock_ms,
            auto_propagate=payload.auto_propagate,
        )
    except NodeSimulatorError as exc:
        raise _handle_sim_error(exc, ctx.correlation_id) from None
    return RevocationIssueResponse(
        event=RevocationEventOut.model_validate(event),
        convergence=convergence,
        correlation_id=ctx.correlation_id,
    )


@router.get("/revocations/events", response_model=PaginatedResponse[RevocationEventOut])
def get_revocation_events(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    ctx: AuthContext = Depends(require_permission("node:read")),
    db: Session = Depends(get_db),
) -> PaginatedResponse[RevocationEventOut]:
    from sqlalchemy import func

    total = int(db.scalar(select(func.count()).select_from(RevocationEvent)) or 0)
    events = list(
        db.scalars(
            select(RevocationEvent)
            .order_by(RevocationEvent.sequence_number.desc())
            .limit(limit)
            .offset(offset)
        ).all()
    )
    return PaginatedResponse[RevocationEventOut](
        items=[RevocationEventOut.model_validate(e) for e in events],
        total=total,
        limit=limit,
        offset=offset,
        correlation_id=ctx.correlation_id,
    )


@router.get("/revocations/events/{event_id}/convergence", response_model=ConvergenceReportOut)
def get_event_convergence(
    event_id: str,
    ctx: AuthContext = Depends(require_permission("node:read")),
    db: Session = Depends(get_db),
) -> ConvergenceReportOut:
    try:
        return measure_event_convergence(db, event_id, correlation_id=ctx.correlation_id)
    except NodeSimulatorError as exc:
        raise _handle_sim_error(exc, ctx.correlation_id) from None


@router.post("/nodes/scenarios/{scenario_name}", response_model=ScenarioRunResponse)
def post_run_node_scenario(
    scenario_name: str,
    ctx: AuthContext = Depends(require_permission("node:manage")),
    db: Session = Depends(get_db),
    keystore: LocalEncryptedKeyStore = Depends(get_keystore),
) -> ScenarioRunResponse:
    """Execute deterministic node propagation & failure scenarios."""
    if scenario_name == "offline_and_catchup":
        nodes = configure_nodes(db, node_count=4, latencies_ms=[10, 20, 35, 50])
        set_node_availability(db, node_id="node-4", available=False, fault_mode="OFFLINE")
        event, partial = issue_revocation_event(
            db,
            keystore,
            subject_type="device",
            subject_id="dev-alex-trusted",
            reason="Scenario: node-4 offline during revocation",
            confirmation=True,
            acting_user=ctx.user,
            correlation_id=ctx.correlation_id,
            sim_clock_ms=1000,
            auto_propagate=True,
        )
        assert not partial.converged
        set_node_availability(db, node_id="node-4", available=True, fault_mode="NONE")
        propagate_pending_events(db, sim_clock_ms=1500)
        final = measure_event_convergence(db, event.event_id, correlation_id=ctx.correlation_id)
        return ScenarioRunResponse(
            scenario=scenario_name,
            status="COMPLETED" if final.converged else "PARTIAL",
            summary="node-4 remained unsynchronized while offline and caught up after reconnection.",
            events=[RevocationEventOut.model_validate(event)],
            convergence=final,
            access_checks=[{"node": n.node_id, "sync_status": n.sync_status} for n in list_nodes(db)],
            nodes=[node_to_out(n) for n in list_nodes(db)],
            correlation_id=ctx.correlation_id,
        )

    if scenario_name == "multi_offline":
        configure_nodes(db, node_count=5, latencies_ms=[10, 20, 30, 40, 50])
        set_node_availability(db, node_id="node-3", available=False, fault_mode="OFFLINE")
        set_node_availability(db, node_id="node-5", available=False, fault_mode="PARTITIONED")
        event, partial = issue_revocation_event(
            db,
            keystore,
            subject_type="device",
            subject_id="dev-alex-trusted",
            reason="Scenario: multi-node offline",
            confirmation=True,
            acting_user=ctx.user,
            correlation_id=ctx.correlation_id,
            sim_clock_ms=2000,
            auto_propagate=True,
        )
        return ScenarioRunResponse(
            scenario=scenario_name,
            status="PARTIAL",
            summary=f"Partial propagation: {partial.converged_nodes}/{partial.total_nodes} nodes converged.",
            events=[RevocationEventOut.model_validate(event)],
            convergence=partial,
            access_checks=[{"node": n.node_id, "sync_status": n.sync_status} for n in list_nodes(db)],
            nodes=[node_to_out(n) for n in list_nodes(db)],
            correlation_id=ctx.correlation_id,
        )

    if scenario_name == "duplicate_and_out_of_order":
        configure_nodes(db, node_count=3, latencies_ms=[10, 20, 30])
        ev1, _ = issue_revocation_event(
            db,
            keystore,
            subject_type="device",
            subject_id="dev-alex-pending",
            reason="Scenario seq1",
            confirmation=True,
            acting_user=ctx.user,
            correlation_id=ctx.correlation_id,
            sim_clock_ms=1000,
            auto_propagate=True,
        )
        ev2, _ = issue_revocation_event(
            db,
            keystore,
            subject_type="device",
            subject_id="dev-alex-trusted",
            reason="Scenario seq2",
            confirmation=True,
            acting_user=ctx.user,
            correlation_id=ctx.correlation_id,
            sim_clock_ms=2000,
            auto_propagate=True,
        )
        dup_outcomes = propagate_pending_events(db, sim_clock_ms=2500, replay_event_id=ev2.event_id)
        ooo_outcomes = propagate_pending_events(
            db, sim_clock_ms=2600, deliver_out_of_order=True, replay_event_id=ev1.event_id
        )
        return ScenarioRunResponse(
            scenario=scenario_name,
            status="COMPLETED",
            summary="Duplicate ignored idempotently and out-of-order seq1 did not roll back seq2.",
            events=[RevocationEventOut.model_validate(ev1), RevocationEventOut.model_validate(ev2)],
            convergence=measure_event_convergence(db, ev2.event_id, correlation_id=ctx.correlation_id),
            access_checks=[
                {"kind": "duplicate", "outcome": dup_outcomes[0].outcome},
                {"kind": "out_of_order", "outcome": ooo_outcomes[0].outcome},
            ],
            nodes=[node_to_out(n) for n in list_nodes(db)],
            correlation_id=ctx.correlation_id,
        )

    if scenario_name == "drop_and_processing_failure":
        configure_nodes(db, node_count=3, latencies_ms=[10, 20, 30])
        set_node_availability(db, node_id="node-2", available=True, fault_mode="DROP_EVENTS")
        set_node_availability(db, node_id="node-3", available=True, fault_mode="PROCESSING_ERROR")
        ev, partial = issue_revocation_event(
            db,
            keystore,
            subject_type="device",
            subject_id="dev-alex-trusted",
            reason="Scenario drop and processing failure",
            confirmation=True,
            acting_user=ctx.user,
            correlation_id=ctx.correlation_id,
            sim_clock_ms=3000,
            auto_propagate=True,
        )
        return ScenarioRunResponse(
            scenario=scenario_name,
            status="PARTIAL",
            summary="Dropped and failed nodes remained unsynchronized and did not report converged.",
            events=[RevocationEventOut.model_validate(ev)],
            convergence=partial,
            access_checks=[{"node": n.node_id, "sync_status": n.sync_status} for n in list_nodes(db)],
            nodes=[node_to_out(n) for n in list_nodes(db)],
            correlation_id=ctx.correlation_id,
        )

    raise HTTPException(
        status_code=404,
        detail={
            "code": "SCENARIO_NOT_FOUND",
            "message": f"Unknown scenario '{scenario_name}'.",
            "correlation_id": ctx.correlation_id,
        },
    )
