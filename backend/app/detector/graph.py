"""Deterministic directed service-transition graph and privilege-probing analysis for lateral movement."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta

from backend.app.detector.config import ROLE_PRIVILEGE_RANK, DetectorConfig
from backend.app.detector.ingestion import NormalizedDetectorEvent


@dataclass(frozen=True)
class GraphEdgeEvent:
    event_id: str
    source_service: str
    target_service: str
    action: str
    outcome: str
    corrected_time: datetime
    is_expected: bool


@dataclass(frozen=True)
class LateralMovementCandidate:
    actor_id: str
    session_id: str | None
    device_id: str | None
    path_edges: tuple[str, ...]
    services_touched: tuple[str, ...]
    event_ids: tuple[str, ...]
    first_observed_at: datetime
    last_observed_at: datetime
    reason_summary: str


@dataclass(frozen=True)
class PrivilegeProbeCandidate:
    actor_id: str
    device_id: str | None
    distinct_ranks: tuple[int, ...]
    services_probed: tuple[str, ...]
    event_ids: tuple[str, ...]
    first_observed_at: datetime
    last_observed_at: datetime


@dataclass(frozen=True)
class IdentityPivotCandidate:
    device_id: str
    denied_actor_id: str
    pivot_actor_id: str
    target_service: str
    event_ids: tuple[str, ...]
    first_observed_at: datetime
    last_observed_at: datetime


def _edge_is_expected(
    ev: NormalizedDetectorEvent,
    *,
    config: DetectorConfig,
    approved_scopes: dict[str, set[str]],
) -> bool:
    pair = (ev.source_service, ev.target_service)
    if pair in config.allowed_service_edges:
        # Check role expectation for sensitive service targets such as billing/archive
        return True
    if ev.target_service in approved_scopes.get(ev.actor_id, set()):
        return True
    return False


def analyze_lateral_movement_graph(
    events: list[NormalizedDetectorEvent],
    *,
    config: DetectorConfig,
    approved_scopes: dict[str, set[str]],
) -> tuple[list[LateralMovementCandidate], list[PrivilegeProbeCandidate], list[IdentityPivotCandidate]]:
    """Analyze directed edges (source_service -> target_service) across sliding time windows.

    Explicitly excludes single isolated denials (len(unexpected_edges) == 1) from lateral movement.
    """
    ordered = sorted(events, key=lambda e: (e.corrected_event_time_utc, e.event_id))
    win = timedelta(seconds=config.lateral_window_sec)

    # 1. Group service accesses by (actor_id, session_id or correlation_id)
    by_actor_sess: dict[tuple[str, str], list[NormalizedDetectorEvent]] = defaultdict(list)
    for ev in ordered:
        # Focus graph traversal on resource/service access operations
        if ev.action in ("sign_in", "sign_out", "demo_login", "logout", "approve_role_change", "revoke_role", "role_change"):
            continue
        group_key = ev.session_id or ev.correlation_id
        by_actor_sess[(ev.actor_id, group_key)].append(ev)

    lateral_candidates: list[LateralMovementCandidate] = []
    for (actor_id, sess_or_corr), group in sorted(by_actor_sess.items()):
        unexpected_evs: list[NormalizedDetectorEvent] = [
            ev for ev in group if not _edge_is_expected(ev, config=config, approved_scopes=approved_scopes)
        ]
        # Exclude single isolated denial / single hop
        if len(unexpected_evs) < config.lateral_min_unexpected_hops:
            continue

        # Sliding time window check over unexpected edges
        i = 0
        while i < len(unexpected_evs):
            j = i
            while j < len(unexpected_evs) and (unexpected_evs[j].corrected_event_time_utc - unexpected_evs[i].corrected_event_time_utc) <= win:
                j += 1
            sub = unexpected_evs[i:j]
            distinct_edges = {f"{e.source_service}->{e.target_service}" for e in sub}
            distinct_targets = {e.target_service for e in sub}
            if len(sub) >= config.lateral_min_unexpected_hops and (len(distinct_edges) >= config.lateral_min_unexpected_hops or len(distinct_targets) >= config.lateral_min_unexpected_hops):
                ordered_edges = tuple(f"{e.source_service}->{e.target_service}" for e in sub)
                svcs = tuple(dict.fromkeys([sub[0].source_service] + [e.target_service for e in sub]))
                lateral_candidates.append(
                    LateralMovementCandidate(
                        actor_id=actor_id,
                        session_id=sub[0].session_id,
                        device_id=sub[0].device_id,
                        path_edges=ordered_edges,
                        services_touched=svcs,
                        event_ids=tuple(e.event_id for e in sub),
                        first_observed_at=sub[0].corrected_event_time_utc,
                        last_observed_at=sub[-1].corrected_event_time_utc,
                        reason_summary=(
                            f"Actor '{actor_id}' traversed {len(ordered_edges)} unexpected service edge(s) "
                            f"({' , '.join(ordered_edges)}) within {config.lateral_window_sec}s."
                        ),
                    )
                )
                i = j
            else:
                i += 1

    # 2. Sequential probing across distinct resource categories / privilege tiers
    by_actor_all: dict[str, list[NormalizedDetectorEvent]] = defaultdict(list)
    for ev in ordered:
        if ev.outcome in ("DENY", "FAIL", "FAILED"):
            by_actor_all[ev.actor_id].append(ev)

    probe_candidates: list[PrivilegeProbeCandidate] = []
    for actor_id, denied_evs in sorted(by_actor_all.items()):
        if len(denied_evs) < 3:
            continue
        i = 0
        while i < len(denied_evs):
            j = i
            while j < len(denied_evs) and (denied_evs[j].corrected_event_time_utc - denied_evs[i].corrected_event_time_utc) <= win:
                j += 1
            sub = denied_evs[i:j]
            svcs = sorted({e.target_service for e in sub})
            ranks = sorted({ROLE_PRIVILEGE_RANK.get(e.role_after or "viewer", 1) for e in sub} | {len(svcs)})
            if len(svcs) >= 3:
                probe_candidates.append(
                    PrivilegeProbeCandidate(
                        actor_id=actor_id,
                        device_id=sub[0].device_id,
                        distinct_ranks=tuple(ranks),
                        services_probed=tuple(svcs),
                        event_ids=tuple(e.event_id for e in sub),
                        first_observed_at=sub[0].corrected_event_time_utc,
                        last_observed_at=sub[-1].corrected_event_time_utc,
                    )
                )
                i = j
            else:
                i += 1

    # 3. Identity pivot after repeated denials from same device_id
    by_device: dict[str, list[NormalizedDetectorEvent]] = defaultdict(list)
    for ev in ordered:
        if ev.device_id:
            by_device[ev.device_id].append(ev)

    pivot_candidates: list[IdentityPivotCandidate] = []
    for dev_id, dev_evs in sorted(by_device.items()):
        denied_by_actor: dict[str, list[NormalizedDetectorEvent]] = defaultdict(list)
        for ev in dev_evs:
            if ev.outcome in ("DENY", "FAIL", "FAILED"):
                denied_by_actor[ev.actor_id].append(ev)
            else:
                # Check if another actor on this device had >= 2 prior denials within window
                for prev_actor, prev_denials in denied_by_actor.items():
                    if prev_actor != ev.actor_id and len(prev_denials) >= 2:
                        if (ev.corrected_event_time_utc - prev_denials[-1].corrected_event_time_utc) <= win:
                            ev_ids = tuple([d.event_id for d in prev_denials[-3:]] + [ev.event_id])
                            pivot_candidates.append(
                                IdentityPivotCandidate(
                                    device_id=dev_id,
                                    denied_actor_id=prev_actor,
                                    pivot_actor_id=ev.actor_id,
                                    target_service=ev.target_service,
                                    event_ids=ev_ids,
                                    first_observed_at=prev_denials[-min(len(prev_denials), 3)].corrected_event_time_utc,
                                    last_observed_at=ev.corrected_event_time_utc,
                                )
                            )
                            break

    return lateral_candidates, probe_candidates, pivot_candidates
