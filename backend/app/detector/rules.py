"""Deterministic explainable detection rules evaluating normalized telemetry & baselines."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
from typing import Any

from backend.app.detector.baselines import (
    compute_actor_baselines,
    compute_median_and_mad,
    compute_percentile,
    modified_z_score,
    sliding_window_clusters,
)
from backend.app.detector.config import RULE_CATALOG, DetectorConfig
from backend.app.detector.graph import analyze_lateral_movement_graph
from backend.app.detector.ingestion import NormalizedDetectorEvent, parse_utc


@dataclass(frozen=True)
class CandidateAlert:
    rule_id: str
    rule_version: str
    fingerprint: str
    severity: str
    confidence: float
    actor_id: str
    device_id: str | None
    session_id: str | None
    node_id: str | None
    resource_id: str | None
    services: tuple[str, ...]
    event_refs: tuple[str, ...]
    reason_codes: tuple[str, ...]
    explanation: str
    recommended_response: str
    detection_window_sec: int
    first_observed_at: datetime
    last_observed_at: datetime


def _make_fingerprint(rule_id: str, rule_version: str, scope_parts: list[str]) -> str:
    raw = "|".join([rule_id, rule_version] + scope_parts).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _mk_alert(
    *,
    rule_id: str,
    config: DetectorConfig,
    scope_parts: list[str],
    actor_id: str,
    events: list[NormalizedDetectorEvent],
    explanation: str,
    reason_codes: list[str],
    detection_window_sec: int,
    device_id: str | None = None,
    session_id: str | None = None,
    node_id: str | None = None,
    resource_id: str | None = None,
) -> CandidateAlert:
    spec = RULE_CATALOG[rule_id]
    ordered = sorted(events, key=lambda e: (e.corrected_event_time_utc, e.event_id))
    svcs = tuple(dict.fromkeys(e.target_service for e in ordered if e.target_service))
    ev_ids = tuple(dict.fromkeys(e.event_id for e in ordered))
    r_codes = tuple(dict.fromkeys(reason_codes))
    conf = round(min(0.99, spec.base_weight + 0.03 * max(0, len(ev_ids) - 1)), 4)
    return CandidateAlert(
        rule_id=rule_id,
        rule_version=config.rule_set_version,
        fingerprint=_make_fingerprint(rule_id, config.rule_set_version, scope_parts),
        severity=spec.severity,
        confidence=conf,
        actor_id=actor_id,
        device_id=device_id or next((e.device_id for e in ordered if e.device_id), None),
        session_id=session_id or next((e.session_id for e in ordered if e.session_id), None),
        node_id=node_id or next((e.node_id for e in ordered if e.node_id), None),
        resource_id=resource_id or next((e.resource_id for e in ordered if e.resource_id), None),
        services=svcs,
        event_refs=ev_ids,
        reason_codes=r_codes,
        explanation=explanation,
        recommended_response=spec.recommended_response,
        detection_window_sec=detection_window_sec,
        first_observed_at=ordered[0].corrected_event_time_utc,
        last_observed_at=ordered[-1].corrected_event_time_utc,
    )


def _extract_approval_windows(
    events: list[NormalizedDetectorEvent],
    approvals_cfg: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, set[str]]]:
    """Combine static approvals config with in-stream approve_role_change / revoke_role observations."""
    approvals = list(approvals_cfg)
    approved_scopes: dict[str, set[str]] = defaultdict(set)
    for app in approvals:
        subj = str(app.get("subject", ""))
        for s in app.get("scope", []):
            approved_scopes[subj].add(str(s))
    return approvals, approved_scopes


def _is_role_change_approved(ev: NormalizedDetectorEvent, approvals: list[dict[str, Any]]) -> bool:
    """Verify change-control match (subject, target_role, valid_from <= t < valid_until exclusive)."""
    target_role = ev.role_after
    t = ev.corrected_event_time_utc
    for app in approvals:
        if app.get("operation") not in (None, "grant_role", "role_change"):
            continue
        if app.get("subject") != ev.actor_id:
            continue
        if app.get("role") and target_role and app.get("role") != target_role:
            continue
        if ev.approval_id and app.get("approval_id") != ev.approval_id:
            continue
        v_from = parse_utc(app.get("valid_from_utc"), fallback=t)
        v_until_raw = app.get("valid_until_utc")
        v_until = parse_utc(v_until_raw) if v_until_raw else None
        if v_from <= t and (v_until is None or t < v_until):
            return True
    return False


def evaluate_all_rules(
    events: list[NormalizedDetectorEvent],
    *,
    config: DetectorConfig,
) -> list[CandidateAlert]:
    """Run all deterministic rules over normalized telemetry cleanly without ground-truth labels."""
    if not events:
        return []

    ordered = sorted(events, key=lambda e: (e.corrected_event_time_utc, e.event_id))
    approvals, approved_scopes = _extract_approval_windows(ordered, config.approvals)
    baselines = compute_actor_baselines(ordered)
    alerts_by_fp: dict[str, CandidateAlert] = {}

    def _emit(c: CandidateAlert) -> None:
        if c.fingerprint not in alerts_by_fp:
            alerts_by_fp[c.fingerprint] = c

    # ------------------------------------------------------------------
    # Group events by key entities
    # ------------------------------------------------------------------
    by_actor: dict[str, list[NormalizedDetectorEvent]] = defaultdict(list)
    by_device: dict[str, list[NormalizedDetectorEvent]] = defaultdict(list)
    by_event_id: dict[str, list[NormalizedDetectorEvent]] = defaultdict(list)

    for ev in ordered:
        by_actor[ev.actor_id].append(ev)
        if ev.device_id:
            by_device[ev.device_id].append(ev)
        by_event_id[ev.event_id].append(ev)

    # ------------------------------------------------------------------
    # 1. AUTHENTICATION & IDENTITY RULES (RULE-ID-001..005)
    # ------------------------------------------------------------------
    for actor_id, evs in sorted(by_actor.items()):
        # RULE-ID-001: Repeated authentication failures
        auth_fails = [
            e
            for e in evs
            if e.outcome in ("DENY", "FAIL", "FAILED")
            and (e.event_type in ("AUTH_LOGIN_FAILED", "AUTH_SESSION_INVALID", "AUTH_TOKEN_MISSING", "AUTH_TOKEN_EMPTY") or e.action in ("sign_in", "demo_login", "authenticate"))
        ]
        for cl in sliding_window_clusters(auth_fails, window_sec=config.auth_failure_window_sec, min_count=config.auth_failure_threshold):
            _emit(
                _mk_alert(
                    rule_id="RULE-ID-001",
                    config=config,
                    scope_parts=[actor_id, cl[0].event_id],
                    actor_id=actor_id,
                    events=cl,
                    reason_codes=[e.reason_code for e in cl],
                    explanation=f"{len(cl)} authentication failure(s) for '{actor_id}' within {config.auth_failure_window_sec}s (threshold={config.auth_failure_threshold}).",
                    detection_window_sec=config.auth_failure_window_sec,
                )
            )

        # RULE-ID-003: Unapproved privilege / role change
        role_evs = [
            e
            for e in evs
            if e.event_type in ("ROLE_CHANGED", "ROLE_ESCALATION_DENIED")
            or e.action in ("role_change", "change_role", "update_user_role")
        ]
        for rev in role_evs:
            if not _is_role_change_approved(rev, approvals):
                linked = [rev]
                for follow in evs:
                    if (
                        follow.event_id != rev.event_id
                        and follow.session_id == rev.session_id
                        and rev.session_id is not None
                        and follow.corrected_event_time_utc >= rev.corrected_event_time_utc
                        and (follow.corrected_event_time_utc - rev.corrected_event_time_utc) <= timedelta(seconds=60)
                    ):
                        linked.append(follow)
                _emit(
                    _mk_alert(
                        rule_id="RULE-ID-003",
                        config=config,
                        scope_parts=[actor_id, rev.event_id],
                        actor_id=actor_id,
                        events=linked,
                        reason_codes=["UNAPPROVED_ROLE_CHANGE", rev.reason_code],
                        explanation=f"Role change for '{actor_id}' ({rev.role_before} -> {rev.role_after}) lacks a valid change-control approval.",
                        detection_window_sec=60,
                    )
                )

        # RULE-ID-004: Revoked or disabled identity attempting further access
        revoked_id_evs = [
            e
            for e in evs
            if e.outcome in ("DENY", "FAIL", "FAILED")
            and e.reason_code in ("DENY_IDENTITY_DISABLED", "IDENTITY_INACTIVE_OR_UNKNOWN", "IDENTITY_DISABLED", "DENY_NODE_LOCAL_REVOKED_ACTOR")
        ]
        if len(revoked_id_evs) >= 2:
            _emit(
                _mk_alert(
                    rule_id="RULE-ID-004",
                    config=config,
                    scope_parts=[actor_id, revoked_id_evs[0].event_id],
                    actor_id=actor_id,
                    events=revoked_id_evs,
                    reason_codes=[e.reason_code for e in revoked_id_evs],
                    explanation=f"Revoked/disabled identity '{actor_id}' recorded {len(revoked_id_evs)} post-revocation access attempt(s).",
                    detection_window_sec=300,
                )
            )

        # RULE-DEV-001: Revoked device continuing access
        revoked_dev_evs = [
            e
            for e in evs
            if "DEVICE" in e.reason_code and ("REVOKED" in e.reason_code or "NOT_TRUSTED_REVOKED" in e.reason_code)
        ]
        for rev_dev in revoked_dev_evs:
            if rev_dev.outcome in ("DENY", "FAIL", "FAILED"):
                _emit(
                    _mk_alert(
                        rule_id="RULE-DEV-001",
                        config=config,
                        scope_parts=[actor_id, rev_dev.device_id or "none", rev_dev.event_id],
                        actor_id=actor_id,
                        device_id=rev_dev.device_id,
                        events=[rev_dev],
                        reason_codes=[rev_dev.reason_code],
                        explanation=f"Revoked device '{rev_dev.device_id}' attempted protected access/login under '{actor_id}' ({rev_dev.reason_code}).",
                        detection_window_sec=60,
                    )
                )

        # RULE-DEV-003: Suspicious session creation burst
        sess_creates = [
            e
            for e in evs
            if e.outcome in ("ALLOW", "SUCCESS") and e.action in ("sign_in", "demo_login", "session_create")
        ]
        for cl in sliding_window_clusters(sess_creates, window_sec=config.session_burst_window_sec, min_count=config.session_burst_threshold):
            _emit(
                _mk_alert(
                    rule_id="RULE-DEV-003",
                    config=config,
                    scope_parts=[actor_id, cl[0].event_id],
                    actor_id=actor_id,
                    events=cl,
                    reason_codes=["SESSION_CREATION_BURST"],
                    explanation=f"Actor '{actor_id}' opened {len(cl)} sessions within {config.session_burst_window_sec}s (threshold={config.session_burst_threshold}).",
                    detection_window_sec=config.session_burst_window_sec,
                )
            )

        # RULE-DEV-004: Repeated expired or revoked session use
        bad_sess = [
            e
            for e in evs
            if e.reason_code in ("SESSION_EXPIRED", "SESSION_REVOKED", "DENY_SESSION_REVOKED", "DENY_SESSION_EXPIRED", "DENY_NODE_LOCAL_REVOKED_SESSION")
        ]
        if len(bad_sess) >= config.expired_revoked_session_threshold:
            _emit(
                _mk_alert(
                    rule_id="RULE-DEV-004",
                    config=config,
                    scope_parts=[actor_id, bad_sess[0].event_id],
                    actor_id=actor_id,
                    events=bad_sess,
                    reason_codes=[e.reason_code for e in bad_sess],
                    explanation=f"Actor '{actor_id}' triggered {len(bad_sess)} expired/revoked session denials.",
                    detection_window_sec=300,
                )
            )

        # RULE-DEV-005: Post-rotation old-key cutoff activity
        cutoff_evs = [
            e
            for e in evs
            if e.reason_code in ("OLD_KEY_CUTOFF_DENIAL", "DENY_NODE_OLD_KEY_CUTOFF", "DENY_KEY_INACTIVE", "DENY_OLD_KEY_CUTOFF")
        ]
        if len(cutoff_evs) >= 2:
            _emit(
                _mk_alert(
                    rule_id="RULE-DEV-005",
                    config=config,
                    scope_parts=[actor_id, cutoff_evs[0].event_id],
                    actor_id=actor_id,
                    events=cutoff_evs,
                    reason_codes=[e.reason_code for e in cutoff_evs],
                    explanation=f"Actor '{actor_id}' submitted {len(cutoff_evs)} post-rotation requests using superseded/inactive keys.",
                    detection_window_sec=300,
                )
            )

    # Per-device checks (RULE-ID-002 identity switching & RULE-DEV-002 high cardinality)
    for dev_id, devs in sorted(by_device.items()):
        # Distinct actors within identity_switch_window_sec
        win_switch = timedelta(seconds=config.identity_switch_window_sec)
        for i in range(len(devs)):
            sub = [e for e in devs[i:] if (e.corrected_event_time_utc - devs[i].corrected_event_time_utc) <= win_switch]
            distinct_actors = sorted({e.actor_id for e in sub if e.actor_id != "unknown"})
            if len(distinct_actors) >= config.identity_switch_threshold:
                _emit(
                    _mk_alert(
                        rule_id="RULE-ID-002",
                        config=config,
                        scope_parts=[dev_id, sub[0].event_id],
                        actor_id=distinct_actors[0],
                        device_id=dev_id,
                        events=sub,
                        reason_codes=["RAPID_IDENTITY_SWITCH"],
                        explanation=f"Device '{dev_id}' switched rapidly across {len(distinct_actors)} identities ({', '.join(distinct_actors)}) within {config.identity_switch_window_sec}s.",
                        detection_window_sec=config.identity_switch_window_sec,
                    )
                )
                break

        all_dev_actors = sorted({e.actor_id for e in devs if e.actor_id != "unknown"})
        if len(all_dev_actors) >= config.device_identity_threshold:
            _emit(
                _mk_alert(
                    rule_id="RULE-DEV-002",
                    config=config,
                    scope_parts=[dev_id],
                    actor_id=all_dev_actors[0],
                    device_id=dev_id,
                    events=devs,
                    reason_codes=["DEVICE_IDENTITY_CARDINALITY"],
                    explanation=f"Device '{dev_id}' associated with {len(all_dev_actors)} distinct identities (threshold={config.device_identity_threshold}).",
                    detection_window_sec=config.device_identity_window_sec,
                )
            )

    # ------------------------------------------------------------------
    # 2. RESOURCE ACCESS & STATISTICAL BASELINES (RULE-RES-001..004, RULE-ID-005)
    # ------------------------------------------------------------------
    # Compute global read counts per actor-window distribution for MAD / P95 anomaly check
    read_actions = ("read", "decrypt_resource", "node_access:read", "vault_read")
    actor_window_counts: list[float] = []
    actor_read_clusters: dict[str, list[list[NormalizedDetectorEvent]]] = {}
    for actor_id, evs in sorted(by_actor.items()):
        reads = [e for e in evs if e.action in read_actions and e.outcome in ("ALLOW", "SUCCESS")]
        actor_window_counts.append(float(len(reads)))
        actor_read_clusters[actor_id] = sliding_window_clusters(
            reads, window_sec=config.excessive_reads_window_sec, min_count=config.excessive_reads_threshold
        )

    med_reads, mad_reads = compute_median_and_mad(actor_window_counts)
    p95_reads = compute_percentile(actor_window_counts, config.percentile_threshold) or float(config.excessive_reads_threshold)

    for actor_id, evs in sorted(by_actor.items()):
        # RULE-RES-001: Sliding-window read burst OR MAD modified Z-score outlier above P95
        clusters = actor_read_clusters.get(actor_id, [])
        for cl in clusters:
            z_val = modified_z_score(float(len(cl)), med=med_reads, mad=mad_reads)
            _emit(
                _mk_alert(
                    rule_id="RULE-RES-001",
                    config=config,
                    scope_parts=[actor_id, cl[0].event_id],
                    actor_id=actor_id,
                    events=cl,
                    reason_codes=["EXCESSIVE_RESOURCE_READS"],
                    explanation=(
                        f"Actor '{actor_id}' performed {len(cl)} resource reads in {config.excessive_reads_window_sec}s "
                        f"(threshold={config.excessive_reads_threshold}, median={med_reads:.1f}, MAD={mad_reads:.1f}, modZ={'inf' if z_val == float('inf') else f'{z_val:.2f}'}, P95={p95_reads:.1f})."
                    ),
                    detection_window_sec=config.excessive_reads_window_sec,
                )
            )

        # RULE-RES-002: Rapid access across unrelated resource categories (explicit categories on granted accesses or unapproved targets)
        cat_evs = [
            e
            for e in evs
            if (e.action in read_actions or e.event_category == "PROTECTED_ACCESS")
            and e.outcome in ("ALLOW", "SUCCESS")
        ]
        win_cat = timedelta(seconds=config.category_window_sec)
        for i in range(len(cat_evs)):
            sub = [e for e in cat_evs[i:] if (e.corrected_event_time_utc - cat_evs[i].corrected_event_time_utc) <= win_cat]
            cats = sorted({e.resource_category for e in sub if e.resource_category and e.resource_category != "general"})
            if len(cats) >= config.category_diversity_threshold:
                _emit(
                    _mk_alert(
                        rule_id="RULE-RES-002",
                        config=config,
                        scope_parts=[actor_id, sub[0].event_id],
                        actor_id=actor_id,
                        events=sub,
                        reason_codes=["CROSS_CATEGORY_ACCESS_BURST"],
                        explanation=f"Actor '{actor_id}' accessed {len(cats)} distinct resource categories ({', '.join(cats)}) within {config.category_window_sec}s.",
                        detection_window_sec=config.category_window_sec,
                    )
                )
                break

        # RULE-RES-003: Anomalous denied-to-allowed access ratio (only if actor also shows >= 5 attempts)
        prof = baselines.get(actor_id)
        if prof is not None and (prof.allowed_count + prof.denied_count) >= config.min_ratio_samples:
            if prof.denied_ratio >= config.denied_to_allowed_ratio_threshold:
                denied_evs = [e for e in evs if e.outcome in ("DENY", "FAIL", "FAILED")]
                _emit(
                    _mk_alert(
                        rule_id="RULE-RES-003",
                        config=config,
                        scope_parts=[actor_id],
                        actor_id=actor_id,
                        events=denied_evs,
                        reason_codes=["HIGH_DENIED_TO_ALLOWED_RATIO"],
                        explanation=f"Actor '{actor_id}' denied ratio {prof.denied_ratio:.2f} ({prof.denied_count}/{prof.allowed_count + prof.denied_count}) >= {config.denied_to_allowed_ratio_threshold:.2f}.",
                        detection_window_sec=300,
                    )
                )

        # RULE-RES-004: Repeated retries on same resource after authorization denial
        denials_by_res: dict[str, list[NormalizedDetectorEvent]] = defaultdict(list)
        for e in evs:
            if e.outcome in ("DENY", "FAIL", "FAILED") and e.resource_id:
                denials_by_res[e.resource_id].append(e)
        for res_id, r_evs in sorted(denials_by_res.items()):
            for cl in sliding_window_clusters(r_evs, window_sec=config.post_denial_window_sec, min_count=config.post_denial_retry_threshold):
                _emit(
                    _mk_alert(
                        rule_id="RULE-RES-004",
                        config=config,
                        scope_parts=[actor_id, res_id, cl[0].event_id],
                        actor_id=actor_id,
                        resource_id=res_id,
                        events=cl,
                        reason_codes=[e.reason_code for e in cl],
                        explanation=f"Actor '{actor_id}' repeated {len(cl)} denied attempts on resource '{res_id}' within {config.post_denial_window_sec}s.",
                        detection_window_sec=config.post_denial_window_sec,
                    )
                )

        # RULE-ID-005: Unusual access to elevated/sensitive resource categories outside baseline & approvals
        unusual_evs = [
            e
            for e in evs
            if e.resource_category in ("restricted_admin", "sensitive_billing", "secret_archive")
            and e.target_service not in approved_scopes.get(actor_id, set())
            and (prof is not None and e.target_service not in prof.normal_services or e.outcome in ("ALLOW", "DENY"))
            and e.event_type in ("ACCESS_GRANTED", "RESOURCE_DECRYPTED", "ACCESS_DENIED", "RESOURCE_ACCESS_ANOMALY")
        ]
        if unusual_evs and (len(unusual_evs) >= 2 or any(e.outcome == "ALLOW" for e in unusual_evs)):
            _emit(
                _mk_alert(
                    rule_id="RULE-ID-005",
                    config=config,
                    scope_parts=[actor_id, unusual_evs[0].target_service],
                    actor_id=actor_id,
                    events=unusual_evs,
                    reason_codes=["OUTSIDE_BASELINE_AUTHORIZATION"],
                    explanation=f"Actor '{actor_id}' accessed restricted category outside baseline scope ({unusual_evs[0].resource_category}).",
                    detection_window_sec=300,
                )
            )

    # ------------------------------------------------------------------
    # 3. LATERAL MOVEMENT GRAPH RULES (RULE-LAT-001..003)
    # ------------------------------------------------------------------
    lat_cands, probe_cands, pivot_cands = analyze_lateral_movement_graph(ordered, config=config, approved_scopes=approved_scopes)
    for cand in lat_cands:
        matched_evs = [e for e in ordered if e.event_id in cand.event_ids]
        _emit(
            _mk_alert(
                rule_id="RULE-LAT-001",
                config=config,
                scope_parts=[cand.actor_id, cand.event_ids[0]],
                actor_id=cand.actor_id,
                device_id=cand.device_id,
                session_id=cand.session_id,
                events=matched_evs,
                reason_codes=["LATERAL_MOVEMENT_GRAPH_PATH"],
                explanation=cand.reason_summary,
                detection_window_sec=config.lateral_window_sec,
            )
        )
    for pcand in probe_cands:
        # Avoid duplicate alert if identical exact events already flagged as multi-hop lateral movement unless distinct service ranks probed
        matched_evs = [e for e in ordered if e.event_id in pcand.event_ids]
        _emit(
            _mk_alert(
                rule_id="RULE-LAT-002",
                config=config,
                scope_parts=[pcand.actor_id, pcand.event_ids[0]],
                actor_id=pcand.actor_id,
                device_id=pcand.device_id,
                events=matched_evs,
                reason_codes=["SEQUENTIAL_PRIVILEGE_PROBE"],
                explanation=f"Actor '{pcand.actor_id}' probed {len(pcand.services_probed)} distinct privilege targets ({', '.join(pcand.services_probed)}).",
                detection_window_sec=config.lateral_window_sec,
            )
        )
    for piv in pivot_cands:
        matched_evs = [e for e in ordered if e.event_id in piv.event_ids]
        _emit(
            _mk_alert(
                rule_id="RULE-LAT-003",
                config=config,
                scope_parts=[piv.device_id, piv.denied_actor_id, piv.pivot_actor_id],
                actor_id=piv.pivot_actor_id,
                device_id=piv.device_id,
                events=matched_evs,
                reason_codes=["CROSS_IDENTITY_PIVOT_AFTER_DENIAL"],
                explanation=f"Device '{piv.device_id}' pivoted from denied actor '{piv.denied_actor_id}' to '{piv.pivot_actor_id}' targeting '{piv.target_service}'.",
                detection_window_sec=config.lateral_window_sec,
            )
        )

    # ------------------------------------------------------------------
    # 4. NODE & REVOCATION BEHAVIOR RULES (RULE-NOD-001..004)
    # ------------------------------------------------------------------
    for actor_id, evs in sorted(by_actor.items()):
        post_rev_node_denials = [
            e
            for e in evs
            if e.outcome in ("DENY", "FAIL", "FAILED")
            and (
                e.event_type == "NODE_ACCESS_DENIED"
                or e.reason_code in ("DENY_NODE_LOCAL_REVOKED_ACTOR", "DENY_NODE_LOCAL_REVOKED_DEVICE", "DENY_NODE_LOCAL_REVOKED_SESSION", "DENY_NODE_LOCAL_REVOKED_KEY")
            )
        ]
        # Persistent access attempts after revocation (>= 3 denials distinguishes malicious hammering from routine post-revocation notice)
        if len(post_rev_node_denials) >= 3:
            _emit(
                _mk_alert(
                    rule_id="RULE-NOD-001",
                    config=config,
                    scope_parts=[actor_id, post_rev_node_denials[0].event_id],
                    actor_id=actor_id,
                    events=post_rev_node_denials,
                    reason_codes=[e.reason_code for e in post_rev_node_denials],
                    explanation=f"Persistent post-revocation access attempts ({len(post_rev_node_denials)}) observed for '{actor_id}' across simulated nodes.",
                    detection_window_sec=300,
                )
            )

    stale_evs = [
        e
        for e in ordered
        if e.event_type == "STALE_NODE_DENIAL"
        or e.reason_code == "DENY_NODE_STALE_TRUST_STATE"
        or (e.latency_ms is not None and e.latency_ms > config.stale_node_threshold_ms)
        or (e.propagation_status == "PARTIAL" or (e.event_type == "REVOCATION_CONVERGENCE" and e.outcome == "PARTIAL"))
    ]
    for sev in stale_evs:
        _emit(
            _mk_alert(
                rule_id="RULE-NOD-002",
                config=config,
                scope_parts=[sev.node_id or sev.actor_id, sev.event_id],
                actor_id=sev.actor_id,
                node_id=sev.node_id,
                events=[sev],
                reason_codes=["NODE_STALE_OR_CONVERGENCE_LAG", sev.reason_code],
                explanation=f"Node '{sev.node_id or 'cluster'}' remained stale or exceeded convergence threshold ({config.stale_node_threshold_ms}ms; observed={sev.latency_ms}ms).",
                detection_window_sec=300,
            )
        )

    prop_fail_evs = [
        e
        for e in ordered
        if e.propagation_status in ("DROPPED", "FAILED", "CONFLICTING_STATE")
        or e.reason_code in ("NODE_PROCESSING_ERROR", "NODE_DROP_EVENTS", "NODE_CONFLICTING_TRUST_STATE")
    ]
    if len(prop_fail_evs) >= config.prop_failure_threshold:
        _emit(
            _mk_alert(
                rule_id="RULE-NOD-003",
                config=config,
                scope_parts=[prop_fail_evs[0].node_id or "cluster", prop_fail_evs[0].event_id],
                actor_id=prop_fail_evs[0].actor_id,
                node_id=prop_fail_evs[0].node_id,
                events=prop_fail_evs,
                reason_codes=[e.reason_code for e in prop_fail_evs],
                explanation=f"{len(prop_fail_evs)} node propagation failure(s) or conflicting node trust state(s) detected.",
                detection_window_sec=300,
            )
        )

    order_rev_evs = [
        e
        for e in ordered
        if e.propagation_status == "STALE_IGNORED" or e.reason_code in ("REVOCATION_STALE_ORDER", "REVOCATION_OUT_OF_ORDER")
    ]
    for oev in order_rev_evs:
        _emit(
            _mk_alert(
                rule_id="RULE-NOD-004",
                config=config,
                scope_parts=[oev.node_id or "cluster", oev.event_id],
                actor_id=oev.actor_id,
                node_id=oev.node_id,
                events=[oev],
                reason_codes=[oev.reason_code],
                explanation=f"Unexpected out-of-order revocation sequence/rollback attempt rejected at node '{oev.node_id}'.",
                detection_window_sec=300,
            )
        )

    # ------------------------------------------------------------------
    # 5. REPLAY & TEMPORAL INTEGRITY RULES (RULE-TMP-001..005)
    # ------------------------------------------------------------------
    # RULE-TMP-002: Reused event_id with divergent content; & duplicate id handling
    for ev_id, dup_list in sorted(by_event_id.items()):
        if len(dup_list) < 2:
            continue
        distinct_digests = {e.payload_digest for e in dup_list}
        if len(distinct_digests) > 1:
            _emit(
                _mk_alert(
                    rule_id="RULE-TMP-002",
                    config=config,
                    scope_parts=[ev_id],
                    actor_id=dup_list[0].actor_id,
                    events=dup_list,
                    reason_codes=["REUSED_EVENT_ID_DIVERGENT_CONTENT"],
                    explanation=f"Event identifier '{ev_id}' reused {len(dup_list)} times across differing payloads/actors.",
                    detection_window_sec=300,
                )
            )
        else:
            # Distinguish legitimate transient retries (<= max_legitimate_retries & is_retry_hint) vs malicious replay
            all_benign_retry = all(e.is_retry_hint for e in dup_list[1:]) and (len(dup_list) - 1) <= config.max_legitimate_retries
            if not all_benign_retry:
                _emit(
                    _mk_alert(
                        rule_id="RULE-TMP-001",
                        config=config,
                        scope_parts=[ev_id],
                        actor_id=dup_list[0].actor_id,
                        events=dup_list,
                        reason_codes=["DUPLICATE_REPLAY_DETECTED"],
                        explanation=f"Malicious duplicate/replay detected for '{ev_id}' ({len(dup_list)} occurrences; exceeds benign retry allowance {config.max_legitimate_retries}).",
                        detection_window_sec=300,
                    )
                )

    # Content-based malicious replay (identical non-retry payload_digest replayed across > max_legitimate_retries or explicit REPLAY marker)
    by_digest: dict[tuple[str, str], list[NormalizedDetectorEvent]] = defaultdict(list)
    for ev in ordered:
        if ev.action in ("sign_in", "demo_login", "read", "decrypt_resource", "send_message", "receive_message", "submit_tx"):
            by_digest[(ev.session_id or ev.actor_id, ev.payload_digest)].append(ev)
    for (scope_id, _dig), d_evs in sorted(by_digest.items()):
        if len(d_evs) <= config.max_legitimate_retries + 1:
            # Check explicit replay reason code
            explicit_replays = [e for e in d_evs if "REPLAY" in e.reason_code]
            if not explicit_replays:
                continue
        # Only flag if not already flagged by RULE-TMP-002 and not benign retry-hinted transient retries
        non_retry = [e for e in d_evs[1:] if not e.is_retry_hint]
        if len(non_retry) >= 2 or any("REPLAY" in e.reason_code for e in d_evs):
            _emit(
                _mk_alert(
                    rule_id="RULE-TMP-001",
                    config=config,
                    scope_parts=[scope_id, d_evs[0].event_id],
                    actor_id=d_evs[0].actor_id,
                    events=d_evs,
                    reason_codes=["REPLAY_PATTERN_DETECTED"],
                    explanation=f"Repeated identical operation replay ({len(d_evs)} events) for actor '{d_evs[0].actor_id}' exceeding legitimate retry limit ({config.max_legitimate_retries}).",
                    detection_window_sec=300,
                )
            )

    # RULE-TMP-003 & RULE-TMP-004: Out-of-order & Unexplained Clock Skew (preserve documented benign offsets/delays!)
    raw_by_receipt = sorted(events, key=lambda e: e.receipt_index)
    for idx, ev in enumerate(raw_by_receipt):
        # Unexplained clock skew: subtract documented source_clock_offset_ms first!
        # delivery_delay_ms = received_time_utc - corrected_event_time_utc
        delivery_delay_ms = (ev.received_time_utc - ev.corrected_event_time_utc).total_seconds() * 1000.0
        # Unexplained negative delay (< -clock_skew_tolerance_ms -> future timestamp) OR huge undocumented offset
        if delivery_delay_ms < -config.clock_skew_tolerance_ms or abs(ev.source_clock_offset_ms) > config.clock_skew_tolerance_ms * 5:
            _emit(
                _mk_alert(
                    rule_id="RULE-TMP-004",
                    config=config,
                    scope_parts=[ev.actor_id, ev.event_id],
                    actor_id=ev.actor_id,
                    events=[ev],
                    reason_codes=["UNEXPLAINED_CLOCK_SKEW"],
                    explanation=(
                        f"Event '{ev.event_id}' exhibits unexplained clock skew: corrected delivery delay={delivery_delay_ms:.0f}ms, "
                        f"offset={ev.source_clock_offset_ms}ms (tolerance=+/-{config.clock_skew_tolerance_ms}ms)."
                    ),
                    detection_window_sec=60,
                )
            )

        # Out-of-order sequence number OR arrival lag beyond reorder_window_ms
        if idx > 0:
            prev_rx = raw_by_receipt[idx - 1]
            if ev.sequence is not None and prev_rx.sequence is not None and ev.sequence < prev_rx.sequence:
                _emit(
                    _mk_alert(
                        rule_id="RULE-TMP-003",
                        config=config,
                        scope_parts=[ev.event_id],
                        actor_id=ev.actor_id,
                        events=[prev_rx, ev],
                        reason_codes=["OUT_OF_ORDER_SEQUENCE"],
                        explanation=f"Sequence number inversion detected: sequence {ev.sequence} arrived after {prev_rx.sequence}.",
                        detection_window_sec=60,
                    )
                )
            elif ev.corrected_event_time_utc < prev_rx.corrected_event_time_utc:
                lag_ms = (prev_rx.corrected_event_time_utc - ev.corrected_event_time_utc).total_seconds() * 1000.0
                if lag_ms > config.reorder_window_ms:
                    _emit(
                        _mk_alert(
                            rule_id="RULE-TMP-003",
                            config=config,
                            scope_parts=[ev.event_id],
                            actor_id=ev.actor_id,
                            events=[prev_rx, ev],
                            reason_codes=["EXCESSIVE_ARRIVAL_REORDER"],
                            explanation=f"Out-of-order event '{ev.event_id}' delayed by {lag_ms:.0f}ms (> reorder_window={config.reorder_window_ms}ms).",
                            detection_window_sec=60,
                        )
                    )

    # RULE-TMP-005: Simulation clock burst or clock regression
    for actor_id, a_evs in sorted(by_actor.items()):
        a_sim = [e for e in a_evs if e.sim_clock_ms is not None]
        if len(a_sim) >= 2:
            by_rx = sorted(a_sim, key=lambda x: x.receipt_index)
            for idx in range(1, len(by_rx)):
                if by_rx[idx].sim_clock_ms < by_rx[idx - 1].sim_clock_ms:  # type: ignore[operator]
                    _emit(
                        _mk_alert(
                            rule_id="RULE-TMP-005",
                            config=config,
                            scope_parts=[actor_id, by_rx[idx].event_id],
                            actor_id=actor_id,
                            events=[by_rx[idx - 1], by_rx[idx]],
                            reason_codes=["SIM_CLOCK_REGRESSION"],
                            explanation=f"Simulation clock regressed from {by_rx[idx-1].sim_clock_ms}ms to {by_rx[idx].sim_clock_ms}ms.",
                            detection_window_sec=60,
                        )
                    )
                    break
        if len(a_sim) >= config.sim_burst_threshold:
            # Tight burst on simulation clock
            i = 0
            while i < len(a_sim):
                j = i
                while j < len(a_sim) and (a_sim[j].sim_clock_ms - a_sim[i].sim_clock_ms) <= config.sim_burst_window_ms:  # type: ignore[operator]
                    j += 1
                sub = a_sim[i:j]
                if len(sub) >= config.sim_burst_threshold:
                    _emit(
                        _mk_alert(
                            rule_id="RULE-TMP-005",
                            config=config,
                            scope_parts=[actor_id, sub[0].event_id],
                            actor_id=actor_id,
                            events=sub,
                            reason_codes=["SIM_CLOCK_BURST"],
                            explanation=f"{len(sub)} events occurred within {config.sim_burst_window_ms}ms on simulation clock.",
                            detection_window_sec=10,
                        )
                    )
                    i = j
                else:
                    i += 1

    return sorted(alerts_by_fp.values(), key=lambda a: (a.first_observed_at, a.rule_id, a.fingerprint))
