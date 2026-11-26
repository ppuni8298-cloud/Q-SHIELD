"""Per-rule positive and negative boundary unit matrix for all 26 deterministic Phase 7 rules."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from backend.app.detector.config import RULE_CATALOG, DetectorConfig
from backend.app.detector.ingestion import ingest_event_records
from backend.app.detector.rules import evaluate_all_rules


def _ts(sec: int = 0) -> str:
    return (datetime(2026, 11, 26, 12, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=sec)).isoformat()


def _ev(eid: str, sec: int, **kw) -> dict:
    base = {
        "event_id": eid,
        "event_time_utc": _ts(sec),
        "received_time_utc": _ts(sec),
        "source_clock_offset_ms": 0,
        "actor_id": "actor-u1",
        "source_service": "portal",
        "target_service": "catalog",
        "action": "read",
        "outcome": "ALLOW",
        "reason_code": "ALLOW_AUTHORIZED",
        "correlation_id": f"corr-{eid}",
    }
    base.update(kw)
    return base


def _eval(events: list[dict], cfg: DetectorConfig | None = None) -> list:
    c = cfg or DetectorConfig()
    norm, _ = ingest_event_records(events, config=c)
    return evaluate_all_rules(norm, config=c)


def test_catalog_contains_26_explicit_deterministic_rules() -> None:
    assert len(RULE_CATALOG) == 26


def test_rule_id_001_repeated_auth_failures_positive_and_boundary_negative() -> None:
    pos = [
        _ev(f"a-{i}", i * 20, actor_id="brute-1", action="sign_in", outcome="DENY", reason_code="AUTH_BAD_CREDENTIALS")
        for i in range(4)
    ]
    assert "RULE-ID-001" in {a.rule_id for a in _eval(pos)}

    # Negative 1: 3 failures < threshold (4)
    neg_count = pos[:3]
    assert "RULE-ID-001" not in {a.rule_id for a in _eval(neg_count)}

    # Negative 2: 4 failures spaced 150s apart (total span 450s > 300s window)
    neg_window = [
        _ev(f"slow-{i}", i * 150, actor_id="brute-2", action="sign_in", outcome="DENY", reason_code="AUTH_BAD_CREDENTIALS")
        for i in range(4)
    ]
    assert "RULE-ID-001" not in {a.rule_id for a in _eval(neg_window)}


def test_rule_id_002_rapid_identity_switching_positive_and_pair_negative() -> None:
    pos = [_ev(f"sw-{i}", i * 10, actor_id=f"u-{i}", device_id="dev-s") for i in range(3)]
    assert "RULE-ID-002" in {a.rule_id for a in _eval(pos)}

    neg = [_ev(f"swp-{i}", i * 10, actor_id=f"u-{i}", device_id="dev-p") for i in range(2)]
    assert "RULE-ID-002" not in {a.rule_id for a in _eval(neg)}


def test_rule_id_003_unapproved_privilege_escalation_and_valid_window_negative() -> None:
    chg = _ev(
        "rc-1",
        100,
        actor_id="user-x",
        event_type="ROLE_CHANGED",
        action="role_change",
        role_before="viewer",
        role_after="admin",
        approval_id="app-1",
    )
    # Missing approval
    assert "RULE-ID-003" in {a.rule_id for a in _eval([chg])}

    # Exclusive upper bound: valid_until_utc == event time must still fire
    expired_cfg = DetectorConfig(
        approvals=[
            {
                "approval_id": "app-1",
                "subject": "user-x",
                "role": "admin",
                "valid_from_utc": _ts(50),
                "valid_until_utc": _ts(100),
            }
        ]
    )
    assert "RULE-ID-003" in {a.rule_id for a in _eval([chg], expired_cfg)}

    # Active matching approval stays clean
    valid_cfg = DetectorConfig(
        approvals=[
            {
                "approval_id": "app-1",
                "subject": "user-x",
                "role": "admin",
                "valid_from_utc": _ts(50),
                "valid_until_utc": _ts(200),
            }
        ]
    )
    assert "RULE-ID-003" not in {a.rule_id for a in _eval([chg], valid_cfg)}


def test_rule_id_004_revoked_or_disabled_identity_access_positive_and_single_negative() -> None:
    e1 = _ev("di-1", 0, actor_id="rev-u", outcome="DENY", reason_code="DENY_IDENTITY_DISABLED")
    assert "RULE-ID-004" not in {a.rule_id for a in _eval([e1])}

    e2 = _ev("di-2", 5, actor_id="rev-u", outcome="DENY", reason_code="DENY_IDENTITY_DISABLED")
    assert "RULE-ID-004" in {a.rule_id for a in _eval([e1, e2])}


def test_rule_id_005_outside_actor_baseline_scope_positive_and_approved_negative() -> None:
    base = _ev("bs-1", 0, actor_id="bob", target_service="catalog", event_type="ACCESS_GRANTED")
    anom = _ev(
        "bs-2",
        10,
        actor_id="bob",
        target_service="admin_core",
        resource_category="restricted_admin",
        event_type="ACCESS_DENIED",
        outcome="DENY",
    )
    anom2 = _ev(
        "bs-3",
        15,
        actor_id="bob",
        target_service="admin_core",
        resource_category="restricted_admin",
        event_type="ACCESS_DENIED",
        outcome="DENY",
    )
    assert "RULE-ID-005" in {a.rule_id for a in _eval([base, anom, anom2])}

    approved = DetectorConfig(approvals=[{"subject": "bob", "scope": ["admin_core"]}])
    assert "RULE-ID-005" not in {a.rule_id for a in _eval([base, anom, anom2], approved)}


def test_rule_dev_001_revoked_device_attempt_positive_and_trusted_negative() -> None:
    pos = [_ev("rd-1", 0, device_id="dev-lost", outcome="DENY", reason_code="DENY_DEVICE_REVOKED")]
    assert "RULE-DEV-001" in {a.rule_id for a in _eval(pos)}

    neg = [_ev("ok-1", 0, device_id="dev-trusted", outcome="ALLOW", reason_code="ALLOW_AUTHORIZED")]
    assert "RULE-DEV-001" not in {a.rule_id for a in _eval(neg)}


def test_rule_dev_002_device_identity_cardinality_positive_and_negative() -> None:
    pos = [_ev(f"dc-{i}", i * 300, actor_id=f"u-{i}", device_id="dev-card") for i in range(3)]
    assert "RULE-DEV-002" in {a.rule_id for a in _eval(pos)}

    neg = [_ev(f"dc2-{i}", i * 300, actor_id=f"u-{i}", device_id="dev-pair") for i in range(2)]
    assert "RULE-DEV-002" not in {a.rule_id for a in _eval(neg)}


def test_rule_dev_003_session_creation_burst_positive_and_negative() -> None:
    pos = [_ev(f"sb-{i}", i * 5, actor_id="sess-flood", action="demo_login", target_service="identity") for i in range(5)]
    assert "RULE-DEV-003" in {a.rule_id for a in _eval(pos)}

    neg = pos[:4]
    assert "RULE-DEV-003" not in {a.rule_id for a in _eval(neg)}


def test_rule_dev_004_expired_revoked_session_reuse_positive_and_single_negative() -> None:
    e1 = _ev("sr-1", 0, actor_id="u-sess", outcome="DENY", reason_code="SESSION_EXPIRED")
    assert "RULE-DEV-004" not in {a.rule_id for a in _eval([e1])}

    e2 = _ev("sr-2", 5, actor_id="u-sess", outcome="DENY", reason_code="DENY_SESSION_REVOKED")
    assert "RULE-DEV-004" in {a.rule_id for a in _eval([e1, e2])}


def test_rule_dev_005_pre_cutoff_key_post_rotation_positive_and_current_negative() -> None:
    pos = [
        _ev("kc-1", 0, actor_id="u-rot", outcome="DENY", reason_code="OLD_KEY_CUTOFF_DENIAL"),
        _ev("kc-2", 3, actor_id="u-rot", outcome="DENY", reason_code="DENY_NODE_OLD_KEY_CUTOFF"),
    ]
    assert "RULE-DEV-005" in {a.rule_id for a in _eval(pos)}

    neg = [_ev("kc-ok", 0, actor_id="u-rot", outcome="ALLOW", reason_code="ALLOW_AUTHORIZED")]
    assert "RULE-DEV-005" not in {a.rule_id for a in _eval(neg)}


def test_rule_res_001_excessive_reads_threshold_and_normal_baseline_negative() -> None:
    pos = [_ev(f"r-{i}", i * 3, actor_id="bulk-1", resource_id=f"res-{i}") for i in range(10)]
    alerts = [a for a in _eval(pos) if a.rule_id == "RULE-RES-001"]
    assert len(alerts) == 1 and "modZ=" in alerts[0].explanation

    neg = pos[:5]
    assert "RULE-RES-001" not in {a.rule_id for a in _eval(neg)}


def test_rule_res_002_unrelated_category_burst_positive_and_denied_excluded() -> None:
    pos = [_ev(f"c-{i}", i * 5, actor_id="cat-reader", resource_category=f"domain-{i}", outcome="ALLOW") for i in range(3)]
    assert "RULE-RES-002" in {a.rule_id for a in _eval(pos)}

    # Denied reads across categories must NOT falsely count as cross-category read exfiltration
    neg_denied = [_ev(f"cd-{i}", i * 5, actor_id="cat-denied", resource_category=f"domain-{i}", outcome="DENY") for i in range(3)]
    assert "RULE-RES-002" not in {a.rule_id for a in _eval(neg_denied)}


def test_rule_res_003_anomalous_denied_ratio_positive_and_sample_guard_negative() -> None:
    pos = [
        *[_ev(f"dr-d{i}", i, actor_id="probe-u", outcome="DENY") for i in range(3)],
        *[_ev(f"dr-a{i}", 10 + i, actor_id="probe-u", outcome="ALLOW") for i in range(2)],
    ]
    assert "RULE-RES-003" in {a.rule_id for a in _eval(pos)}

    # 3 denials + 1 allow (< min_ratio_samples=5) must NOT trigger
    assert "RULE-RES-003" not in {a.rule_id for a in _eval(pos[:4])}


def test_rule_res_004_repeated_post_denial_retries_positive_and_isolated_negative() -> None:
    pos = [_ev(f"pdr-{i}", i * 5, actor_id="retry-u", resource_id="res-sec", outcome="DENY") for i in range(3)]
    assert "RULE-RES-004" in {a.rule_id for a in _eval(pos)}

    assert "RULE-RES-004" not in {a.rule_id for a in _eval(pos[:1])}


def test_rule_lat_001_multi_hop_lateral_movement_and_isolated_denial_negative() -> None:
    pos = [
        _ev("l-1", 0, actor_id="svc-w", session_id="s-1", source_service="reports", target_service="billing", outcome="DENY"),
        _ev("l-2", 4, actor_id="svc-w", session_id="s-1", source_service="billing", target_service="archive", outcome="DENY"),
    ]
    lat_alerts = [a for a in _eval(pos) if a.rule_id == "RULE-LAT-001"]
    assert len(lat_alerts) == 1
    assert set(lat_alerts[0].event_refs) == {"l-1", "l-2"}

    # Single isolated denial must NOT trigger RULE-LAT-001
    assert "RULE-LAT-001" not in {a.rule_id for a in _eval(pos[:1])}

    # Normal allowed topology edges stay clean
    allowed_topology = [
        _ev("ok-l1", 0, actor_id="svc-ok", session_id="s-ok", source_service="portal", target_service="catalog"),
        _ev("ok-l2", 4, actor_id="svc-ok", session_id="s-ok", source_service="reports", target_service="catalog"),
    ]
    assert "RULE-LAT-001" not in {a.rule_id for a in _eval(allowed_topology)}


def test_rule_lat_002_sequential_privilege_tier_probing_positive_and_negative() -> None:
    pos = [
        _ev("lp-1", 0, actor_id="priv-p", target_service="billing", outcome="DENY", role_after="viewer"),
        _ev("lp-2", 5, actor_id="priv-p", target_service="archive", outcome="DENY", role_after="auditor"),
        _ev("lp-3", 10, actor_id="priv-p", target_service="identity", outcome="DENY", role_after="admin"),
    ]
    assert "RULE-LAT-002" in {a.rule_id for a in _eval(pos)}

    assert "RULE-LAT-002" not in {a.rule_id for a in _eval(pos[:2])}


def test_rule_lat_003_identity_pivot_from_shared_device_positive_and_negative() -> None:
    pos = [
        _ev("pv-1", 0, actor_id="a1", device_id="d-share", outcome="DENY"),
        _ev("pv-2", 5, actor_id="a1", device_id="d-share", outcome="DENY"),
        _ev("pv-3", 12, actor_id="a2", device_id="d-share", outcome="ALLOW", target_service="vault"),
    ]
    assert "RULE-LAT-003" in {a.rule_id for a in _eval(pos)}

    neg_distinct_dev = [
        _ev("pv-n1", 0, actor_id="a1", device_id="d-1", outcome="DENY"),
        _ev("pv-n2", 5, actor_id="a1", device_id="d-1", outcome="DENY"),
        _ev("pv-n3", 12, actor_id="a2", device_id="d-2", outcome="ALLOW", target_service="vault"),
    ]
    assert "RULE-LAT-003" not in {a.rule_id for a in _eval(neg_distinct_dev)}


def test_rule_nod_001_persistent_post_revocation_node_hammering_positive_and_negative() -> None:
    pos = [
        _ev(f"np-{i}", i, actor_id="node-hammer", node_id=f"node-{i+1}", event_type="NODE_ACCESS_DENIED", outcome="DENY", reason_code="DENY_NODE_LOCAL_REVOKED_ACTOR")
        for i in range(3)
    ]
    assert "RULE-NOD-001" in {a.rule_id for a in _eval(pos)}
    assert "RULE-NOD-001" not in {a.rule_id for a in _eval(pos[:2])}


def test_rule_nod_002_stale_node_and_latency_threshold_positive_and_negative() -> None:
    pos = [_ev("sn-1", 0, node_id="node-2", event_type="STALE_NODE_DENIAL", outcome="DENY", latency_ms=900)]
    assert "RULE-NOD-002" in {a.rule_id for a in _eval(pos)}

    neg = [_ev("sn-ok", 0, node_id="node-2", event_type="NODE_ACCESS_ALLOWED", outcome="ALLOW", latency_ms=50)]
    assert "RULE-NOD-002" not in {a.rule_id for a in _eval(neg)}


def test_rule_nod_003_propagation_failures_positive_and_single_fault_negative() -> None:
    pos = [
        _ev("pf-1", 0, node_id="node-2", propagation_status="DROPPED", outcome="DENY", reason_code="NODE_DROP_EVENTS"),
        _ev("pf-2", 2, node_id="node-3", propagation_status="FAILED", outcome="DENY", reason_code="NODE_PROCESSING_ERROR"),
    ]
    assert "RULE-NOD-003" in {a.rule_id for a in _eval(pos)}
    assert "RULE-NOD-003" not in {a.rule_id for a in _eval(pos[:1])}


def test_rule_nod_004_revocation_rollback_or_out_of_order_positive_and_negative() -> None:
    pos = [_ev("ro-1", 0, node_id="node-1", propagation_status="STALE_IGNORED", reason_code="REVOCATION_STALE_ORDER")]
    assert "RULE-NOD-004" in {a.rule_id for a in _eval(pos)}

    neg = [_ev("ro-ok", 0, node_id="node-1", propagation_status="APPLIED", reason_code="REVOCATION_APPLIED")]
    assert "RULE-NOD-004" not in {a.rule_id for a in _eval(neg)}


def test_rule_tmp_001_malicious_replay_vs_legitimate_transient_retry() -> None:
    benign_retry = [
        _ev("rt-1", 0, action="read", payload={"tx": 1}),
        _ev("rt-2", 2, action="read", payload={"tx": 1}, is_retry_hint=True, reason_code="RETRY_TRANSIENT_TIMEOUT"),
        _ev("rt-3", 4, action="read", payload={"tx": 1}, is_retry_hint=True, reason_code="RETRY_TRANSIENT_TIMEOUT"),
    ]
    assert "RULE-TMP-001" not in {a.rule_id for a in _eval(benign_retry)}

    malicious_replay = [
        _ev(f"rp-{i}", i * 2, actor_id="rep-u", action="decrypt_resource", payload={"tx": 2}, reason_code="REPLAY_DETECTED" if i > 0 else "ALLOW")
        for i in range(4)
    ]
    assert "RULE-TMP-001" in {a.rule_id for a in _eval(malicious_replay)}


def test_rule_tmp_002_reused_event_id_divergent_content_positive_and_negative() -> None:
    pos = [
        _ev("dup-id", 0, actor_id="a1", payload={"v": 1}),
        _ev("dup-id", 2, actor_id="a1", payload={"v": 2}),
    ]
    assert "RULE-TMP-002" in {a.rule_id for a in _eval(pos)}

    neg = [
        _ev("uniq-1", 0, actor_id="a1", payload={"v": 1}),
        _ev("uniq-2", 2, actor_id="a1", payload={"v": 2}),
    ]
    assert "RULE-TMP-002" not in {a.rule_id for a in _eval(neg)}


def test_rule_tmp_003_sequence_inversion_vs_bounded_delay() -> None:
    # Sequence inversion triggers RULE-TMP-003
    seq_inv = [
        _ev("si-1", 0, sequence=20),
        _ev("si-2", 2, sequence=10),
    ]
    assert "RULE-TMP-003" in {a.rule_id for a in _eval(seq_inv)}

    # Delayed arrival within 5000ms preserves uncertain_order without firing RULE-TMP-003
    bounded_delay = [
        _ev("bd-2", 2, actor_id="delay-u", event_time_utc=_ts(2), received_time_utc=_ts(2)),
        _ev("bd-1", 1, actor_id="delay-u", event_time_utc=_ts(1), received_time_utc=_ts(3)),
    ]
    norm, _ = ingest_event_records(bounded_delay, config=DetectorConfig())
    assert any(e.uncertain_order for e in norm)
    assert "RULE-TMP-003" not in {a.rule_id for a in evaluate_all_rules(norm, config=DetectorConfig())}


def test_rule_tmp_004_unexplained_clock_skew_vs_documented_offset() -> None:
    # +2000ms documented offset yields ~0ms residual -> no skew false positive
    documented = [_ev("off-ok", 10, event_time_utc=_ts(12), received_time_utc=_ts(10), source_clock_offset_ms=2000)]
    assert "RULE-TMP-004" not in {a.rule_id for a in _eval(documented)}

    # Unexplained 20s forward skew with offset=0 fires RULE-TMP-004
    unexplained = [_ev("skew-bad", 30, event_time_utc=_ts(30), received_time_utc=_ts(10), source_clock_offset_ms=0)]
    assert "RULE-TMP-004" in {a.rule_id for a in _eval(unexplained)}


def test_rule_tmp_005_sim_clock_burst_and_regression_positive_and_negative() -> None:
    burst = [_ev(f"sb-{i}", 0, actor_id="sim-u", sim_clock_ms=1000 + i * 50) for i in range(8)]
    assert "RULE-TMP-005" in {a.rule_id for a in _eval(burst)}

    regression = [
        _ev("sr-1", 0, actor_id="sim-reg", sim_clock_ms=2000),
        _ev("sr-2", 1, actor_id="sim-reg", sim_clock_ms=1500),
    ]
    assert "RULE-TMP-005" in {a.rule_id for a in _eval(regression)}

    steady = [_ev(f"st-{i}", i * 2, actor_id="sim-ok", sim_clock_ms=1000 + i * 2000) for i in range(8)]
    assert "RULE-TMP-005" not in {a.rule_id for a in _eval(steady)}
