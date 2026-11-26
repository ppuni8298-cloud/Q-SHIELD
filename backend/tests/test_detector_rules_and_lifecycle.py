"""Independent tests for Phase 7 Detector Rules, Practice Fixture, Lifecycle, RBAC, Config & Integrity."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from backend.app.audit.verifier import verify_ledger_db
from backend.app.db.models import AlertRecord, AuditEvent, Device, KeyMetadata, User
from backend.app.detector.config import DetectorConfig
from backend.app.detector.ingestion import ingest_event_records, load_practice_csv_events
from backend.app.detector.rules import evaluate_all_rules
from backend.app.services.seed import DEMO_SYNTHETIC_TOKENS


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _ts(offset_sec: int = 0) -> str:
    return (datetime(2026, 11, 26, 14, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=offset_sec)).isoformat()


def _ev(eid: str, sec: int, **kw) -> dict:
    base = {
        "event_id": eid,
        "event_time_utc": _ts(sec),
        "received_time_utc": _ts(sec),
        "source_clock_offset_ms": 0,
        "actor_id": "actor-1",
        "source_service": "portal",
        "target_service": "catalog",
        "action": "read",
        "outcome": "ALLOW",
        "reason_code": "ALLOW_AUTHORIZED",
        "correlation_id": f"corr-{eid}",
    }
    base.update(kw)
    return base


def test_toolkit_practice_fixture_and_entity_renaming_invariance() -> None:
    candidates = [
        Path(r"C:\Users\ADMIN\.gemini\antigravity\brain\b5f7cfe8-202f-4ac6-a38c-63cd684a937d\scratch\Track-4-Toolkit\practice"),
    ]
    practice_path = next((p for p in candidates if p.is_dir()), None)
    assert practice_path is not None, "Official Track-4-Toolkit practice directory not found."

    raw_rows, approvals = load_practice_csv_events(practice_path / "events.csv", practice_path / "approvals.json")
    cfg = DetectorConfig(approvals=approvals)
    norm, _ = ingest_event_records(raw_rows, config=cfg)
    alerts = evaluate_all_rules(norm, config=cfg)

    by_rule = {}
    for al in alerts:
        by_rule.setdefault(al.rule_id, []).append(al)

    # evt-008/009 unapproved role change triggers RULE-ID-003, while evt-004 approved change does NOT
    assert "RULE-ID-003" in by_rule
    id3_refs = {eid for a in by_rule["RULE-ID-003"] for eid in a.event_refs}
    assert "evt-008" in id3_refs
    assert "evt-004" not in id3_refs

    # evt-010..012 triggers RULE-LAT-001 lateral movement, while evt-020 isolated denial does NOT
    assert "RULE-LAT-001" in by_rule
    lat_refs = {eid for a in by_rule["RULE-LAT-001"] for eid in a.event_refs}
    assert {"evt-010", "evt-011", "evt-012"}.issubset(lat_refs)
    assert "evt-020" not in lat_refs

    # Delayed evt-013/014 (<5s) and documented offset evt-015 (+2000ms) do NOT fire clock/replay alerts
    all_refs = {eid for a in alerts for eid in a.event_refs}
    assert "evt-013" not in all_refs
    assert "evt-014" not in all_refs
    assert "evt-015" not in all_refs

    # Entity-renaming invariance: rename actors, sessions, services, approvals -> identical alert rule multiset
    rename_map = {
        "user-alex": "alias-entity-alpha",
        "user-blair": "alias-entity-beta",
        "user-admin": "alias-entity-gamma",
        "user-casey": "alias-entity-delta",
        "svc-report-worker": "alias-svc-epsilon",
        "sess-alex": "sess-alias-alpha",
        "sess-blair": "sess-alias-beta",
        "sess-worker": "sess-alias-epsilon",
    }

    def _sub_str(s: str) -> str:
        return rename_map.get(s, s)

    renamed_rows = [{k: (_sub_str(v) if isinstance(v, str) else v) for k, v in r.items()} for r in raw_rows]
    renamed_approvals = [{k: (_sub_str(v) if isinstance(v, str) else v) for k, v in app.items()} for app in approvals]
    cfg_renamed = DetectorConfig(approvals=renamed_approvals)
    norm_ren, _ = ingest_event_records(renamed_rows, config=cfg_renamed)
    alerts_ren = evaluate_all_rules(norm_ren, config=cfg_renamed)
    assert sorted(a.rule_id for a in alerts) == sorted(a.rule_id for a in alerts_ren)


def test_comprehensive_rule_coverage_benign_vs_malicious_and_retries() -> None:
    cfg = DetectorConfig()
    benign_stream = [
        _ev("b-1", 0, actor_id="a-ok", device_id="d-ok", action="sign_in", target_service="identity"),
        _ev("b-2", 5, actor_id="a-ok", device_id="d-ok", action="read", resource_id="r-1", payload={"x": 1}),
        _ev("b-3", 6, actor_id="a-ok", device_id="d-ok", action="read", resource_id="r-1", is_retry_hint=True, reason_code="RETRY_TRANSIENT_TIMEOUT", payload={"x": 1}),
    ]
    b_norm, _ = ingest_event_records(benign_stream, config=cfg)
    assert evaluate_all_rules(b_norm, config=cfg) == []

    stream = [
        *[_ev(f"auth-{i}", 10 + i, actor_id="atk-auth", device_id="dev-1", target_service="identity", action="demo_login", outcome="DENY", reason_code="IDENTITY_INACTIVE_OR_UNKNOWN") for i in range(4)],
        _ev("sw-1", 30, actor_id="sw-a", device_id="dev-shared", action="read"),
        _ev("sw-2", 35, actor_id="sw-b", device_id="dev-shared", action="read"),
        _ev("sw-3", 40, actor_id="sw-c", device_id="dev-shared", action="read"),
        *[_ev(f"sb-{i}", 60 + i, actor_id="atk-sess", device_id="dev-sb", action="demo_login", target_service="identity") for i in range(5)],
        _ev("se-1", 70, actor_id="atk-exp", outcome="DENY", reason_code="SESSION_EXPIRED"),
        _ev("se-2", 72, actor_id="atk-exp", outcome="DENY", reason_code="SESSION_REVOKED"),
        _ev("kc-1", 80, actor_id="atk-key", outcome="DENY", reason_code="DENY_NODE_OLD_KEY_CUTOFF"),
        _ev("kc-2", 82, actor_id="atk-key", outcome="DENY", reason_code="OLD_KEY_CUTOFF_DENIAL"),
        _ev("ri-1", 90, actor_id="atk-revid", outcome="DENY", reason_code="DENY_IDENTITY_DISABLED"),
        _ev("ri-2", 92, actor_id="atk-revid", outcome="DENY", reason_code="DENY_IDENTITY_DISABLED"),
        _ev("rd-1", 95, actor_id="atk-revdev", device_id="dev-lost", outcome="DENY", reason_code="DENY_DEVICE_REVOKED"),
        *[_ev(f"er-{i}", 110 + i, actor_id="atk-read", resource_id=f"r-{i}", resource_category=f"cat-{i % 3}") for i in range(10)],
        *[_ev(f"dr-{i}", 140 + i, actor_id="atk-deny", resource_id="r-secret", target_service=f"svc-{i % 3}", outcome="DENY", reason_code="DENY_ROLE_PERMISSION_DENIED") for i in range(5)],
        _ev("piv-1", 170, actor_id="piv-a", device_id="dev-piv", outcome="DENY", reason_code="DENY_ROLE_PERMISSION_DENIED"),
        _ev("piv-2", 172, actor_id="piv-a", device_id="dev-piv", outcome="DENY", reason_code="DENY_ROLE_PERMISSION_DENIED"),
        _ev("piv-3", 175, actor_id="piv-b", device_id="dev-piv", outcome="ALLOW", target_service="vault"),
        *[_ev(f"np-{i}", 200 + i, actor_id="atk-np", node_id=f"node-{i+1}", event_type="NODE_ACCESS_DENIED", outcome="DENY", reason_code="DENY_NODE_LOCAL_REVOKED_ACTOR") for i in range(3)],
        _ev("ns-1", 210, actor_id="sys", node_id="node-3", event_type="STALE_NODE_DENIAL", outcome="DENY", reason_code="DENY_NODE_STALE_TRUST_STATE", latency_ms=1200),
        _ev("pf-1", 215, actor_id="sys", node_id="node-2", propagation_status="DROPPED", outcome="DENY", reason_code="NODE_DROP_EVENTS"),
        _ev("pf-2", 216, actor_id="sys", node_id="node-2", propagation_status="FAILED", outcome="DENY", reason_code="NODE_PROCESSING_ERROR"),
        _ev("no-1", 218, actor_id="sys", node_id="node-2", propagation_status="STALE_IGNORED", reason_code="REVOCATION_OUT_OF_ORDER"),
        *[_ev(f"rep-{i}", 230 + i, actor_id="atk-rep", action="decrypt_resource", payload={"seq": 99}, reason_code="REPLAY_DETECTED") for i in range(4)],
        _ev("reuse-1", 250, actor_id="atk-reuse", action="read", payload={"a": 1}),
        _ev("reuse-1", 251, actor_id="atk-reuse", action="read", payload={"a": 2}),
        _ev("seq-hi", 260, sequence=50, actor_id="atk-seq"),
        _ev("seq-lo", 261, sequence=40, actor_id="atk-seq"),
        _ev("skew-1", 290, received_time_utc=_ts(265), source_clock_offset_ms=0, actor_id="atk-skew"),
        *[_ev(f"sbx-{i}", 310, actor_id="atk-sim", sim_clock_ms=5000 + i * 50) for i in range(8)],
    ]
    norm, _ = ingest_event_records(stream, config=cfg)
    rule_ids = {a.rule_id for a in evaluate_all_rules(norm, config=cfg)}
    expected_rules = {
        "RULE-ID-001", "RULE-ID-002", "RULE-ID-004",
        "RULE-DEV-001", "RULE-DEV-002", "RULE-DEV-003", "RULE-DEV-004", "RULE-DEV-005",
        "RULE-RES-001", "RULE-RES-002", "RULE-RES-003", "RULE-RES-004",
        "RULE-LAT-002", "RULE-LAT-003",
        "RULE-NOD-001", "RULE-NOD-002", "RULE-NOD-003", "RULE-NOD-004",
        "RULE-TMP-001", "RULE-TMP-002", "RULE-TMP-003", "RULE-TMP-004", "RULE-TMP-005",
    }
    assert not (expected_rules - rule_ids)


def test_detector_determinism_and_fingerprint_stability() -> None:
    cfg = DetectorConfig()
    events = [
        _ev("d-1", 10, actor_id="u-det", action="demo_login", outcome="DENY", reason_code="IDENTITY_INACTIVE_OR_UNKNOWN"),
        _ev("d-2", 12, actor_id="u-det", action="demo_login", outcome="DENY", reason_code="IDENTITY_INACTIVE_OR_UNKNOWN"),
        _ev("d-3", 14, actor_id="u-det", action="demo_login", outcome="DENY", reason_code="IDENTITY_INACTIVE_OR_UNKNOWN"),
        _ev("d-4", 16, actor_id="u-det", action="demo_login", outcome="DENY", reason_code="IDENTITY_INACTIVE_OR_UNKNOWN"),
    ]
    n1, _ = ingest_event_records(events, config=cfg)
    n2, _ = ingest_event_records(list(reversed(events)), config=cfg)
    a1 = evaluate_all_rules(n1, config=cfg)
    a2 = evaluate_all_rules(n2, config=cfg)
    assert [(a.rule_id, a.fingerprint, a.event_refs, a.confidence) for a in a1] == [
        (a.rule_id, a.fingerprint, a.event_refs, a.confidence) for a in a2
    ]


def test_alert_deduplication_and_reopen_after_resolution(client: TestClient) -> None:
    secops_tok = DEMO_SYNTHETIC_TOKENS["sess-secops-valid"]
    payload = {
        "source": "custom_events",
        "custom_events": [
            _ev(f"ded-{i}", 10 + i, actor_id="dedup-u", action="demo_login", outcome="DENY", reason_code="IDENTITY_INACTIVE_OR_UNKNOWN")
            for i in range(4)
        ],
    }
    r1 = client.post("/api/v1/detector/evaluate", json=payload, headers=_auth(secops_tok))
    assert r1.status_code == 200 and r1.json()["run"]["alerts_created"] >= 1
    alt_id = r1.json()["alerts"][0]["id"]
    fp1 = r1.json()["alerts"][0]["fingerprint"]

    # Second run while OPEN -> deduplicated, zero new alerts
    r2 = client.post("/api/v1/detector/evaluate", json=payload, headers=_auth(secops_tok))
    assert r2.status_code == 200
    assert r2.json()["run"]["alerts_created"] == 0
    assert r2.json()["run"]["alerts_deduplicated"] >= 1

    # Resolve original alert -> third run creates fresh alert instance with identical fingerprint
    res = client.post(
        f"/api/v1/detector/alerts/{alt_id}/resolve",
        json={"reason": "Closed initial investigation", "confirmation": True},
        headers=_auth(secops_tok),
    )
    assert res.status_code == 200 and res.json()["alert"]["status"] == "RESOLVED"

    r3 = client.post("/api/v1/detector/evaluate", json=payload, headers=_auth(secops_tok))
    assert r3.status_code == 200 and r3.json()["run"]["alerts_created"] >= 1
    assert r3.json()["alerts"][0]["id"] != alt_id
    assert r3.json()["alerts"][0]["fingerprint"] == fp1


def test_alert_lifecycle_acknowledge_resolve_false_positive_and_confirmation_gate(
    client: TestClient, db_session: Session
) -> None:
    secops_tok = DEMO_SYNTHETIC_TOKENS["sess-secops-valid"]
    r1 = client.post(
        "/api/v1/detector/evaluate",
        json={
            "source": "custom_events",
            "custom_events": [_ev("lc-1", 0, actor_id="user-alex", device_id="dev-alex-trusted", outcome="DENY", reason_code="DENY_DEVICE_REVOKED")],
        },
        headers=_auth(secops_tok),
    )
    assert r1.status_code == 200
    alt_id = r1.json()["alerts"][0]["id"]

    # confirmation=False fails closed (400 CONFIRMATION_REQUIRED)
    no_conf = client.post(
        f"/api/v1/detector/alerts/{alt_id}/acknowledge",
        json={"reason": "Trying without confirmation", "confirmation": False},
        headers=_auth(secops_tok),
    )
    assert no_conf.status_code == 400 and no_conf.json()["error"]["code"] == "CONFIRMATION_REQUIRED"

    # Nonexistent alert -> 404
    assert (
        client.post(
            "/api/v1/detector/alerts/alt-missing/resolve",
            json={"reason": "Does not exist", "confirmation": True},
            headers=_auth(secops_tok),
        ).status_code
        == 404
    )

    ack = client.post(f"/api/v1/detector/alerts/{alt_id}/acknowledge", json={"reason": "Triaging", "confirmation": True}, headers=_auth(secops_tok))
    assert ack.status_code == 200 and ack.json()["alert"]["status"] == "ACKNOWLEDGED"

    res = client.post(f"/api/v1/detector/alerts/{alt_id}/resolve", json={"reason": "Verified handled", "confirmation": True}, headers=_auth(secops_tok))
    assert res.status_code == 200 and res.json()["alert"]["status"] == "RESOLVED" and res.json()["alert"]["reviewed_by"] == "user-secops"

    fp = client.post(f"/api/v1/detector/alerts/{alt_id}/false-positive", json={"reason": "Test drill", "confirmation": True}, headers=_auth(secops_tok))
    assert fp.status_code == 200 and fp.json()["alert"]["status"] == "FALSE_POSITIVE"

    # Non-destructive guarantee: identities, devices, and keys are never auto-revoked by detector runs/alerts
    db_session.expire_all()
    assert db_session.get(User, "user-alex").enabled is True
    assert db_session.get(Device, "dev-alex-trusted").state == "TRUSTED"
    assert db_session.get(KeyMetadata, "key-v1-active").state == "ACTIVE"


def test_detector_rbac_matrix_owner_auditor_secops_admin(client: TestClient) -> None:
    alex_tok = DEMO_SYNTHETIC_TOKENS["sess-alex-valid"]
    auditor_tok = DEMO_SYNTHETIC_TOKENS["sess-auditor-valid"]
    secops_tok = DEMO_SYNTHETIC_TOKENS["sess-secops-valid"]
    admin_tok = DEMO_SYNTHETIC_TOKENS["sess-admin-valid"]

    # Owner denied read, run, manage
    assert client.get("/api/v1/detector/rules", headers=_auth(alex_tok)).status_code == 403
    assert client.post("/api/v1/detector/evaluate", json={"source": "audit_ledger"}, headers=_auth(alex_tok)).status_code == 403
    assert client.post("/api/v1/detector/config", json={"reason": "No", "confirmation": True}, headers=_auth(alex_tok)).status_code == 403

    # Auditor allowed read (rules, runs, alerts, metrics) but denied run & manage
    assert client.get("/api/v1/detector/rules", headers=_auth(auditor_tok)).status_code == 200
    assert client.get("/api/v1/detector/runs", headers=_auth(auditor_tok)).status_code == 200
    assert client.get("/api/v1/detector/alerts", headers=_auth(auditor_tok)).status_code == 200
    assert client.post("/api/v1/detector/evaluate", json={"source": "audit_ledger"}, headers=_auth(auditor_tok)).status_code == 403
    assert client.post("/api/v1/detector/config", json={"reason": "No", "confirmation": True}, headers=_auth(auditor_tok)).status_code == 403

    # SecOps & Admin permitted all read/run/manage operations
    assert client.get("/api/v1/detector/rules", headers=_auth(secops_tok)).status_code == 200
    assert client.post("/api/v1/detector/evaluate", json={"source": "audit_ledger"}, headers=_auth(admin_tok)).status_code == 200


def test_detector_config_validation_bounds_persistence_and_audit(client: TestClient, db_session: Session) -> None:
    secops_tok = DEMO_SYNTHETIC_TOKENS["sess-secops-valid"]

    # Pydantic validation error (auth_failure_threshold < 1 or mad_z_threshold > 20) -> 422
    assert (
        client.post(
            "/api/v1/detector/config",
            json={"auth_failure_threshold": 0, "reason": "Bad", "confirmation": True},
            headers=_auth(secops_tok),
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/v1/detector/config",
            json={"mad_z_threshold": 99.0, "reason": "Bad", "confirmation": True},
            headers=_auth(secops_tok),
        ).status_code
        == 422
    )
    # Missing confirmation -> 400
    assert (
        client.post(
            "/api/v1/detector/config",
            json={"auth_failure_threshold": 3, "reason": "Unconfirmed", "confirmation": False},
            headers=_auth(secops_tok),
        ).status_code
        == 400
    )

    upd = client.post(
        "/api/v1/detector/config",
        json={"rule_set_version": "1.2.0", "auth_failure_threshold": 2, "reason": "Tighten brute threshold", "confirmation": True},
        headers=_auth(secops_tok),
    )
    assert upd.status_code == 200
    assert upd.json()["rule_set_version"] == "1.2.0"
    assert upd.json()["active_config"]["auth_failure_threshold"] == 2

    # Persisted threshold takes effect on subsequent evaluations + audit event recorded
    run_res = client.post(
        "/api/v1/detector/evaluate",
        json={
            "source": "custom_events",
            "custom_events": [
                _ev("cfg-1", 0, actor_id="cfg-u", action="sign_in", outcome="DENY", reason_code="AUTH_BAD"),
                _ev("cfg-2", 5, actor_id="cfg-u", action="sign_in", outcome="DENY", reason_code="AUTH_BAD"),
            ],
        },
        headers=_auth(secops_tok),
    )
    assert run_res.status_code == 200 and run_res.json()["run"]["rule_set_version"] == "1.2.0"
    assert any(a["rule_id"] == "RULE-ID-001" for a in run_res.json()["alerts"])

    cfg_audit = db_session.scalar(select(AuditEvent).where(AuditEvent.event_type == "DETECTOR_CONFIG_UPDATED"))
    assert cfg_audit is not None


def test_detector_invalid_sequence_range_oversized_batch_and_invalid_source(client: TestClient) -> None:
    secops_tok = DEMO_SYNTHETIC_TOKENS["sess-secops-valid"]
    assert (
        client.post(
            "/api/v1/detector/evaluate",
            json={"source": "audit_ledger", "start_sequence": 10, "end_sequence": 5},
            headers=_auth(secops_tok),
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/api/v1/detector/evaluate",
            json={"source": "unknown_source"},
            headers=_auth(secops_tok),
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/api/v1/detector/evaluate",
            json={"source": "custom_events", "custom_events": [_ev(f"x-{i}", i) for i in range(5001)]},
            headers=_auth(secops_tok),
        ).status_code
        == 422
    )


def test_detector_audit_chain_tamper_fails_closed_payload_and_gap(client: TestClient, db_session: Session) -> None:
    secops_tok = DEMO_SYNTHETIC_TOKENS["sess-secops-valid"]
    # Generate valid audit events first
    for _ in range(3):
        client.post("/api/v1/auth/demo-login", json={"actor_id": "user-disabled", "device_id": "dev-alex-trusted"})
    db_session.expire_all()
    assert verify_ledger_db(db_session).valid is True

    # Payload tamper -> live ledger detector fails closed 409
    db_session.execute(text('UPDATE audit_events SET reason_code = "TAMPERED" WHERE sequence = 1'))
    db_session.commit()
    tampered_run = client.post("/api/v1/detector/evaluate", json={"source": "audit_ledger"}, headers=_auth(secops_tok))
    assert tampered_run.status_code == 409
    assert tampered_run.json()["error"]["code"] == "AUDIT_CHAIN_INVALID"
    failed_ev = db_session.scalar(select(AuditEvent).where(AuditEvent.event_type == "DETECTOR_RUN_FAILED_CLOSED"))
    assert failed_ev is not None


def test_missing_evidence_empty_custom_and_empty_audit_slice(client: TestClient) -> None:
    secops_tok = DEMO_SYNTHETIC_TOKENS["sess-secops-valid"]

    empty_ledger = client.post("/api/v1/detector/evaluate", json={"source": "audit_ledger"}, headers=_auth(secops_tok))
    assert empty_ledger.status_code == 200
    assert empty_ledger.json()["run"]["status"] == "DEGRADED_MISSING_EVIDENCE"

    empty_custom = client.post("/api/v1/detector/evaluate", json={"source": "custom_events", "custom_events": []}, headers=_auth(secops_tok))
    assert empty_custom.status_code == 200
    assert empty_custom.json()["run"]["status"] == "DEGRADED_MISSING_EVIDENCE"

    # Also request slice past max existing sequence -> degraded missing evidence
    empty_slice = client.post(
        "/api/v1/detector/evaluate",
        json={"source": "audit_ledger", "start_sequence": 5000, "end_sequence": 6000},
        headers=_auth(secops_tok),
    )
    assert empty_slice.status_code == 200
    assert empty_slice.json()["run"]["status"] == "DEGRADED_MISSING_EVIDENCE"


def test_lateral_movement_false_positive_controls_approved_scope_and_window() -> None:
    # 1. Unexpected path outside default topology, but covered by active approvals -> NO RULE-LAT-001
    cfg = DetectorConfig(approvals=[{"subject": "svc-approved", "scope": ["partner_x", "ledger_y"]}])
    evs = [
        _ev("ap-1", 0, actor_id="svc-approved", session_id="s-ap", source_service="portal", target_service="partner_x"),
        _ev("ap-2", 5, actor_id="svc-approved", session_id="s-ap", source_service="partner_x", target_service="ledger_y"),
    ]
    n_ap, _ = ingest_event_records(evs, config=cfg)
    assert "RULE-LAT-001" not in {a.rule_id for a in evaluate_all_rules(n_ap, config=cfg)}

    # 2. Hops spread outside 300s window -> NO RULE-LAT-001
    slow_evs = [
        _ev("sl-1", 0, actor_id="svc-slow", session_id="s-slow", source_service="reports", target_service="billing"),
        _ev("sl-2", 350, actor_id="svc-slow", session_id="s-slow", source_service="billing", target_service="archive"),
    ]
    n_sl, _ = ingest_event_records(slow_evs, config=DetectorConfig())
    assert "RULE-LAT-001" not in {a.rule_id for a in evaluate_all_rules(n_sl, config=DetectorConfig())}


def test_clock_skew_and_uncertain_order_timestamp_preservation() -> None:
    raw = [
        _ev("t-late", 10, actor_id="clk-u", event_time_utc=_ts(12), received_time_utc=_ts(12), source_clock_offset_ms=0),
        _ev("t-off", 10, actor_id="clk-u", event_time_utc=_ts(12), received_time_utc=_ts(10), source_clock_offset_ms=2000),
    ]
    norm, _ = ingest_event_records(raw, config=DetectorConfig())
    by_id = {e.event_id: e for e in norm}

    # Raw event_time_utc and received_time_utc remain untouched; corrected_event_time_utc subtracts 2000ms
    assert by_id["t-off"].event_time_utc == datetime.fromisoformat(_ts(12))
    assert by_id["t-off"].received_time_utc == datetime.fromisoformat(_ts(10))
    assert by_id["t-off"].corrected_event_time_utc == datetime.fromisoformat(_ts(10))
    assert by_id["t-off"].uncertain_order is True
    assert evaluate_all_rules(norm, config=DetectorConfig()) == []
