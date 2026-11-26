"""Phase 9 tests: security hardening, datasets, 14 live scenarios, and benchmark APIs."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from backend.app.detector.config import DetectorConfig
from backend.app.detector.ingestion import load_jsonl_events
from backend.app.detector.rules import evaluate_all_rules
from backend.app.services.scenarios import SCENARIO_CATALOG
from backend.app.services.seed import DEMO_SYNTHETIC_TOKENS

REPO_ROOT = Path(__file__).resolve().parents[2]
DATASETS_DIR = REPO_ROOT / "datasets"


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_security_headers_and_cors_allowlist(client: TestClient) -> None:
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    assert res.headers.get("x-content-type-options") == "nosniff"
    assert res.headers.get("x-frame-options") == "DENY"
    assert res.headers.get("referrer-policy") == "no-referrer"
    assert res.headers.get("cache-control") == "no-store"
    csp = res.headers.get("content-security-policy", "")
    assert "default-src 'self'" in csp and "object-src 'none'" in csp

    # Localhost Vite origin allowed; unknown remote origin rejected on preflight
    pre_ok = client.options(
        "/api/v1/auth/demo-login",
        headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST"},
    )
    assert pre_ok.status_code == 200
    assert pre_ok.headers.get("access-control-allow-origin") == "http://localhost:5173"

    pre_bad = client.options(
        "/api/v1/auth/demo-login",
        headers={"Origin": "https://evil.example.net", "Access-Control-Request-Method": "POST"},
    )
    assert pre_bad.headers.get("access-control-allow-origin") is None


def test_login_rate_limiter_enforced_and_reset_on_seed(client: TestClient) -> None:
    # 8 consecutive bad login attempts for user-alex trigger sliding-window lock (9th -> 429)
    for _ in range(8):
        r = client.post(
            "/api/v1/auth/demo-login",
            json={"actor_id": "user-alex", "device_id": "dev-nonexistent-bad"},
        )
        assert r.status_code == 403

    locked = client.post(
        "/api/v1/auth/demo-login",
        json={"actor_id": "user-alex", "device_id": "dev-alex-trusted"},
    )
    assert locked.status_code == 429
    assert locked.json()["error"]["code"] == "AUTH_RATE_LIMITED"

    # Admin simulation reset clears limiter state cleanly
    admin_tok = DEMO_SYNTHETIC_TOKENS["sess-admin-valid"]
    reset_res = client.post(
        "/api/v1/simulation/reset",
        json={"reason": "reset rate limit test", "confirmation": True},
        headers=_auth(admin_tok),
    )
    assert reset_res.status_code == 200

    ok = client.post(
        "/api/v1/auth/demo-login",
        json={"actor_id": "user-alex", "device_id": "dev-alex-trusted"},
    )
    assert ok.status_code == 200


def test_curated_jsonl_datasets_and_malformed_safety() -> None:
    expected_files = [
        "benign_admin.jsonl",
        "privilege_escalation.jsonl",
        "lateral_movement.jsonl",
        "clock_skew_reordered.jsonl",
        "replay_recipient_tamper.jsonl",
        "malformed.jsonl",
    ]
    for fname in expected_files:
        assert (DATASETS_DIR / fname).is_file(), f"Missing fixture: {fname}"

    # 1. Benign approved role change -> zero alerts
    cfg_benign = DetectorConfig(
        approvals=[
            {
                "approval_id": "fx-chg-100",
                "operation": "role_change",
                "subject": "fx-admin-ok",
                "role": "report-reader",
                "valid_from_utc": "2026-11-26T08:50:00+00:00",
                "valid_until_utc": "2026-11-26T09:10:00+00:00",
            }
        ]
    )
    ev_b, w_b = load_jsonl_events(DATASETS_DIR / "benign_admin.jsonl", config=cfg_benign)
    assert len(ev_b) == 2 and not w_b
    assert evaluate_all_rules(ev_b, config=cfg_benign) == []

    # 2. Unapproved privilege escalation -> RULE-ID-003
    ev_p, _ = load_jsonl_events(DATASETS_DIR / "privilege_escalation.jsonl")
    alerts_p = evaluate_all_rules(ev_p, config=DetectorConfig())
    assert any(a.rule_id == "RULE-ID-003" and a.actor_id == "fx-escalator" for a in alerts_p)

    # 3. Lateral movement multi-hop -> RULE-LAT-001 (isolated denial excluded)
    ev_l, _ = load_jsonl_events(DATASETS_DIR / "lateral_movement.jsonl")
    alerts_l = evaluate_all_rules(ev_l, config=DetectorConfig())
    lat_actors = {a.actor_id for a in alerts_l if a.rule_id == "RULE-LAT-001"}
    assert "fx-worker" in lat_actors
    assert "fx-isolated" not in lat_actors

    # 4. Clock skew & reordered arrival -> documented +2000ms ok, +30s unexplained -> RULE-TMP-004
    ev_c, _ = load_jsonl_events(DATASETS_DIR / "clock_skew_reordered.jsonl")
    assert any(e.uncertain_order for e in ev_c)
    alerts_c = evaluate_all_rules(ev_c, config=DetectorConfig())
    skew_actors = {a.actor_id for a in alerts_c if a.rule_id == "RULE-TMP-004"}
    assert "fx-clk-skew" in skew_actors
    assert "fx-clk-ok" not in skew_actors

    # 5. Replay & event_id reuse -> RULE-TMP-001 & RULE-TMP-002
    ev_r, _ = load_jsonl_events(DATASETS_DIR / "replay_recipient_tamper.jsonl")
    rule_ids_r = {a.rule_id for a in evaluate_all_rules(ev_r, config=DetectorConfig())}
    assert {"RULE-TMP-001", "RULE-TMP-002"}.issubset(rule_ids_r)

    # 6. Malformed JSON / NaN / array lines fail closed with warnings & parse remaining valid record
    ev_m, w_m = load_jsonl_events(DATASETS_DIR / "malformed.jsonl")
    assert len(ev_m) == 1
    assert ev_m[0].event_id == "fx-mal-valid"
    assert len(w_m) >= 3


def test_all_14_scenarios_and_rbac(client: TestClient) -> None:
    assert len(SCENARIO_CATALOG) == 14
    secops_tok = DEMO_SYNTHETIC_TOKENS["sess-secops-valid"]
    alex_tok = DEMO_SYNTHETIC_TOKENS["sess-alex-valid"]

    # Viewer/owner cannot run scenarios
    denied = client.post("/api/v1/simulation/scenarios/normal_protected_read/run", headers=_auth(alex_tok))
    assert denied.status_code == 403

    listed = client.get("/api/v1/simulation/scenarios", headers=_auth(secops_tok))
    assert listed.status_code == 200
    assert listed.json()["total"] == 14

    unknown = client.post("/api/v1/simulation/scenarios/not_a_real_scenario/run", headers=_auth(secops_tok))
    assert unknown.status_code == 404

    for item in SCENARIO_CATALOG:
        sid = item["id"]
        res = client.post(f"/api/v1/simulation/scenarios/{sid}/run", headers=_auth(secops_tok))
        assert res.status_code == 200, f"Scenario {sid} failed HTTP: {res.text}"
        body = res.json()
        assert body["passed"] is True, f"Scenario {sid} failed assertion: {body}"
        assert body["duration_ms"] >= 0


def test_benchmark_api_and_persisted_run(client: TestClient) -> None:
    secops_tok = DEMO_SYNTHETIC_TOKENS["sess-secops-valid"]
    alex_tok = DEMO_SYNTHETIC_TOKENS["sess-alex-valid"]

    assert client.post("/api/v1/bench/run", headers=_auth(alex_tok)).status_code == 403

    run_res = client.post("/api/v1/bench/run", headers=_auth(secops_tok))
    assert run_res.status_code == 200
    data = run_res.json()
    assert data["run_id"]
    assert len(data["results"]) >= 8
    for row in data["results"]:
        assert row["errors"] == 0
        assert row["median_ms"] >= 0
        assert row["throughput_ops_sec"] > 0

    latest = client.get("/api/v1/bench/latest", headers=_auth(secops_tok))
    assert latest.status_code == 200
    assert latest.json()["run_id"] == data["run_id"]
    assert (REPO_ROOT / "reports" / "benchmarks" / "latest.json").is_file()
    parsed = json.loads((REPO_ROOT / "reports" / "benchmarks" / "latest.json").read_text(encoding="utf-8"))
    assert parsed["run_id"] == data["run_id"]
