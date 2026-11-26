"""Independent verification of Phase 7 benchmark dataset, label isolation, zero-ML guarantee, and metrics."""

from __future__ import annotations

import ast
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import median

from fastapi.testclient import TestClient

from backend.app.detector.config import DetectorConfig
from backend.app.detector.dataset import (
    EvaluationScenarioTruth,
    SyntheticEvaluationDataset,
    generate_synthetic_evaluation_dataset,
)
from backend.app.detector.evaluation import evaluate_benchmark_dataset
from backend.app.detector.ingestion import NormalizedDetectorEvent, ingest_event_records
from backend.app.services.seed import DEMO_SYNTHETIC_TOKENS


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_ground_truth_label_isolation_and_reproducibility() -> None:
    ds1 = generate_synthetic_evaluation_dataset(seed=20261126)
    ds2 = generate_synthetic_evaluation_dataset(seed=20261126)
    assert len(ds1.events) >= 300
    assert len(ds1.scenarios) >= 100

    # Ensure NormalizedDetectorEvent cannot receive or expose ground-truth labels
    assert not hasattr(NormalizedDetectorEvent, "label")
    assert not any("label" in ev or "ground_truth" in ev or "is_attack" in ev for ev in ds1.events)

    # Inject poisoned labels into a copy of raw events -> normalized events & emitted alerts remain IDENTICAL
    poisoned = [dict(ev, label="FORCED_MALICIOUS", ground_truth="attack", truth_label=True) for ev in ds1.events]
    cfg = DetectorConfig(approvals=ds1.approvals)
    norm_clean, _ = ingest_event_records(ds1.events, config=cfg)
    norm_poisoned, _ = ingest_event_records(poisoned, config=cfg)
    assert norm_clean == norm_poisoned

    rep1, alerts1 = evaluate_benchmark_dataset(ds1)
    rep2, alerts2 = evaluate_benchmark_dataset(ds2)
    assert rep1 == rep2
    assert alerts1 == alerts2


def test_independent_confusion_matrix_precision_recall_f1_fa_rate_and_median_time(client: TestClient) -> None:
    ds = generate_synthetic_evaluation_dataset(seed=20261126)
    rep, alerts = evaluate_benchmark_dataset(ds)

    # Independently recompute scenario-level confusion matrix & operational metrics
    by_event = defaultdict(list)
    for al in alerts:
        for eid in al.event_refs:
            by_event[eid].append(al)

    ind_tp = 0
    ind_fp = 0
    ind_tn = 0
    ind_fn = 0
    ind_det_times: list[float] = []
    benign_fp_keys: set[str] = set()

    for sc in ds.scenarios:
        hits = []
        for eid in sc.event_ids:
            hits.extend(by_event.get(eid, []))
        if sc.is_attack:
            matched = [a for a in hits if any(a.rule_id.startswith(p) for p in sc.expected_rule_prefixes)]
            if matched:
                ind_tp += 1
                first_al = min(matched, key=lambda a: (a.last_observed_at, a.rule_id))
                ind_det_times.append(max(0.0, (first_al.last_observed_at - sc.start_time_utc).total_seconds() * 1000.0))
            else:
                ind_fn += 1
        else:
            if hits:
                ind_fp += 1
                for h in hits:
                    benign_fp_keys.add(h.fingerprint)
            else:
                ind_tn += 1

    ind_prec = round(ind_tp / (ind_tp + ind_fp), 6)
    ind_rec = round(ind_tp / (ind_tp + ind_fn), 6)
    ind_f1 = round(2 * ind_prec * ind_rec / (ind_prec + ind_rec), 6)
    ind_fa_1k = round((len(benign_fp_keys) / len(ds.benign_event_ids)) * 1000.0, 4)
    ind_med_dt = round(float(median(ind_det_times)), 3)

    assert (rep.tp, rep.fp, rep.tn, rep.fn) == (ind_tp, ind_fp, ind_tn, ind_fn)
    assert rep.precision == ind_prec
    assert rep.recall == ind_rec
    assert rep.f1_score == ind_f1
    assert rep.false_alerts_per_1000_benign == ind_fa_1k
    assert rep.median_detection_time_ms == ind_med_dt
    # Verify honest non-gamed boundary metrics: slow-drip probing misses RULE-ID-001 (FN=3)
    # and benign typo recovery overlaps RULE-TMP-001 digest heuristic (FP=3)
    assert rep.fn == 3 and rep.detection_rate_by_attack_scenario["slow_drip_auth_probing"] == 0.0
    assert rep.fp == 3 and rep.false_positive_rate_by_benign_scenario["benign_typo_recovery"] == 1.0
    assert 0.90 <= rep.precision < 1.0 and 0.90 <= rep.recall < 1.0

    # Verify saved API response matches independent recalculation
    secops_tok = DEMO_SYNTHETIC_TOKENS["sess-secops-valid"]
    auditor_tok = DEMO_SYNTHETIC_TOKENS["sess-auditor-valid"]

    m_resp = client.get("/api/v1/detector/metrics", headers=_auth(auditor_tok))
    assert m_resp.status_code == 200
    m_json = m_resp.json()
    assert m_json["tp"] == rep.tp and m_json["fn"] == rep.fn and m_json["f1_score"] == rep.f1_score

    eval_resp = client.post("/api/v1/detector/evaluate", json={"source": "synthetic_benchmark"}, headers=_auth(secops_tok))
    assert eval_resp.status_code == 200
    run_id = eval_resp.json()["run"]["run_id"]
    run_get = client.get(f"/api/v1/detector/runs/{run_id}", headers=_auth(auditor_tok))
    assert run_get.status_code == 200 and run_get.json()["metrics"]["recall"] == rep.recall


def test_benchmark_alert_vs_scenario_and_benign_event_reconciliation() -> None:
    """Verify exact arithmetic mapping between events, scenarios, and multi-rule alerts."""
    ds = generate_synthetic_evaluation_dataset(seed=20261126)
    rep, alerts = evaluate_benchmark_dataset(ds)

    benign_scenarios = [s for s in ds.scenarios if not s.is_attack]
    attack_scenarios = [s for s in ds.scenarios if s.is_attack]
    assert len(benign_scenarios) == rep.benign_scenarios
    assert len(attack_scenarios) == rep.attack_scenarios

    # Exact benign event count equals sum of events across benign scenarios
    assert sum(len(s.event_ids) for s in benign_scenarios) == len(ds.benign_event_ids) == rep.total_benign_events

    # Multi-rule orthogonal firing explains why total_alerts_emitted > TP scenarios
    assert rep.total_alerts_emitted > rep.tp
    scenario_matched_counts = [
        len({a.fingerprint for eid in sc.event_ids for a in alerts if eid in a.event_refs})
        for sc in attack_scenarios
    ]
    assert max(scenario_matched_counts) >= 2


def test_undefined_metrics_reported_explicitly_on_empty_classes() -> None:
    empty_ds = SyntheticEvaluationDataset(
        dataset_name="empty-eval",
        dataset_version="test.v1",
        seed=1,
        events=[],
        approvals=[],
        scenarios=[],
        benign_event_ids=frozenset(),
    )
    rep, alerts = evaluate_benchmark_dataset(empty_ds)
    assert alerts == []
    assert rep.precision is None
    assert rep.recall is None
    assert rep.f1_score is None
    assert rep.false_alerts_per_1000_benign is None
    assert rep.median_detection_time_ms is None
    assert set(rep.undefined_metrics) == {
        "precision",
        "recall",
        "f1_score",
        "false_alerts_per_1000_benign",
        "median_detection_time_ms",
    }


def test_zero_denominator_partial_metric_cases_benign_only_and_all_fn() -> None:
    t0 = datetime(2026, 11, 26, 10, 0, 0, tzinfo=timezone.utc)
    # 1. Benign-only benchmark (0 attack scenarios -> TP+FN=0 -> recall/f1/median undefined)
    benign_only = SyntheticEvaluationDataset(
        dataset_name="benign-only",
        dataset_version="test.v1",
        seed=2,
        events=[
            {
                "event_id": "bo-1",
                "event_time_utc": t0.isoformat(),
                "received_time_utc": t0.isoformat(),
                "actor_id": "u-ok",
                "source_service": "portal",
                "target_service": "catalog",
                "action": "read",
                "outcome": "ALLOW",
            }
        ],
        approvals=[],
        scenarios=[EvaluationScenarioTruth("sc-bo-1", "routine_benign", False, (), t0, ("bo-1",))],
        benign_event_ids=frozenset({"bo-1"}),
    )
    rep_bo, _ = evaluate_benchmark_dataset(benign_only)
    assert rep_bo.recall is None and rep_bo.f1_score is None and rep_bo.precision is None
    assert "recall" in rep_bo.undefined_metrics and "precision" in rep_bo.undefined_metrics
    assert rep_bo.false_alerts_per_1000_benign == 0.0

    # 2. All-FN attack-only benchmark (0 TP, 0 FP -> TP+FP=0 -> precision undefined, recall=0.0, fa_per_1k undefined)
    all_fn = SyntheticEvaluationDataset(
        dataset_name="all-fn",
        dataset_version="test.v1",
        seed=3,
        events=[
            {
                "event_id": "fn-1",
                "event_time_utc": t0.isoformat(),
                "received_time_utc": t0.isoformat(),
                "actor_id": "stealth",
                "source_service": "portal",
                "target_service": "catalog",
                "action": "read",
                "outcome": "ALLOW",
            }
        ],
        approvals=[],
        scenarios=[EvaluationScenarioTruth("sc-fn-1", "stealth", True, ("RULE-ID-001",), t0, ("fn-1",))],
        benign_event_ids=frozenset(),
    )
    rep_fn, _ = evaluate_benchmark_dataset(all_fn)
    assert rep_fn.tp == 0 and rep_fn.fn == 1 and rep_fn.recall == 0.0
    assert rep_fn.precision is None and rep_fn.f1_score is None and rep_fn.false_alerts_per_1000_benign is None
    assert {"precision", "f1_score", "false_alerts_per_1000_benign", "median_detection_time_ms"}.issubset(set(rep_fn.undefined_metrics))


def test_no_ai_ml_runtime_dependencies_in_detector_modules() -> None:
    detector_dir = Path(__file__).resolve().parents[1] / "app" / "detector"
    banned = {
        "sklearn", "scikit-learn", "torch", "tensorflow", "keras", "transformers",
        "openai", "anthropic", "google.generativeai", "google.genai", "xgboost",
        "lightgbm", "catboost", "spacy", "nltk", "scipy", "statsmodels",
        "langchain", "llama_index",
    }
    hits = []
    for py_file in detector_dir.rglob("*.py"):
        tree = ast.parse(py_file.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.name in banned or a.name.split(".")[0] in banned:
                        hits.append((py_file.name, a.name))
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module in banned or node.module.split(".")[0] in banned:
                    hits.append((py_file.name, node.module))
    assert hits == []
