"""Scenario confusion-matrix benchmark & honest metrics calculation (Precision, Recall, F1, FA/1k, Median Time)."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass
from statistics import median
from typing import Any

from backend.app.detector.config import DetectorConfig
from backend.app.detector.dataset import EvaluationScenarioTruth, SyntheticEvaluationDataset
from backend.app.detector.ingestion import ingest_event_records
from backend.app.detector.rules import CandidateAlert, evaluate_all_rules


@dataclass(frozen=True)
class EvaluationMetricsReport:
    dataset_name: str
    dataset_version: str
    rule_set_version: str
    seed: int
    total_events: int
    total_benign_events: int
    total_scenarios: int
    attack_scenarios: int
    benign_scenarios: int
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float | None
    recall: float | None
    f1_score: float | None
    false_alerts_per_1000_benign: float | None
    median_detection_time_ms: float | None
    detection_rate_by_attack_scenario: dict[str, float | None]
    false_positive_rate_by_benign_scenario: dict[str, float | None]
    total_alerts_emitted: int
    false_alerts_on_benign: int
    undefined_metrics: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def evaluate_benchmark_dataset(
    dataset: SyntheticEvaluationDataset,
    *,
    config: DetectorConfig | None = None,
) -> tuple[EvaluationMetricsReport, list[CandidateAlert]]:
    """Run deterministic detector on isolated stripped events, then score against ground-truth scenarios."""
    active_cfg = config or DetectorConfig()
    active_cfg = DetectorConfig(**{**active_cfg.__dict__, "approvals": list(dataset.approvals)})

    # Detector receives ONLY stripped telemetry (no ground-truth labels!)
    normalized_events, _warnings = ingest_event_records(dataset.events, config=active_cfg)
    alerts = evaluate_all_rules(normalized_events, config=active_cfg)

    # Index alerts by referenced event_ids
    alerts_by_event: dict[str, list[CandidateAlert]] = defaultdict(list)
    for al in alerts:
        for eid in al.event_refs:
            alerts_by_event[eid].append(al)

    tp = 0
    fp = 0
    tn = 0
    fn = 0
    false_alerts_on_benign = 0
    seen_fp_alert_fps: set[str] = set()
    detection_times_ms: list[float] = []

    atk_totals: dict[str, int] = defaultdict(int)
    atk_hits: dict[str, int] = defaultdict(int)
    ben_totals: dict[str, int] = defaultdict(int)
    ben_fps: dict[str, int] = defaultdict(int)

    for sc in dataset.scenarios:
        matched: list[CandidateAlert] = []
        for eid in sc.event_ids:
            matched.extend(alerts_by_event.get(eid, []))

        if sc.is_attack:
            atk_totals[sc.category] += 1
            matching_expected = [
                a
                for a in matched
                if not sc.expected_rule_prefixes or any(a.rule_id.startswith(p) for p in sc.expected_rule_prefixes)
            ]
            if matching_expected:
                tp += 1
                atk_hits[sc.category] += 1
                first_alert = min(matching_expected, key=lambda a: (a.last_observed_at, a.rule_id))
                delta_ms = max(0.0, (first_alert.last_observed_at - sc.start_time_utc).total_seconds() * 1000.0)
                detection_times_ms.append(delta_ms)
            else:
                fn += 1
        else:
            ben_totals[sc.category] += 1
            unique_ben_alerts = {a.fingerprint: a for a in matched}
            if unique_ben_alerts:
                fp += 1
                ben_fps[sc.category] += 1
                for fp_key in unique_ben_alerts:
                    if fp_key not in seen_fp_alert_fps:
                        seen_fp_alert_fps.add(fp_key)
                        false_alerts_on_benign += 1
            else:
                tn += 1

    undefined_metrics: list[str] = []

    if (tp + fp) > 0:
        precision: float | None = round(tp / (tp + fp), 6)
    else:
        precision = None
        undefined_metrics.append("precision")

    if (tp + fn) > 0:
        recall: float | None = round(tp / (tp + fn), 6)
    else:
        recall = None
        undefined_metrics.append("recall")

    if precision is not None and recall is not None and (precision + recall) > 0:
        f1: float | None = round(2 * precision * recall / (precision + recall), 6)
    else:
        f1 = None
        undefined_metrics.append("f1_score")

    ben_ev_count = len(dataset.benign_event_ids)
    if ben_ev_count > 0:
        fa_per_1k: float | None = round((false_alerts_on_benign / ben_ev_count) * 1000.0, 4)
    else:
        fa_per_1k = None
        undefined_metrics.append("false_alerts_per_1000_benign")

    if detection_times_ms:
        med_det: float | None = round(float(median(detection_times_ms)), 3)
    else:
        med_det = None
        undefined_metrics.append("median_detection_time_ms")

    det_by_atk = {
        cat: round(atk_hits[cat] / cnt, 6) if cnt > 0 else None
        for cat, cnt in sorted(atk_totals.items())
    }
    fpr_by_ben = {
        cat: round(ben_fps[cat] / cnt, 6) if cnt > 0 else None
        for cat, cnt in sorted(ben_totals.items())
    }

    report = EvaluationMetricsReport(
        dataset_name=dataset.dataset_name,
        dataset_version=dataset.dataset_version,
        rule_set_version=active_cfg.rule_set_version,
        seed=dataset.seed,
        total_events=len(dataset.events),
        total_benign_events=ben_ev_count,
        total_scenarios=len(dataset.scenarios),
        attack_scenarios=tp + fn,
        benign_scenarios=tn + fp,
        tp=tp,
        fp=fp,
        tn=tn,
        fn=fn,
        precision=precision,
        recall=recall,
        f1_score=f1,
        false_alerts_per_1000_benign=fa_per_1k,
        median_detection_time_ms=med_det,
        detection_rate_by_attack_scenario=det_by_atk,
        false_positive_rate_by_benign_scenario=fpr_by_ben,
        total_alerts_emitted=len(alerts),
        false_alerts_on_benign=false_alerts_on_benign,
        undefined_metrics=undefined_metrics,
    )
    return report, alerts
