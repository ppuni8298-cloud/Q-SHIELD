# Q-SHIELD — Phase 7 Detector Evaluation Metrics Report

**Evaluation Engine:** [backend/app/detector/evaluation.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/detector/evaluation.py)  
**Benchmark Dataset:** `qshield-synthetic-eval-benchmark` (`qshield.eval.v1`, `seed=20261126`)  
**Rule Set Version:** `1.0.0` (26 deterministic rules, zero AI/ML)

---

## 1. Metric Granularity & Definitions

- **Unit of Confusion Matrix (`TP`, `FP`, `TN`, `FN`):** **Scenario-level**, NOT per individual raw event and NOT per emitted alert row:
  - Each `EvaluationScenarioTruth` groups correlated events (`1–12` events per scenario).
  - **TP:** Attack scenario (`is_attack=True`) whose events are referenced by at least one emitted alert matching `expected_rule_prefixes`.
  - **FN:** Attack scenario with zero matching alerts from `expected_rule_prefixes`.
  - **FP:** Benign scenario (`is_attack=False`) whose events triggered any alert.
  - **TN:** Benign scenario with zero alerts referencing any of its events.
- **Why `74` Emitted Alerts Correspond to `43` TP Scenarios (+ `3` FP Scenarios):**
  - Several multi-event scenarios satisfy multiple orthogonal rules simultaneously:
    - `brute_force_auth` (`5` scenarios -> `20` alerts: `RULE-ID-001`, `RULE-ID-004`, `RULE-RES-003`, `RULE-TMP-001`).
    - `lateral_movement` (`5` scenarios -> `10` alerts: `RULE-LAT-001` + `RULE-LAT-002`).
    - `malicious_replay` (`5` scenarios -> `10` alerts across replay detection checks).
    - `expired_approval_escalation` (`3`), `node_convergence_failure` (`5`), `privilege_escalation` (`5`), `revoked_device_access` (`5`), `unexplained_clock_skew` (`5`), `unusual_resource_access` (`5`) -> `1` alert per scenario (`28` alerts).
    - `slow_drip_auth_probing` (`3` scenarios) fails its expected `RULE-ID-001` check (`FN=3`), though repeated empty-payload `sign_in` digests trigger `3` `RULE-TMP-001` alerts.
    - `benign_typo_recovery` (`3` benign scenarios) triggers `3` false-positive `RULE-TMP-001` alerts (`FP=3`).
    - Total = `20 + 10 + 10 + 28 + 3 + 3 = 74` emitted alerts.
- **How `162` Benign Events Relate to `66` Benign Scenarios:**
  - `routine_benign`: `30 * 3 = 90`
  - `benign_retry`: `8 * 2 = 16`
  - `approved_role_change`: `6 * 1 = 6`
  - `benign_delay_clock_offset`: `8 * 3 = 24`
  - `isolated_benign_denial`: `8 * 1 = 8`
  - `approved_custom_workflow`: `3 * 2 = 6`
  - `benign_typo_recovery`: `3 * 4 = 12`
  - Total = `66` benign scenarios containing `90 + 16 + 6 + 24 + 8 + 6 + 12 = 162` benign events.
- **Classification & Operational Formulas (Zero-Denominator Guarded):**
  - `Precision = TP / (TP + FP)` (`null` and listed in `undefined_metrics` if `TP + FP == 0`)
  - `Recall = TP / (TP + FN)` (`null` if `TP + FN == 0`)
  - `F1 = 2 * Precision * Recall / (Precision + Recall)` (`null` if denominator is `0` or either term is `null`)
  - `false_alerts_per_1000_benign = (false_alerts_on_benign / total_benign_events) * 1000.0` (`null` if `total_benign_events == 0`)
  - `median_detection_time_ms = median((first_matching_alert.last_observed_at - scenario.start_time_utc) * 1000)` over TP scenarios (`null` if empty).

---

## 2. Measured Synthetic Benchmark Results (`seed=20261126`)

| Metric | Measured Value |
|---|---|
| `total_events` | `322` (`160` attack events, `162` benign events) |
| `total_scenarios` | `112` (`46` attack scenarios, `66` benign scenarios) |
| **True Positives (TP)** | `43` |
| **False Positives (FP)** | `3` |
| **True Negatives (TN)** | `63` |
| **False Negatives (FN)** | `3` |
| **Precision** | `0.934783` (`43 / 46`) |
| **Recall** | `0.934783` (`43 / 46`) |
| **F1 Score** | `0.934783` |
| **False Alerts per 1,000 Benign Events** | `18.5185` (`3` false alerts across `162` benign events) |
| **Median Detection Time (ms)** | `6000.0` ms |
| `total_alerts_emitted` | `74` |
| `undefined_metrics` | `[]` |

### Per-Category Empirical Breakdown
- **Attack Categories (`46` scenarios):**
  - `brute_force_auth`: `1.0` (`5/5`)
  - `expired_approval_escalation`: `1.0` (`3/3`)
  - `lateral_movement`: `1.0` (`5/5`)
  - `malicious_replay`: `1.0` (`5/5`)
  - `node_convergence_failure`: `1.0` (`5/5`)
  - `privilege_escalation`: `1.0` (`5/5`)
  - `revoked_device_access`: `1.0` (`5/5`)
  - **`slow_drip_auth_probing`: `0.0` (`0/3`, `FN=3`)** — `180s` spaced failures exceed `auth_failure_window_sec=300` without triggering `RULE-ID-001`.
  - `unexplained_clock_skew`: `1.0` (`5/5`)
  - `unusual_resource_access`: `1.0` (`5/5`)
- **Benign Categories (`66` scenarios):**
  - `routine_benign`: `0.0` (`0/30`)
  - `benign_retry`: `0.0` (`0/8`)
  - `approved_role_change`: `0.0` (`0/6`)
  - `benign_delay_clock_offset`: `0.0` (`0/8`)
  - `isolated_benign_denial`: `0.0` (`0/8`)
  - `approved_custom_workflow`: `0.0` (`0/3`)
  - **`benign_typo_recovery`: `1.0` (`3/3`, `FP=3`)** — 3 transient password typos + 1 successful `sign_in` with empty payload digest triggers `RULE-TMP-001` content-replay heuristic.

---

## 3. Label Isolation & Independent Recalculation

- **Ground-Truth Label Isolation:** `NormalizedDetectorEvent` has no `label`, `ground_truth`, or `truth_label` attribute. `normalize_event_mapping()` strips those keys before rule evaluation. Verified by `test_ground_truth_label_isolation_and_reproducibility`.
- **Independent Recalculation:** Precision, Recall, F1, FA/1k, Median Time, Alert-to-Scenario cardinality, and Benign Event counts can all be recomputed directly from saved `/api/v1/detector/metrics` / `/api/v1/detector/runs/{run_id}` outputs and scenario definitions (`recalc_match=True`).

---

## 4. Honest Limitations

1. **Slow-Drip Evasion (`FN=3`):** Single-window thresholds (`300s`) miss low-and-slow credential guessing spaced `>= 180s` apart unless long-horizon rate rules are configured.
2. **Repeated Auth Typo Overlap (`FP=3`):** Content-digest replay heuristics (`RULE-TMP-001`) can over-flag harmless repeated `sign_in` attempts when upstream telemetry omits per-attempt nonces/challenge IDs.
3. **Synthetic vs Production Reality:** Although borderline/stealthy scenarios were added without tuning thresholds for artificial perfection, simulated events reflect test-model structure rather than unmodeled adversarial TTPs.
