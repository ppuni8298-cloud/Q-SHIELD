# Q-SHIELD — Phase 7 Synthetic Evaluation Dataset Specification

**Generator Module:** [backend/app/detector/dataset.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/detector/dataset.py)  
**Dataset Name:** `qshield-synthetic-eval-benchmark` (`qshield.eval.v1`)  
**Default Seed:** `20261126` (`EVAL_DEFAULT_SEED`)

---

## 1. Scenario & Event Composition (`seed=20261126`)

Calling `generate_synthetic_evaluation_dataset(seed=20261126)` deterministically produces:
- **Total Events:** `322` (`162` benign events, `160` attack scenario events)
- **Total Labeled Scenarios:** `112` (`66` benign scenarios, `46` attack scenarios)

### Benign Scenarios (`66` scenarios, `162` benign events)
1. **`routine_benign` (`30` scenarios, `90` events):** `sign_in` (`portal -> identity`) and reads (`portal -> catalog`, `reports -> catalog`).
2. **`benign_retry` (`8` scenarios, `16` events):** Legitimate retry (`is_retry_hint=True`, `2` events per scenario, within `max_legitimate_retries=2`).
3. **`approved_role_change` (`6` scenarios, `6` events):** `ROLE_CHANGED` covered by active `approvals` metadata (`valid_from_utc <= t < valid_until_utc`).
4. **`benign_delay_clock_offset` (`8` scenarios, `24` events):** Three-event sequences mixing `1s` arrival inversion (`< 5000ms`) and `+2000ms` documented `source_clock_offset_ms`.
5. **`isolated_benign_denial` (`8` scenarios, `8` events):** Single denied access to `billing` with zero retries or multi-hop follow-ons.
6. **`approved_custom_workflow` (`3` scenarios, `6` events):** Cross-service workflow (`portal -> partner_analytics -> ledger_export`) backed by active `approvals` scopes.
7. **`benign_typo_recovery` (`3` scenarios, `12` events):** Borderline scenario of 3 wrong-password `sign_in` denials followed by 1 successful `sign_in` (intentionally exercises threshold overlap without tuning).

### Attack Scenarios (`46` scenarios, `160` attack events)
1. **`brute_force_auth` (`5` scenarios, `25` events):** `5` rapid `AUTH_LOGIN_FAILED` denials (`RULE-ID-001`).
2. **`revoked_device_access` (`5` scenarios, `5` events):** Denied read from explicitly revoked devices (`RULE-DEV-001`).
3. **`lateral_movement` (`5` scenarios, `15` events):** `3`-hop unexpected traversal `reports -> billing -> archive -> identity` (`RULE-LAT-001`, `RULE-LAT-002`).
4. **`malicious_replay` (`5` scenarios, `20` events):** `4` repeated `decrypt_resource` requests with `REPLAY_DETECTED` (`RULE-TMP-001`).
5. **`unexplained_clock_skew` (`5` scenarios, `5` events):** `+25s` unexplained forward timestamp skew (`RULE-TMP-004`).
6. **`node_convergence_failure` (`5` scenarios, `5` events):** `STALE_NODE_DENIAL` with `latency_ms >= 1400ms` (`RULE-NOD-002`).
7. **`unusual_resource_access` (`5` scenarios, `60` events):** `12` rapid allowed reads per actor (`RULE-RES-001`).
8. **`privilege_escalation` (`5` scenarios, `10` events):** Unapproved `ROLE_CHANGED` + elevated read (`RULE-ID-003`).
9. **`expired_approval_escalation` (`3` scenarios, `3` events):** `ROLE_CHANGED` at exact `valid_until_utc` exclusive expiry boundary (`RULE-ID-003`).
10. **`slow_drip_auth_probing` (`3` scenarios, `12` events):** Stealth credential probing spaced `180s` apart (`540s > 300s` window) demonstrating genuine `RULE-ID-001` false-negative boundary (`FN=3`).

---

## 2. Strict Truth-Label Isolation

- Event dictionaries generated for scoring contain **no label fields** (`label`, `ground_truth`, `truth_label`, `is_attack`).
- Ground truth lives exclusively in `SyntheticEvaluationDataset.scenarios` (`EvaluationScenarioTruth`) and `benign_event_ids`.
- `ingest_event_records(...)` strips any accidental label keys before constructing frozen `NormalizedDetectorEvent` instances.
