# Q-SHIELD — Phase 7 Explainable Deterministic Threat Detection Architecture

**Status:** Implemented & Verified (Phase 7)  
**AI/ML Guarantee:** **Zero AI, Machine Learning, LLM, Embeddings, Learned Parameters, or External Network APIs at runtime.** Every alert and metric is produced solely from deterministic rules, closed-form summary statistics, bounded sliding windows, and an explicit directed service-transition graph.

---

## 1. End-to-End Architecture

```
  [Audit Ledger] / [Toolkit CSV] / [Custom Events] / [Seeded Benchmark]
         │
         ▼
  1. Integrity & Precondition Gate (`ingestion.py`)
     • Live `audit_ledger`: runs read-only `verify_ledger_db(db)` FIRST
     • Tamper / chain error -> fail closed (`409 AUDIT_CHAIN_INVALID`)
     • Empty ledger -> `DEGRADED_MISSING_EVIDENCE` (no crash)
     • Ground-truth labels (`label`, `ground_truth`, `truth_label`) stripped before `NormalizedDetectorEvent`
     • Clock correction: `corrected_event_time_utc = event_time_utc - timedelta(milliseconds=source_clock_offset_ms)`
     • Out-of-order / overlapping interval marker: `uncertain_order = True`
         │
         ▼
  2. Transparent Statistical Baselines (`baselines.py`)
     • Per-actor allowed vs denied counts and `denied_ratio`
     • Baseline `normal_services` and `normal_categories` per actor
     • Sample median & Median Absolute Deviation (MAD) + NIST modified Z-score `0.6745 * (x - med) / MAD`
     • Linear-interpolated percentiles (`compute_percentile`)
     • Non-overlapping sliding-window clusters (`sliding_window_clusters`)
         │
         ├─────────────────────────────┐
         ▼                             ▼
  3. Directed Service Graph       4. Deterministic Rule Engine
     (`graph.py`)                    (`rules.py`, 26 rules in `config.py`)
     • Unexpected directed edges     • IDENTITY_AUTH (`RULE-ID-001..005`)
       outside allowlist/approval    • DEVICE_SESSION (`RULE-DEV-001..005`)
     • >= 2 hops within window       • RESOURCE_ACCESS (`RULE-RES-001..004`)
     • Isolated single denial        • LATERAL_MOVEMENT (`RULE-LAT-001..003`)
       explicitly excluded           • NODE_REVOCATION (`RULE-NOD-001..004`)
     • Privilege rank probing        • REPLAY_TEMPORAL (`RULE-TMP-001..005`)
     • Shared-device identity pivot
         │                             │
         └──────────────┬──────────────┘
                        ▼
  5. Deduplication, Persistence & Audited Alert Lifecycle (`service.py`)
     • Stable SHA-256 fingerprint over `(rule_id, actor_id, device_id, session_id, target_key)`
     • Merges `event_refs` and updates `last_observed_at` when `(fingerprint, status in {OPEN, ACKNOWLEDGED})` exists
     • Emits tamper-evident audit events for `DETECTOR_RUN_*`, `DETECTOR_ALERT_*`, and `DETECTOR_CONFIG_UPDATED`
     • Recommendations NEVER auto-execute revocations/disables (human confirmation required)
```

---

## 2. Database & RBAC Integration

- **ORM / Migration:** [backend/alembic/versions/38153e0ad5b1_phase7_explainable_detector.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/alembic/versions/38153e0ad5b1_phase7_explainable_detector.py)
  - Extends `alerts` (`AlertRecord`) with `rule_version`, `fingerprint`, `confidence`, `device_id`, `session_id`, `node_id`, `resource_id`, `reason_codes_json`, `recommended_response`, `detection_window_sec`, `first_observed_at`, `last_observed_at`, `run_id`, `resolution_note`, `reviewed_by`, `reviewed_at`, and check constraint `ck_alerts_status`.
  - Creates `detection_runs` (`DetectionRun`, bringing total SQLite schema tables to **30**).
- **Permissions ([backend/app/identity/roles.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/identity/roles.py)):**
  - `detector:read`: `auditor`, `security_operator`, `admin`
  - `detector:run`: `security_operator`, `admin`
  - `detector:manage`: `security_operator`, `admin`
  - `owner` / unprivileged identities receive `403`.

---

## 3. REST API Surface (`/api/v1/detector`)

Defined in [backend/app/api/v1/detector.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/api/v1/detector.py):

- `GET /api/v1/detector/rules` — list all 26 deterministic rule specs + current `DetectorConfig` thresholds (`detector:read`)
- `PUT /api/v1/detector/config` — operator-audited threshold updates with explicit `reason` and `confirmation` (`detector:manage`)
- `POST /api/v1/detector/evaluate` — run deterministic detection on `audit_ledger`, `custom_events` (max 5,000 events), or `synthetic_benchmark` (`detector:run`)
- `GET /api/v1/detector/runs` & `GET /api/v1/detector/runs/{run_id}` — inspect run summaries and integrity status (`detector:read`)
- `GET /api/v1/detector/metrics` — compute benchmark confusion matrix, precision/recall/F1, false alert rate, and timing metrics (`detector:read`)
- `GET /api/v1/detector/alerts` & `GET /api/v1/detector/alerts/{alert_id}` — list/filter alerts and inspect full explainable evidence (`detector:read`)
- `POST /api/v1/detector/alerts/{alert_id}/acknowledge` (`detector:manage`)
- `POST /api/v1/detector/alerts/{alert_id}/resolve` (`detector:manage`)
- `POST /api/v1/detector/alerts/{alert_id}/false-positive` (`detector:manage`)

---

## 4. Human-in-the-Loop Safety Boundary

Detector alerts include `recommended_response` strings (e.g., advising operator review of compromised devices, sessions, or unapproved role changes), **but neither evaluation nor alert triage executes automatic revocations, account disabling, or key changes**. Operators must explicitly invoke audited control-plane endpoints with `reason` and `confirmation=True`.
