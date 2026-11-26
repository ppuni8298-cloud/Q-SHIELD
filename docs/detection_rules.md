# Q-SHIELD — Phase 7 Deterministic Detection Rules Catalog (`v1.0.0`)

All **26 rules** in [backend/app/detector/config.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/detector/config.py) and [backend/app/detector/rules.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/detector/rules.py) operate purely on `NormalizedDetectorEvent` fields without ground-truth labels or ML inference.

---

## 1. Identity & Authentication Rules (`IDENTITY_AUTH`)

| Rule ID | Title | Severity | Base Weight | Default Threshold / Logic |
|---|---|---|---|---|
| `RULE-ID-001` | Repeated authentication failures in sliding window | `HIGH` | `0.80` | `>= 4` failed/denied login events for an actor within `300s`. |
| `RULE-ID-002` | Rapid identity switching from same device/source | `HIGH` | `0.78` | `>= 3` distinct `actor_id` values sharing one `device_id` within `180s`. |
| `RULE-ID-003` | Unapproved privilege or role escalation | `CRITICAL` | `0.92` | `ROLE_CHANGED` / `role_change` / `approve_role_change` lacking an active matching approval record (`valid_from_utc <= t < valid_until_utc`, subject & role/scope match). |
| `RULE-ID-004` | Revoked or disabled identity attempting access | `HIGH` | `0.88` | `>= 2` denials matching disabled/inactive/revoked identity reason codes. |
| `RULE-ID-005` | Access outside actor baseline authorization scope | `MEDIUM` | `0.68` | Actor attempts denied access to a service outside its historical baseline `normal_services` and not covered by valid approvals. |

---

## 2. Device & Session Rules (`DEVICE_SESSION`)

| Rule ID | Title | Severity | Base Weight | Default Threshold / Logic |
|---|---|---|---|---|
| `RULE-DEV-001` | Revoked device attempting protected access | `CRITICAL` | `0.90` | Any denial containing `REVOKED` + `DEVICE` (`DENY_DEVICE_REVOKED`, `DEVICE_REVOKED`). |
| `RULE-DEV-002` | Unusual actor cardinality bound to a single device | `MEDIUM` | `0.70` | Distinct identities associated with one device `>= 3` over `600s` (distinct from rapid login burst). |
| `RULE-DEV-003` | Suspicious session creation burst | `HIGH` | `0.76` | `>= 5` login/session-creation events for an actor within `120s`. |
| `RULE-DEV-004` | Repeated use of expired or revoked sessions | `HIGH` | `0.80` | `>= 2` denials with `SESSION_EXPIRED` / `SESSION_REVOKED` reason codes for an actor/session. |
| `RULE-DEV-005` | Unusual session activity using pre-cutoff key post-rotation | `HIGH` | `0.84` | `>= 2` denials matching `OLD_KEY_CUTOFF_DENIAL` / `DENY_NODE_OLD_KEY_CUTOFF` / `KEY_REVOKED`. |

---

## 3. Protected-Resource Access Rules (`RESOURCE_ACCESS`)

| Rule ID | Title | Severity | Base Weight | Default Threshold / Logic |
|---|---|---|---|---|
| `RULE-RES-001` | Excessive protected-resource reads above baseline | `HIGH` | `0.82` | Triggered if allowed read cluster count `>= 10` in `120s` **or** NIST modified MAD Z-score `>= 3.5` relative to population baseline. |
| `RULE-RES-002` | Rapid access across unrelated resource categories | `MEDIUM` | `0.72` | Triggered when `outcome in ("ALLOW", "SUCCESS")` reads span `>= 3` distinct non-default `resource_category` values within `180s` (prevents single isolated denials from creating false category diversity). |
| `RULE-RES-003` | Anomalous denied-to-allowed access ratio | `MEDIUM` | `0.74` | Triggered when `denied / (denied + allowed) >= 0.60` with total samples `>= 5`. |
| `RULE-RES-004` | Repeated attempts after authorization denial | `HIGH` | `0.78` | `>= 3` denials targeting the same `resource_id` within `180s` (never triggers on 1 isolated denial). |

---

## 4. Lateral Movement & Graph Rules (`LATERAL_MOVEMENT`)

Implemented in [backend/app/detector/graph.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/detector/graph.py):

| Rule ID | Title | Severity | Base Weight | Default Threshold / Logic |
|---|---|---|---|---|
| `RULE-LAT-001` | Multi-hop unexpected service-graph lateral movement | `CRITICAL` | `0.90` | Directed edges `(source_service, target_service)` outside `allowed_service_edges` and actor approvals forming `>= 2` unexpected hops within `300s`. Output includes full edge list (`services_touched`), `path_edges`, and contributing `event_refs`. Single isolated denials (`len == 1`) are explicitly excluded. |
| `RULE-LAT-002` | Sequential probing across privilege tiers | `HIGH` | `0.82` | Sequential service/role probing spanning `>= 2` distinct privilege tiers (`ROLE_PRIVILEGE_RANK`) in a window. |
| `RULE-LAT-003` | Identity pivot from shared source following denials | `HIGH` | `0.84` | Repeated denials under Identity A followed within `300s` by probes under Identity B sharing the same `device_id`. |

---

## 5. Node & Revocation Anomaly Rules (`NODE_REVOCATION`)

| Rule ID | Title | Severity | Base Weight | Default Threshold / Logic |
|---|---|---|---|---|
| `RULE-NOD-001` | Persistent post-revocation access hammering across nodes | `HIGH` | `0.82` | `>= 3` denials across simulated nodes post-revocation. |
| `RULE-NOD-002` | Stale node or delayed convergence beyond tolerance | `HIGH` | `0.80` | `STALE_NODE_DENIAL`, `UNSYNCHRONIZED`, `DENY_NODE_STALE_TRUST_STATE`, or `latency_ms > 500`. |
| `RULE-NOD-003` | Conflicting node trust state or repeated propagation failures | `HIGH` | `0.82` | `>= 2` propagation failures (`DROP_EVENTS` / `PROCESSING_ERROR` / `FAILED`) or conflicting convergence reports. |
| `RULE-NOD-004` | Unexpected revocation-event ordering or rollback attempt | `HIGH` | `0.84` | `STALE_IGNORED` rollback attempts or out-of-order revocation sequence delivery. |

---

## 6. Replay & Temporal Rules (`REPLAY_TEMPORAL`)

| Rule ID | Title | Severity | Base Weight | Default Threshold / Logic |
|---|---|---|---|---|
| `RULE-TMP-001` | Malicious duplicate or replay pattern | `HIGH` | `0.86` | Rejects explicit `REPLAY_DETECTED`, cross-actor digest duplicates, or repeated `(actor, action, target, payload_digest)` bursts `> max_legitimate_retries (2)` while allowing benign transient retries (`is_retry_hint=True`, `<= 2`). |
| `RULE-TMP-002` | Reused event identifier with divergent contents | `CRITICAL` | `0.92` | Same `event_id` observed with conflicting actor/action/target/payload digest. |
| `RULE-TMP-003` | Anomalous out-of-order sequence or arrival inversion | `MEDIUM` | `0.70` | Sequence inversions or arrival inversion exceeding `reorder_window_ms = 5000ms` (minor benign delayed delivery within `5s` preserves `uncertain_order=True` without false alerting). |
| `RULE-TMP-004` | Unexplained clock skew beyond configured tolerance | `HIGH` | `0.78` | Flags `|event_time - source_clock_offset_ms - received_time| > 1500ms`. Documented offsets (e.g., `evt-015` with `source_clock_offset_ms=+2000`) calibrate cleanly near `0ms` residual and do not false-positive. |
| `RULE-TMP-005` | Anomalous event burst inconsistent with simulation clock | `MEDIUM` | `0.72` | `>= 8` events within `<= 1000ms` or negative simulation clock regression (`sim_clock_ms` decreasing). |
