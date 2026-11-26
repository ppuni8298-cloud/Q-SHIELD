# Q-SHIELD — Revocation Convergence Definition & Measurement (Phase 4)

**Endpoint:** `GET /api/v1/revocations/events/{event_id}/convergence`  
**Implementation:** `measure_event_convergence()` in [backend/app/nodes/simulator.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/nodes/simulator.py)

---

## 1. Precise Definition of Convergence

An issued `RevocationEvent` `E` is **converged** across the simulated cluster (`total_nodes` in `3..7`) if and only if **every** registered node `N`:
1. Has a persisted `NodeAcknowledgement(operation_id=E.event_id, node_id=N.node_id, status="ENFORCED")`, **AND**
2. Locally holds `(E.subject_type, E.subject_id)` inside `N.local_revocations_json`.

If `converged_nodes < total_nodes`, then:
- `converged = False`
- `convergence_time_ms = None` (never reported as converged!)
- `unsynchronized_nodes = total_nodes - converged_nodes`
- `partial_max_lag_ms` reports max lag among converged nodes only, visibly distinguished from full convergence.

---

## 2. Deterministic Clock Measurement

- **Consistent Clock Source:** Each `RevocationEvent` records a deterministic integer `sim_clock_ms` (`created_sim_clock_ms`, aligned to `created_at` UTC).
- **Per-Node Enforcement Timestamp:**
  $$\text{enforced\_at\_ms}(N, E) = \max(\text{propagate\_clock\_ms}, E.\text{sim\_clock\_ms}) + N.\text{latency\_ms} + \text{extra\_delay\_ms}$$
- **Per-Node Lag:** $\text{lag\_ms}(N, E) = \text{enforced\_at\_ms}(N, E) - E.\text{sim\_clock\_ms}$
- **Cluster Convergence Time (when `converged == True`):**
  $$\text{convergence\_time\_ms}(E) = \max_{N} \text{lag\_ms}(N, E)$$
- **Summary Statistics:** Reports `p50_ms`, `p95_ms`, `p99_ms`, `convergence_time_ms`, and per-node `available`, `health`, `sync_status`, `enforced`, `enforced_at_ms`, and `lag_ms`.
- **Honest Limitation:** Zero propagation time is never claimed; offline/partitioned/faulty nodes keep `converged = False` until healed and caught up.
