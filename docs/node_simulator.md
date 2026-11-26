# Q-SHIELD — Simulated Logical Node Cluster (Phase 4)

**Module:** [backend/app/nodes/simulator.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/nodes/simulator.py)  
**Scope Disclaimer:** These are deterministic simulated logical nodes inside the SQLite-backed modular monolith. They are **not** deployed physical servers or real distributed consensus (Raft/Paxos).

---

## 1. Node Cluster Model (`node_registry` + `node_event_inbox` + `node_acknowledgements`)

- **Configurable Node Count:** Strictly bounded `3 <= node_count <= 7` (`POST /api/v1/nodes/configure`). Default seed creates 3 nodes (`node-1`, `node-2`, `node-3`) with deterministic latencies (`10ms`, `25ms`, `45ms`).
- **Independent Per-Node State:** Each node stores:
  - `node_id`, `service`, `health` (`HEALTHY`, `DEGRADED`, `OFFLINE`, `PARTITIONED`)
  - `available` (`bool`), `fault_mode` (`NONE`, `OFFLINE`, `PARTITIONED`, `DROP_EVENTS`, `PROCESSING_ERROR`, `STALE_TRUST`)
  - `latency_profile` & `latency_ms`
  - `current_epoch`, `last_event_seq`, `last_applied_event_id`
  - `sync_status` (`CONVERGED`, `PENDING`, `UNSYNCHRONIZED`, `FAILED`)
  - `local_revocations_json` (per-node local map of revoked `actor`, `device`, `key`, `session` IDs)
  - `node_event_inbox` queue tracking `QUEUED`, `DELIVERED`, `APPLIED`, `DUPLICATE_IGNORED`, `STALE_IGNORED`, `FAILED`, `DROPPED`.

---

## 2. Fail-Closed Access Evaluation (`POST /api/v1/nodes/{node_id}/access`)

When a caller attempts protected access via a specific simulated node:
1. **Availability & Health Check:** Unavailable, `OFFLINE`, `PARTITIONED`, `DEGRADED`, or fault-injected nodes fail closed (`403 DENY_NODE_UNAVAILABLE`).
2. **Node-Local Revocation Check:** Checks `node.local_revocations_json` for revoked `actor`, `device`, `session`, or resource `key_id`/`key_version` -> `403 DENY_NODE_LOCAL_REVOKED_*`.
3. **Stale Trust Protection:** If `node.sync_status != "CONVERGED"` or `node.last_event_seq < latest_global_sequence`, the node refuses to silently authorize and fails closed (`403 DENY_NODE_STALE_TRUST_STATE`).
4. **Central 10-Step Zero-Trust Policy & Optional AEAD Decryption:** Delegates to `ZeroTrustPolicyEngine` and Phase 3 `decrypt_resource_content` (zero plaintext on any denial or error).

---

## 3. Restart & Fault Simulation

- `POST /api/v1/nodes/{node_id}/availability`: Injects `OFFLINE`, `PARTITIONED`, `DROP_EVENTS`, `PROCESSING_ERROR`, or `STALE_TRUST` faults, or restores availability (`NONE`).
- `POST /api/v1/nodes/{node_id}/restart`: Reloads persisted `local_revocations_json`, `last_event_seq`, `current_epoch`, and pending inbox queue from SQLite without erasing applied revocations.
- `POST /api/v1/nodes/scenarios/{scenario_name}`: Executes deterministic scenarios (`offline_and_catchup`, `multi_offline`, `duplicate_and_out_of_order`, `drop_and_processing_failure`).
