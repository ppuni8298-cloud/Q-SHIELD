# Q-SHIELD — System Architecture Blueprint (Phase 0)

**Status:** Phase 0 Design Blueprint (Not Yet Implemented)  
**Architecture Style:** Modular Monolith + Deterministic Multi-Node Simulator + Zero-3P-Dependency Root Adapter Boundary

---

## 1. Evaluation of Prescribed Stack

| Layer | Prescribed Stack | Local Env Verification (Phase 0) | Design Evaluation & Fit |
|---|---|---|---|
| **Toolkit Adapter Boundary** | Python 3.12 stdlib + `pqcrypto==0.4.0` (`track4_service.py`) | Python 3.11.9 locally; Python 3.12 & `pqcrypto==0.4.0` missing (Phase 1 prereq) | **Mandatory isolation:** Judging container runs offline Linux with read-only root, Python 3.12, `pqcrypto==0.4.0`, and does NOT install submission dependencies. Keeping `track4_service.py` + `qshield_core` free of web/ORM 3P packages prevents `ModuleNotFoundError` in judge runs. |
| **Backend Web & API** | Python 3.12 + FastAPI + Pydantic v2 + SQLAlchemy 2 + Alembic | FastAPI `0.141.1`, Pydantic `2.13.4`, SQLAlchemy `2.0.51` present on Python 3.11; Alembic missing | Fits cleanly as the local control-plane server exposing `/api/v1` + OpenAPI, typed request/response validation, and DB migrations. |
| **Database** | SQLite (WAL, `foreign_keys=ON`, `busy_timeout`, transactions) | Python `sqlite3` (`3.45.1`) present | Ideal for offline/portable single-machine judge demo. Note: SQLite provides local ACID durability, NOT distributed consensus (must be documented honestly). |
| **Cryptography** | `pqcrypto==0.4.0` (ML-KEM-768, ML-DSA if present) + `cryptography` (AES-256-GCM/HKDF) + stdlib `hmac`/`hashlib`/`secrets` | `cryptography` `50.0.2` present on Python 3.11; `pqcrypto==0.4.0` missing | Vetted primitives only. Adapter uses stdlib + `pqcrypto==0.4.0`; full backend uses `pqcrypto==0.4.0` + `cryptography` (or stdlib HMAC/HKDF). |
| **Node Cluster** | Deterministic in-process / SQLite-backed simulator (3–7 nodes) | N/A (custom app module) | Explicitly avoids unnecessary Docker/Kubernetes/Kafka/real distributed servers; supports deterministic seeds, configurable latency profiles, and fault injection. |
| **Frontend** | React + TypeScript + Vite + Tailwind + TanStack Query + React Router + Recharts | Node `v24.11.1` & npm `11.13.0` present (exact Node match) | Clean SPA talking strictly to FastAPI `/api/v1`; built statically or served via Vite dev server; zero influence on offline `track4_service.py` path. |
| **Testing & Benchmarking** | `pytest`, `pytest-cov`, `httpx`, `Hypothesis` (optional), Playwright (optional), `time.perf_counter_ns`, `psutil` | `pytest` `9.1.1`, `httpx` `0.28.1`, `psutil` `7.2.2` present; `pytest-cov` & `hypothesis` missing | Supports independent black-box API tests, subprocess adapter contract tests, crypto KATs, and empirical benchmarks. |
| **AI/ML** | **PROHIBITED** | N/A | Zero ML libraries (`torch`, `scikit-learn`, `transformers`, LLM APIs) allowed in Q-SHIELD runtime or dependencies. |

---

## 2. Logical Architecture & Trust-Boundary Flow

```text
+-------------------------------------------------------------------------+
|                    PATH A: OFFICIAL JUDGE / TOOLKIT ADAPTER             |
|                                                                         |
|  Toolkit Worker / validate.py                                           |
|        |  (1 UTF-8 JSON via stdin -> fresh process -> 1 JSON stdout)    |
|        v                                                                |
|  track4_service.py (Repo Root - ONLY adapter entrypoint)                |
|        |  imports ONLY Python 3.12 stdlib + pqcrypto==0.4.0             |
|        v                                                                |
|  Adapter Core (setup / read / revoke / audit / protected_read)          |
|        |  atomic transactions in $TRACK4_STATE_DIR or OS tempdir        |
|        v                                                                |
|  SQLite State DB + PQC ML-KEM-768 / HMAC-SHA-256 + Audit Correlation    |
+-------------------------------------------------------------------------+

+-------------------------------------------------------------------------+
|                  PATH B: FULL CONTROL PLANE & CONSOLE                   |
|                                                                         |
|  Browser (React + TS + Vite SPA)                                        |
|        |  HTTPS/HTTP JSON (/api/v1/*)                                   |
|        v                                                                |
|  FastAPI Gateway (Auth, Rate Limit, Correlation IDs, Pydantic v2)       |
|        |                                                                |
|        v                                                                |
|  Zero-Trust Policy Engine (10-step ordered fail-closed evaluation)      |
|        |                                                                |
|        +---> Identity, RBAC & Session Manager (hashed tokens, binding)  |
|        +---> Device Registry (enroll, suspend, revoke, re-enroll)       |
|        +---> Key Lifecycle & Cryptographic Vault (DEK/KEK, AES-GCM, PQC)|
|        +---> Revocation Coordinator <---> Deterministic Node Simulator  |
|        |                                   (3-7 nodes, epochs, faults)  |
|        +---> Crash Recovery Journal & Signed Backup Manager             |
|        +---> Secure Messaging & Replay/Delivery/Resumption Subsystem    |
|        +---> Explainable Detector & Graph Engine (rules/stats/skew, NO ML)|
|        +---> Append-Only Audit Ledger & Receipt/Evidence Verifier       |
|        +---> Benchmark Lab & 14-Scenario Orchestrator                   |
|        |                                                                |
|        v                                                                |
|  SQLite DB (WAL, FK=ON, Alembic) + Local Encrypted Keystore + Reports   |
+-------------------------------------------------------------------------+
```

---

## 3. Module Responsibilities & Interactions (13 Core Responsibilities + 15 Prompt Modules)

| Module | Prompt Modules Covered | Core Responsibilities | Primary Interactions |
|---|---|---|---|
| **1. Official Toolkit Adapter** | #1 Adapter/process boundary | Reads 1 JSON object from `stdin`, enforces payload validation, dispatches `setup`/`read`/`revoke`/`audit`/`protected_read`, writes 1 JSON object (`allow_nan=False`) to `stdout`, sanitizes `stderr`, caps output `<64 KiB`, uses zero 3P web packages. | Calls **Adapter Core** (shared policy/vault/audit/ML-KEM primitives) backed by `TRACK4_STATE_DIR` / tempdir SQLite DB. |
| **2. Core Trust & Authorization Engine** | #2 Domain services, #3 Identity & access policy | Implements the 10-step ordered Zero-Trust evaluation pipeline (`parse -> identity -> session -> expiry -> device -> RBAC/ownership -> resource -> key version -> incident deny -> ALLOW/DENY + reason + correlation_id`) and fail-closed defaults. | Queried by every mutating/reading FastAPI endpoint, Adapter, Vault, Messaging, and Node checks. |
| **3. Identity & Device Management** | #3 Identity/RBAC, #4 Device registry | Manages synthetic users (`Owner/User`, `Security Operator`, `Admin`, `Auditor`), RBAC matrix, device states (`PENDING`, `TRUSTED`, `SUSPENDED`, `REVOKED`), monotonic `state_version`, lost-device revocation, and replacement re-enrollment (blocking old credential). | Updates **DB**; triggers **Revocation Coordinator** & **Audit Engine**; emits **Proof-Carrying Receipts**. |
| **4. Cryptographic Vault** | #6 Crypto provider facade, #7 Protected resource vault | Wraps vetted primitives (`pqcrypto` ML-KEM-768 & ML-DSA, `cryptography` AES-256-GCM, HKDF-SHA-256, HMAC-SHA-256, SHA-256, `secrets`). Manages per-resource random DEKs wrapped by KEK, authenticated metadata AAD, startup KAT self-test, and strict plaintext protection on failure. | Used by **Adapter `protected_read`**, **Vault API**, **Key Lifecycle**, **Messaging**, **Backups**, and **Audit Checkpoints**. |
| **5. Key Lifecycle Management** | #8 Key lifecycle/state machine, #10 Recovery & backups | Enforces `PREPARED -> ACTIVE -> ROTATING -> ACTIVE_NEW -> RETIRED/REVOKED` and terminal `COMPROMISED` (no reactivation). Coordinates 4-phase rotation (`PREPARE -> DISTRIBUTE -> COMMIT -> RETIRE`), zero-grace cutoff policy, DEK rewrap, crash journal recovery, and signed/checksummed backups. | Writes **Rotation Journal** & **Backup Manifests**; pushes staged/committed versions to **Node Simulator**; logs to **Audit Engine**. |
| **6. Revocation Coordinator** | #2 Domain orchestration, #9 Revocation propagation | Executes atomic revocation workflow: verifies operator authz & reason, persists intent + monotonic epoch + durable revocation tombstone prior to ack, updates central policy immediately, dispatches signed/authenticated control events to nodes, and computes `convergence_time = last_node_enforced_at - revoke_started_at`. | Coordinates **Identity/Devices/Keys**, **Simulated Nodes**, **Audit Engine**, and **Incident Receipts**. |
| **7. Simulated Nodes** | #9 Node simulator & convergence | Simulates 3–7 configurable logical service nodes (`node_registry`, `node_acknowledgements`) in deterministic/profiled latency modes. Each node verifies event authenticity & monotonic sequence, rejects stale/out-of-order updates, enforces cutoff, supports partition/latency fault injection, and fails closed when unreachable where required. | Receives events from **Revocation Coordinator** & **Key Lifecycle**; serves simulated node read checks; reports convergence telemetry. |
| **8. Audit & Evidence Engine** | #11 Audit append-only ledger & verifier, #13 Metrics | Maintains append-only structured JSON audit events (`sequence`, UTC+monotonic timestamps, server-authenticated actor/action enums, `prev_hash`, `event_hash = SHA256(prev_hash \|\| canonical_bytes)`), periodic ML-DSA checkpoints, log-injection escaping, secret redaction, Proof-Carrying Trust Change receipts, and Evidence Scorecard exports. | Consumed by ALL state-changing and access modules; queried by **Frontend Audit & Evidence** and `audit` adapter op. |
| **9. Deterministic Threat Detector** | #12 Explainable detection engine | Ingests toolkit CSV/JSON and app events via schema-flexible parser; runs deterministic rules (privilege escalation, self-escalation, revoked attempts, service-access anomalies), directed time-windowed lateral-movement graph, context suppression (`approvals.json`, maintenance), bounded reorder window/watermarks (`5s` default, configurable), clock-offset correction with uncertainty-overlap flagging, and labelled metric calculation (TP/FP/TN/FN, F1, median alert time, false alerts/1k benign). | Reads **Detector Events**, **Approvals/Context**, and **Audit/Access Logs**; writes **Alerts** with rule/path/event citations. |
| **10. Secure Messaging & Session Manager** | #5 Session manager, #7 Message subsystem | Manages hashed bearer sessions bound to `(actor, device, peer, expiry, auth_strength)` and peer-bound resumption tokens (fresh policy check on resume). Runs E2E messaging lab: AES-GCM AAD with recipient binding verified before decrypt, durable replay ledger (`message_id` + sequence), bounded loss/reordering recovery buffer, and honest forward-secrecy protocol/limitation tracking. | Uses **Crypto Vault** & **Policy Engine**; persists `sessions`, `sessions_crypto`, `messages`, and `replay_records`. |
| **11. REST API** | #14 API/UI, #15 Seed/CLI | FastAPI `/api/v1` routers for Auth, Users/Roles, Devices, Vault, Keys/Backups, Nodes, Incidents/Receipts, Messages, Detector, Audit, Benchmarks, Evidence, and 14-Scenario Reset/Launcher, plus reproducible `scripts/seed` & `scripts/benchmark.py`. | Exposes domain services to **Frontend** & **API Contract Tests**. |
| **12. Frontend Dashboard** | #14 UI | React + TypeScript + Vite SPA: Public Landing, Synthetic Demo Login, and 14 console views (Overview, Identity & Access, Devices, Secure Vault, Key Lifecycle, Node Control Plane, Incident Center, Detection & Lateral Movement, Secure Messaging Lab, Audit & Evidence, Benchmark Lab, Attack/Failure Simulation, Requirements Scorecard, Settings/Docs). | Consumes **REST API `/api/v1/*`**; zero client-side security enforcement or fake toggles. |
| **13. Test & Validation Framework** | Cross-cutting QA | Independent black-box test suites (`tests/adapter/`, `tests/crypto/`, `tests/security/`, `tests/recovery/`, `tests/detector/`, `tests/messaging/`, `tests/integration/`, `tests/e2e/`), official `validate.py` runner script, `scripts/benchmark.py`, and `scripts/security_checks.sh`. | Exercises **Root Adapter**, **REST API**, and **Frontend** against requirement specifications without sharing implementation logic. |

---

## 4. Database & Persistence Strategy

- **Engine:** SQLite 3 (`PRAGMA journal_mode=WAL`, `PRAGMA foreign_keys=ON`, `PRAGMA busy_timeout=5000`, explicit `BEGIN IMMEDIATE` transactions for mutating/revocation/rotation operations).
- **Migrations:** Managed by Alembic (`alembic upgrade head`) from empty DB for the full backend; adapter path bootstraps or reads its compatible SQLite schema inside `$TRACK4_STATE_DIR` using stdlib `sqlite3` without requiring Alembic at judge runtime.
- **23 Minimum Tables (Master PDF Sec 12):** `users`, `devices`, `sessions`, `resources`, `resource_permissions`, `encrypted_objects`, `key_metadata`, `rotation_operations`, `node_registry`, `node_acknowledgements`, `revocation_tombstones`, `incidents`, `audit_events`, `audit_checkpoints`, `access_requests`, `messages`, `sessions_crypto`, `replay_records`, `detector_events`, `alerts`, `benchmarks`, `backup_manifests`, `settings`.
- **No Raw Secrets in Standard Tables:** `sessions` stores token hashes; `key_metadata` stores IDs/versions/purposes/states only; `messages` stores AEAD envelopes only; `audit_events` redacts secrets and protected bodies.
