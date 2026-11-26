# Q-SHIELD — Independent Testing Strategy (Phase 0)

**Principle:** Tests must be derived independently from the Official Toolkit Contract (`docs/adapter-v1.md`) and Q-SHIELD Master Build Prompt—not by reading application code to mirror its assumptions. Never mock away the security property under test, never suppress failing tests, and never fabricate results.

---

## 1. Coverage Matrix: Public Validator vs. Independent Suite vs. Deferred

| Test Category | Public Validator (`validate.py`) Coverage | Independent Test Suite Coverage (Must Build) | Deferred Until Implementation Phase |
|---|---|---|---|
| **A. Official Compliance** | Runs `setup`, `read` (owner/peer/wrong-owner/post-revocation), `revoke`, `audit` (denied read), fresh rerun, stdout JSON format, 64 KiB cap, 8s timeout, `key_material` leak check. | Same-dir `setup` reset, initially `disabled` actors, `audit` on `allow` & unknown `request_id`, `protected_read` full workflow, malformed JSON/NaN/missing-field exit/error checks, zero-3P-import offline container check. | Phase 1 (`track4_service.py` + `tests/adapter/`) |
| **B. Functional Correctness** | Lost-device read/revoke/peer/audit only. | RBAC matrix, 10-step policy ordering, device enroll/suspend/restore/revoke/re-enroll, vault envelope encrypt/read, key rotation phases, crash recovery, backup restore, messaging delivery/resumption. | Phases 2–8 |
| **C. Security** | Wrong-owner deny, post-revoke deny, nested body leak on deny, `key_material` leak in stdout/stderr. | Cross-owner/cross-device session hijack, self-escalation, unauthorized operator actions, revoked key non-reactivation, post-cutoff old-key denial, AEAD/signature/backup/audit tamper, log injection, replay, recipient binding, rate limiting, secret scan. | Phases 1–10 |
| **D. Cryptographic Verification** | **NONE** (explicitly excluded by `validate.py` docstring). | ML-KEM-768 independent decapsulation + HMAC-SHA-256 (`UTF8(challenge + body)`) interop, KAT vectors, invalid Base64/key-length rejection, ML-DSA sign/verify/tamper, AES-GCM AAD tamper, HKDF separation, startup self-test. | Phase 1 (`protected_read`) & Phase 3 (full vault) |
| **E. Reliability** | Fresh process per request (`TRACK4_STATE_DIR`), fresh temp dir rerun. | Simulated crash injection at all 7 rotation/revocation points, backup restore & idempotency, concurrent read-vs-revoke race tests, 3–7 node partition/lag/reconciliation, clock skew & event reordering, DB rollback/corrupt DB fail-safe. | Phases 4–5 & 7–8 |
| **F. Detection** | **NONE** (`practice/` dataset is manual/self-checked). | Toolkit `practice/` (`events.csv`, `labels.csv`, `approvals.json`) exact scoring (`evt-001..022`), 6 curated JSONL fixtures, seeded synthetic generator, renamed-entity anti-hardcoding test, confusion matrix, F1, false alerts/1k benign, median/P95 alert latency, clock uncertainty overlap. | Phase 7 |
| **G. Frontend** | **NONE**. | Production Vite TypeScript build (`tsc --noEmit && npm run build`), API wiring checks (no fake toggles), Playwright E2E smoke tests across landing, login, 14 pages, 14 scenarios, responsive viewports, zero console/page errors. | Phase 9 |
| **H. Delivery & Benchmarks** | **NONE** (`validate.py` explicitly notes timing is not tested). | Clean-venv offline install (`pyproject.toml` / pinned reqs), zero external network test, `scripts/benchmark.py` (`time.perf_counter_ns`, warmups, >=100 lightweight samples, CPU/RSS), `scripts/security_checks.sh`. | Phase 10–11 |

---

## 2. Detailed Test Suites & Measurable Acceptance Criteria

### A. Official Compliance (`tests/adapter/`)
- **Tests:**
  - Run official `python validate.py --entry <repo>/track4_service.py` from `Track-4-Toolkit`.
  - Subprocess protocol tests: 1 JSON stdin -> 1 JSON stdout, `allow_nan=False`, exit 0 on valid handled calls, stderr-only diagnostics, `< 64 KiB` output, zero lingering child processes.
  - Environment isolation test: run `track4_service.py` in a minimal Python 3.12 environment containing **only** stdlib + `pqcrypto==0.4.0` (no FastAPI/SQLAlchemy/cryptography) with repo directory treated as read-only (`TRACK4_STATE_DIR` writable).
- **Acceptance Criteria:**
  - `validate.py` exits `0` with 100% `PASS` across all format/setup/behavior checks.
  - Isolated container-parity test passes all 5 operations with `0` import errors and `0` writes to repo root.

### B. Functional Correctness (`tests/security/`, `tests/integration/`, `tests/recovery/`)
- **Tests:** Black-box FastAPI (`httpx.AsyncClient`/`TestClient`) and domain tests covering users, roles, devices, resources, keys, nodes, incidents/receipts, audit, detector, messaging, and all 14 resettable scenarios.
- **Acceptance Criteria:**
  - 100% of API endpoints match OpenAPI Pydantic schemas; every mutating endpoint enforces authz, emits an audit event, and returns a correlation ID.
  - All 14 demo scenarios execute end-to-end from reset state without skipped assertions.

### C. Security Invariants (`tests/security/`)
- **Tests:**
  - Ordered 10-step policy tests: inject failure at each step 1..9 and verify exact `DENY` reason code and zero plaintext leakage.
  - Privilege escalation & operator authz: owner/viewer attempting `/keys/rotate`, `/users` role upgrade, or `/devices/revoke` without operator/admin role rejected (`403`).
  - Log injection: submit `actor`/comment/metadata containing `\n`, `\r`, ANSI codes, or fake JSON lines `{"actor":"admin","action":"allow"}`; verify stored as escaped single record with server-authenticated actor intact.
  - Secret leakage scan across all error payloads, denied responses, audit exports, and benchmark reports.
- **Acceptance Criteria:**
  - `0` unauthorized `allow`/`200` decisions; `0` occurrences of synthetic `key_material`, `shared_secret`, private keys, tokens, or file plaintext in any deny/error/log/export output.
  - `100%` of tampered audit chains (modify, delete, swap order, alter actor, inject boundary) detected by verifier.

### D. Cryptographic Verification (`tests/crypto/`)
- **Tests:**
  - `protected_read` ML-KEM-768 interop: independent test client generates ML-KEM-768 keypair via `pqcrypto==0.4.0`, calls `track4_service.py` `protected_read`, decapsulates `ciphertext`, computes `hmac.new(shared_secret, (challenge + body).encode("utf-8"), hashlib.sha256).hexdigest()`, asserts exact match with `proof`.
  - Negative `protected_read` tests: bad Base64, wrong key byte length, empty/invalid challenge, revoked actor, wrong owner.
  - AEAD & AAD tamper tests: 1-bit flip in ciphertext, tag, nonce, or any AAD metadata field (`sender_id`, `recipient_id`, `message_id`, `session_id`, `key_version`, `protocol_version`).
  - ML-DSA sign/verify & tamper tests (if supported by `pqcrypto==0.4.0`); HKDF domain-separation tests; startup self-test pass & fail-closed test.
- **Acceptance Criteria:**
  - `100%` roundtrip interop match; `0` plaintext/shared-secret bytes released on any tamper, invalid key, or unauthorized attempt.

### E. Reliability, Concurrency & Crash Recovery (`tests/recovery/`)
- **Tests:**
  - Crash matrix: simulate process termination at all 7 checkpoints (`after PREPARE`, `after backup`, `after node 1/2 ack`, `before COMMIT`, `immediately after COMMIT`, `during RETIRE`, `after revocation tombstone`), restart recovery engine, verify active key version and revocation persistence.
  - Backup matrix: valid restore, 1-byte corrupted backup, wrong-key backup, truncated backup, stale pre-revocation backup, duplicate restore idempotency.
  - Concurrency race: parallel threads/processes issuing `read` overlapping `revoke` and key rotation cutoff.
  - Node simulator: 3, 5, and 7 nodes under configurable latency profiles and partition/recovery faults.
- **Acceptance Criteria:**
  - `0` revoked or compromised keys reactivated across all 7 crash scenarios and all backup scenarios.
  - `old_key_post_cutoff_acceptance == 0`; unaffected authorized peer retains `100%` access; duplicate backup restore is idempotent.

### F. Explainable Detection & Clock Skew (`tests/detector/`)
- **Tests:**
  - Evaluate official toolkit `practice/events.csv` + `practice/approvals.json` against `practice/labels.csv`: verify `evt-003/004/005` benign approved flow, `evt-008/009` unexpected role change, `evt-010..012` lateral movement sequence vs `evt-020` isolated denial, `evt-013/014` out-of-order receipt, and `evt-015` `+2000ms` clock offset.
  - Evaluate 6 curated fixtures + seeded synthetic generator (`seed` fixed and documented) + entity-renaming invariance test (rename all actors/services to ensure zero hardcoding) + malformed/unknown-schema events.
- **Acceptance Criteria:**
  - Real measured TP, FP, TN, FN, precision, recall, F1, median/P95 time-to-alert, and false alerts per 1,000 benign events calculated and exported (no hardcoded scores).
  - Renamed-entity fixture achieves identical classification metrics as original synthetic fixture.
  - Overlapping clock-uncertainty windows always set `uncertain_order = True` rather than asserting strict order.

### G. Frontend & E2E (`tests/e2e/`)
- **Tests:** TypeScript compile + Vite build; Playwright smoke test walking Public Landing -> Demo Login -> Overview -> Lost-Device / Revocation / Vault / Key Lifecycle / Nodes / Detection / Messaging / Audit / Benchmarks / Scenarios -> Scorecard, checking desktop (`1440x900`) and mobile (`390x844`) viewports.
- **Acceptance Criteria:** Zero uncaught page errors, zero console errors, zero HTTP 500s, all tested interactive buttons trigger real backend calls.

### H. Delivery, Performance & Clean Install (`scripts/`)
- **Tests:**
  - Clean virtual environment setup from pinned dependencies in offline mode (after wheel cache / local install) and run full `pytest` suite + `validate.py`.
  - Run `scripts/benchmark.py` (with `time.perf_counter_ns`, warmups, >=100 samples for lightweight ops, CPU/RSS via `psutil`) and generate `reports/benchmarks/latest.{json,csv,md}`.
  - Run `scripts/security_checks.sh` (secret scan, AI/ML import check, static lint/bandit/pip-audit where available).
- **Acceptance Criteria:**
  - Clean install + full test suite reproducible from README commands.
  - Engineering targets (`local zero-trust p95 < 50 ms`, `small-file workflow p95 < 100 ms`, adapter `<< 8s`) measured and honestly compared against actual numbers.


---

## 3. Phase 2 Executed Independent Test Suite (`backend/tests/`)
- `backend/tests/test_db_and_seed.py`:
  - Empty-DB Alembic migration (`upgrade head` -> 25 tables, `downgrade base` -> `upgrade head`)
  - SQLite pragmas (`foreign_keys=1`, `journal_mode=wal`, `busy_timeout>=5000`)
  - Seed idempotency, `--reset` recovery, and verification that raw demo tokens are absent from `sessions.token_hash`
  - Transaction rollback & FK `IntegrityError` enforcement
  - Missing and corrupt SQLite file detection (`DatabaseIntegrityError`, `verify_database_health`)
- `backend/tests/test_policy_engine.py`:
  - Deterministic ordered testing of Steps 1–10 (`DENY_INVALID_REQUEST` through `DENY_ACTIVE_INCIDENT` and `ALLOW_AUTHORIZED`)
  - Precedence check (earlier step failure short-circuits later failing conditions)
  - Explicit `ResourcePermission` allow check and fail-closed `DENY_INTERNAL_ERROR` on checker failure
- `backend/tests/test_api_blackbox.py`:
  - `/api/v1/health`, `/api/v1/ready`, `/api/v1/openapi.json`
  - Synthetic demo login, logout invalidation, expired/revoked session denial, non-trusted device login block
  - Least-privilege RBAC (`owner`, `security_operator`, `admin`, `auditor`), cross-owner isolation, confirmation requirement, and self-role-escalation prevention
  - Device lifecycle (`PENDING -> TRUSTED -> SUSPENDED -> TRUSTED -> REVOKED`), permanent `REVOKED` block, replacement `re-enroll` preserving old device denial & peer availability
  - Resource access zero-leakage on deny, 422 extra-field validation without tracebacks, admin user disable + reset
  - Concurrent API requests (`ThreadPoolExecutor`) across SQLite WAL
- **Pending from Phase 2+:** Login rate limiting (`REQ-ID-004` partial), Phase 3–10 API endpoints (`REQ-API-001` Phase 2 subset only), hash-chained `audit_events` (`REQ-CORE-005`).


---

## 4. Phase 3 Executed Independent Cryptographic & Vault Test Suite
- `backend/tests/test_crypto_primitives.py`:
  - `MLKEM768Provider` interoperability against raw `pqcrypto.kem.ml_kem_768.decrypt`, wrong-key mismatch, tampered ciphertext, invalid Base64/lengths
  - `MLDSA65Provider` sign/verify, wrong-key, and 1-bit tamper rejection
  - `AES256GCMProvider` roundtrip, nonce uniqueness enforcement, ciphertext/tag/nonce/AAD tamper, wrong key, malformed payload
  - `derive_key_hkdf_sha256` context separation, determinism, and RFC 5869 KAT (via `selftest.py`)
  - `compute_protected_read_proof` / `verify_hmac_sha256_hex` constant-time checks and RFC 4231 / FIPS 180-4 KATs
  - `LocalEncryptedKeyStore` restart persistence, purpose separation, envelope tamper rejection, missing keystore fail-closed
- `backend/tests/test_vault_and_keys_api.py`:
  - `/api/v1/ready` & `/api/v1/crypto/selftest` RBAC & KAT checks
  - `/api/v1/keys/*` generation & state machine transitions (`REVOKED`/`COMPROMISED` terminal block, zero secret columns/responses)
  - `/api/v1/resources/{id}/encrypt`, `/decrypt`, `/crypto-metadata` authorization & cross-user denial
  - Live SQLite tamper tests (ciphertext flip, nonce flip, AAD envelope mutation, key revocation, keystore reset) verifying zero plaintext released on failure


---

## 5. Phase 4 Executed Node Simulator & Revocation Propagation Tests
- `backend/tests/test_nodes_and_revocation.py`:
  - Node count boundaries (`3` min, `7` max, `<3` and `>7` rejected)
  - Unauthorized revocation rejected (`owner`/`auditor` -> `403`, missing confirmation -> `400`)
  - Deterministic convergence time & P50/P95/P99 measurement across 4 nodes, independent per-node `local_revocations`, peer isolation
  - Single & multi-node offline/partitioned behavior (`converged=False`, `convergence_time_ms=None`, `UNSYNCHRONIZED`), fail-closed access on offline/stale nodes (`DENY_NODE_UNAVAILABLE`, `DENY_NODE_STALE_TRUST_STATE`), and catch-up convergence upon reconnection
  - Duplicate event idempotency (`DUPLICATE_IGNORED`, single ack), out-of-order replay (`STALE_IGNORED`, zero sequence rollback), and node restart persistence
  - Actor, device, key (including encrypted decrypt with zero plaintext), and session revocation enforcement, `DROP_EVENTS` / `PROCESSING_ERROR` faults, and tampered ML-DSA-65 event signature rejection (`FAILED_SIGNATURE`)
  - Predefined scenarios API (`offline_and_catchup`, `multi_offline`, `duplicate_and_out_of_order`, `drop_and_processing_failure`)


---

## 6. Phase 5 Executed Key Rotation, Crash Recovery & Backup Integrity Tests
- `backend/tests/test_rotation_and_recovery.py`:
  - Full 4-stage rotation (`PREPARE -> DISTRIBUTE -> COMMIT -> RETIRE`) on `vault_kek` with automatic pre-rotation backup, DEK re-wrapping + re-encryption (`v1 -> v2`), identical plaintext decryption post-rotation, and zero-grace old-key cutoff (`DENY_NODE_OLD_KEY_CUTOFF`) across all simulated nodes (`node-1..node-3`).
  - Single-active-rotation concurrency guard (`409 ROTATION_ALREADY_IN_PROGRESS` + SQLite partial unique index `uq_active_rotation_per_purpose`).
  - Continuity policy verification: `ZERO_GRACE` aborts pre-cutoff in-flight transfers at `COMMIT` whereas `CONTROLLED_IN_FLIGHT_ONLY` permits ONLY explicitly registered pre-cutoff transfers to complete prior to `RETIRE` while blocking unregistered post-cutoff requests.
  - RBAC enforcement & `demo_mode=False` crash-injection block (`403 CRASH_INJECTION_DISABLED`).
  - Complete 8-point deterministic crash-injection matrix (`AFTER_PREPARE`, `AFTER_BACKUP`, `AFTER_NODE_1_ACK`, `AFTER_NODE_2_ACK`, `BEFORE_COMMIT`, `AFTER_COMMIT`, `DURING_RETIRE`, `AFTER_REVOCATION_TOMBSTONE`), verifying pre-commit rollback (`RECOVERED_PRE_COMMIT`), post-commit roll-forward (`RECOVERED_POST_COMMIT`), `RevocationTombstone` non-reactivation precedence (`FAILED_CLOSED`), journal tampering detection (`JOURNAL_HASH_MISMATCH`), and multi-run recovery idempotency.
  - Real OS cross-process subprocess crash (`os._exit(42)`) against SQLite WAL followed by fresh-process recovery and decrypted data verification.
- `backend/tests/test_backups_and_integrity.py`:
  - AES-256-GCM encrypted + ML-DSA-65 signed backup creation, verification, RBAC boundaries (`owner` denied, `auditor` read/verify only), zero raw-secret exposure, confirmation gate, key restoration + duplicate restore idempotency.
  - Fail-closed rejection across wrong backup secret (`DECRYPT_AUTH_FAILED`), ciphertext tamper (`TAMPERED_MANIFEST` / `TAMPERED_PAYLOAD`), signature tamper (`INVALID_SIGNATURE`), unsupported version (`UNSUPPORTED_VERSION`), incomplete archive (`INCOMPLETE_BACKUP`), and missing file (`MISSING_FILE`).
  - Anti-rollback protection blocking stale pre-revocation backups from verification or restoration (`STALE_ANTI_ROLLBACK` / `BACKUP_STALE_ANTI_ROLLBACK`) and preserving newer `RevocationTombstone`s.


---

## 7. Phase 6 Executed Audit Ledger & Evidence Verification Tests
- `backend/tests/test_audit_ledger_and_verification.py`:
  - Genesis previous hash (`"0" * 64`), monotonic sequences (`1..N`), previous-hash linking, canonical JSON determinism, Unicode NFC & CR/LF log-injection escaping, `None`/`-0.0` normalization, independent SHA-256 verification, and 6-worker concurrent WAL insertion (`seqs 3..14`).
  - Read-only tamper detection (no repair) across modified payload, modified `event_hash`, modified `prev_hash`, deleted event / sequence gap, duplicate sequence, reordered events, inserted rogue event, invalid genesis, unsupported `schema_version`, and invalid canonical serialization / timestamp.
  - Append-only enforcement (ORM `before_flush` update/delete block, service-layer `AuditAppendOnlyError`, `405` on HTTP mutation verbs), fail-closed policy when `ALLOW` fails audit persistence (`DENY_INTERNAL_ERROR`), and durable `audit_outbox.jsonl` fallback on DB write error.
  - End-to-end coverage across auth login success/failure, RBAC denials, identity create/role-change/disable, device enroll/revoke, resource encrypt/decrypt/cross-user deny, node config/offline/stale-denial/restart, revocations & convergence, backup create/verify, rotation, and crash recovery with zero secrets/plaintext in audit output.
- `backend/tests/test_evidence_receipts_and_export.py`:
  - ML-DSA-65 signed checkpoints and event receipts (`key-audit-signer-v1`) verified independently with raw `pqcrypto.sign.ml_dsa_65.verify`, rejecting modified fields, modified signatures, wrong public keys, and invalid ledgers (`409`).
  - Verifiable bounded evidence export (`first_sequence..last_sequence`, max `5000`) verified independently offline, rejecting modified/missing/reordered events, altered receipt/head hashes, and wrong public keys with zero leaked secrets.


---

## 8. Phase 7 Executed Explainable Detector & Evaluation Tests
- `backend/tests/test_detector_rules_unit_matrix.py` (`27` tests):
  - Verifies `RULE_CATALOG` contains `26` deterministic rules plus dedicated positive & negative boundary unit tests for every single rule (`RULE-ID-001..005`, `RULE-DEV-001..005`, `RULE-RES-001..004`, `RULE-LAT-001..003`, `RULE-NOD-001..004`, `RULE-TMP-001..005`).
- `backend/tests/test_detector_rules_and_lifecycle.py` (`12` tests):
  - Official toolkit `practice/` dataset (`events.csv`, `approvals.json`, `22` events) + entity-renaming invariance (`svc-report-worker` -> `alias-svc-epsilon`).
  - Determinism across reversed arrival order, fingerprint stability, deduplication & re-opening after resolution, `OPEN -> ACKNOWLEDGED -> RESOLVED / FALSE_POSITIVE` transitions + `confirmation=False` gate + non-destructive state guarantee.
  - Full RBAC matrix (`owner`, `auditor`, `secops`, `admin`), config Pydantic validation + `DETECTOR_CONFIG_UPDATED` audit trail, sequence range / batch limit / invalid source rejections, `DEGRADED_MISSING_EVIDENCE` on empty/out-of-range ledgers, `409 AUDIT_CHAIN_INVALID` fail-closed on tamper, lateral movement approval/window FP controls, and raw/corrected/`uncertain_order` timestamp preservation.
- `backend/tests/test_detector_evaluation_metrics.py` (`6` tests):
  - Reproducible seeded benchmark (`seed=20261126`, `322` events, `112` scenarios) + strict label isolation against poisoned label fields.
  - Independent recalculation of scenario-level `TP=43`, `FP=3`, `TN=63`, `FN=3`, `Precision=0.934783`, `Recall=0.934783`, `F1=0.934783`, `FA/1k=18.5185`, `median_detection_time_ms=6000.0` (verified both locally and against saved API JSON), alert-to-scenario cardinality reconciliation (`74` alerts across multi-rule scenarios), zero-denominator `None`/`undefined_metrics` cases, and AST zero-AI/ML check.


---

## 9. Phase 8 Executed E2E Secure Messaging & Session Resumption Tests
- `backend/tests/test_messaging_crypto_and_resumption.py` (`20` tests):
  - Valid ML-KEM-768 + HKDF-SHA-256 + AES-256-GCM session establishment, explicit external ML-KEM-768 public key interop & malformed key rejection, HKDF context/chain separation, and full 8-state transition enforcement (`NEW`, `NEGOTIATING`, `ESTABLISHED`, `SUSPENDED`, `RESUMING`, `EXPIRED`, `REVOKED`, `COMPROMISED`).
  - Zero-trust fail-closed establishment rejections across disabled identities, untrusted/pending/suspended/revoked devices, and revoked messaging keys.
  - Confidentiality, 12-field AAD integrity, ciphertext/nonce/AAD tamper rejection (`0` plaintext leaked), wrong-recipient & wrong-sender rejection, durable `message_id` and `sequence` replay detection + Phase 7 `RULE-TMP-001` audit linkage, nonce uniqueness, expired message rejection, and post-delivery per-message key erasure (`has_key(...) is False`).
  - Peer-bound session resumption (`SUSPENDED -> RESUMING -> ESTABLISHED`), generation & token rotation, cross-peer/wrong-device hijack denial, replayed-token rejection (`409`), post-revocation resume failure, and long-term-key-only compromise check (`PARTIAL` FS boundary).
- `backend/tests/test_messaging_delivery_and_reliability.py` (`14` tests):
  - Non-decrypting `/verify`, bounded packet-loss retry recovery vs `DEAD_LETTER`, simulated delay vs expiry, canonical out-of-order delivery buffering & corrupt/incomplete discard, bounded reorder buffer capacity check, duplicate delivery rejection, idempotent duplicate acknowledgements, node disconnect/reconnect blocking & recovery, Phase 4 revocation propagation immediately invalidating active `CryptoSession`s, concurrent receive race serialization, tamper-evident audit ledger verification with zero plaintext/token leaks, and RBAC matrix across `owner`, `auditor`, `security_operator`, `admin`.
