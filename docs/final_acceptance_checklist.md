# Q-SHIELD Master Acceptance Gate Checklist & Verification Audit

| Requirement ID | Acceptance Gate Condition | Test Evidence | Verdict |
| :--- | :--- | :--- | :--- |
| **REQ-TK-001** | Single root adapter `track4_service.py` exists | `tests/adapter/test_track4_adapter.py` + `validate.py` | **PASS** |
| **REQ-TK-002** | Process-per-request JSON stdin/stdout protocol | `tests/adapter/test_track4_adapter.py` | **PASS** |
| **REQ-TK-003** | 64 KiB stream cap and 8s timeout compliance | `test_stdout_64kib_cap_and_os_tempdir_fallback` | **PASS** |
| **REQ-TK-004** | Offline read-only FS persistence in TRACK4_STATE_DIR | `test_repo_root_stays_untouched_and_isolated_env_works` | **PASS** |
| **REQ-TK-005** | Offline execution with stdlib + pqcrypto 0.4.0 | `tests/security/test_offline_network_isolation.py` | **PASS** |
| **REQ-TK-006** | Adapter setup atomic reset | `test_setup_and_repeated_setup_reset` | **PASS** |
| **REQ-TK-007** | Adapter read exact owner body, zero deny leak | `test_read_authorization_disabled_actor_and_no_leakage` | **PASS** |
| **REQ-TK-008** | Adapter revoke persistent isolation | `test_revoke_persistence_peer_isolation_and_audit` | **PASS** |
| **REQ-TK-009** | Adapter audit decision correlation | `test_revoke_persistence_peer_isolation_and_audit` | **PASS** |
| **REQ-TK-010** | Adapter protected_read ML-KEM-768 + HMAC | `test_protected_read_mlkem768_hmac_interoperability` | **PASS** |
| **REQ-TK-011** | Zero leakage of key material / secrets | `test_track4_adapter.py` + `validate.py` | **PASS** |
| **REQ-TK-012** | Malformed input rejection & fail-closed | `test_malformed_json_missing_fields_unknown_op` | **PASS** |
| **REQ-TK-013** | threat-model.json submission metadata alignment | `scripts/security_checks.py` | **PASS** |
| **REQ-CORE-001**| Key rotation continuity & zero-grace cutoff | `backend/tests/test_rotation_and_recovery.py` | **PASS** |
| **REQ-CORE-002**| 3-7 node distributed revocation & convergence | `backend/tests/test_nodes_and_revocation.py` | **PASS** |
| **REQ-CORE-003**| Transactional crash recovery across rotation | `backend/tests/test_rotation_and_recovery.py` | **PASS** |
| **REQ-CORE-004**| Authenticated backup integrity & anti-rollback | `backend/tests/test_backups_and_integrity.py` | **PASS** |
| **REQ-CORE-005**| Append-only hash-chained audit ledger | `backend/tests/test_audit_ledger_and_verification.py` | **PASS** |
| **REQ-CORE-006**| Explainable non-ML detector with metrics | `backend/tests/test_detector_evaluation_metrics.py` | **PASS** |
| **REQ-CORE-007**| Service-graph lateral movement detection | `backend/tests/test_detector_rules_unit_matrix.py` | **PASS** |
| **REQ-CORE-008**| Out-of-order clock offset correction | `backend/tests/test_detector_evaluation_metrics.py` | **PASS** |
| **REQ-CORE-009**| E2E messaging AEAD & replay protection | `backend/tests/test_messaging_crypto_and_resumption.py`| **PASS** |
| **REQ-CORE-010**| Forward secrecy with compromise verification | `test_20_replayed_token_expired_revoked_resume` | **PASS** |
| **REQ-CORE-011**| Message delivery loss & reorder buffer | `backend/tests/test_messaging_delivery_and_reliability.py`| **PASS** |
| **REQ-CORE-012**| Peer-bound cryptographic session resumption | `test_messaging_crypto_and_resumption.py` | **PASS** |
| **REQ-CORE-013**| ML-DSA-65 proof-carrying trust receipts | `backend/tests/test_evidence_receipts_and_export.py` | **PASS** |
| **REQ-CRYPTO-001**| Vetted cryptographic APIs only | `backend/tests/test_crypto_primitives.py` | **PASS** |
| **REQ-CRYPTO-002**| ML-KEM-768 KAT & interoperability | `test_mlkem768_interoperability_and_error_handling` | **PASS** |
| **REQ-CRYPTO-003**| ML-DSA-65 digital signatures | `test_mldsa65_sign_verify_and_tamper` | **PASS** |
| **REQ-CRYPTO-004**| AES-256-GCM AEAD unique nonces & AAD | `test_aes256_gcm_tamper_aad_and_nonce_uniqueness` | **PASS** |
| **REQ-CRYPTO-005**| HKDF-SHA-256 context-separated derivation | `test_hkdf_sha256_context_separation_and_reproducibility`| **PASS** |
| **REQ-CRYPTO-006**| Startup cryptographic self-test failing closed | `test_crypto_selftest_and_ready_endpoints` | **PASS** |
| **REQ-KEY-001** | Key lifecycle state machine | `test_key_metadata_lifecycle_and_no_secret_exposure`| **PASS** |
| **REQ-KEY-002** | Per-resource random DEK envelope encryption | `test_resource_envelope_encrypt_decrypt` | **PASS** |
| **REQ-KEY-003** | Local encrypted keystore with zero leakage | `test_local_encrypted_keystore_security` | **PASS** |
| **REQ-ID-001**  | RBAC roles least-privilege enforcement | `test_rbac_least_privilege_and_no_self_escalation` | **PASS** |
| **REQ-ID-002**  | Device lifecycle states & re-enrollment | `test_device_lifecycle_permanent_revocation` | **PASS** |
| **REQ-ID-003**  | 10-step zero-trust request evaluation | `backend/tests/test_policy_engine.py` | **PASS** |
| **REQ-ID-004**  | Hashed session tokens & login rate limiting | `test_phase9_hardening_datasets_scenarios_bench.py` | **PASS** |
| **REQ-ID-005**  | Offline synthetic demo auth | `backend/tests/test_api_blackbox.py` | **PASS** |
| **REQ-REV-001** | Deterministic 3-7 node simulator | `backend/tests/test_nodes_and_revocation.py` | **PASS** |
| **REQ-REV-002** | Atomic revocation tombstones | `test_nodes_and_revocation.py` + `test_rotation_and_recovery.py` | **PASS** |
| **REQ-DATA-001**| 6 curated JSONL fixtures & datasets | `datasets/` + `test_phase9_hardening_datasets_scenarios_bench.py` | **PASS** |
| **REQ-DB-001**  | SQLite schema with WAL and FK invariants | `backend/tests/test_db_and_seed.py` | **PASS** |
| **REQ-API-001** | FastAPI /api/v1 typed endpoints & security headers | `backend/tests/test_api_blackbox.py` | **PASS** |
| **REQ-UI-001**  | React + TS console with 14 pages & Vitest | `frontend/src/__tests__/console.test.tsx` + `qshield.spec.ts` | **PASS** |
| **REQ-UI-002**  | 14 one-click resettable demo scenarios | `backend/tests/test_phase9_hardening_datasets_scenarios_bench.py` | **PASS** |
| **REQ-PERF-001**| Empirical benchmarks using perf_counter_ns | `scripts/benchmark.py` | **PASS** |
| **REQ-SEC-001** | Prohibition of AI/ML libraries & offline isolation | `scripts/security_checks.py` + `test_offline_network_isolation.py` | **PASS** |
| **REQ-SEC-002** | Security hardening, AST audit, locked deps | `requirements.lock` + `scripts/security_checks.py` | **PASS** |
| **REQ-SUB-001** | Complete submission documentation & evidence sheet | Master Acceptance Gates | **PASS** |
