# Q-SHIELD Empirical Performance Benchmarks (`bench-20261126163702`)

- **Python:** `3.12.10` | **Platform:** `Windows-11-10.0.26300-SP0` | **CPUs:** `8`
- **Measured At:** `2026-11-26T16:37:28.324466+00:00`

| Operation | Category | Samples | Median (ms) | P95 (ms) | Throughput (ops/s) | Peak Traced (KiB) | Errors |
|---|---|---:|---:|---:|---:|---:|---:|
| `ml_kem_768_encap_decap` | Cryptography | 120 | 0.2779 | 0.3781 | 3359.3 | 5.06 | 0 |
| `ml_dsa_65_sign_verify` | Cryptography | 100 | 0.9853 | 1.7658 | 927.12 | 4.35 | 0 |
| `hkdf_sha256_derive` | Cryptography | 200 | 0.0907 | 0.1104 | 11707.82 | 4.86 | 0 |
| `aes_256_gcm_1kib_roundtrip` | Cryptography | 200 | 0.0233 | 0.0288 | 36277.89 | 43.58 | 0 |
| `aes_256_gcm_64kib_roundtrip` | Cryptography | 100 | 0.0626 | 0.0728 | 15162.08 | 175.89 | 0 |
| `zero_trust_10step_policy_eval` | Authorization | 120 | 9.2966 | 12.6962 | 104.15 | 196.55 | 0 |
| `auth_demo_login` | Authentication | 100 | 17.73 | 27.4214 | 41.72 | 63.79 | 0 |
| `audit_ledger_append` | Audit | 100 | 8.6188 | 13.6547 | 106.02 | 50.02 | 0 |
| `audit_ledger_verify_chain` | Audit | 30 | 82.6248 | 91.2178 | 11.93 | 657.8 | 0 |
| `e2e_message_send_receive` | Messaging | 30 | 172.6014 | 228.8077 | 6.4 | 175.88 | 0 |
| `revocation_propagation_3nodes` | Revocation | 15 | 163.0762 | 224.2384 | 6.2 | 204.77 | 0 |
| `backup_create_and_verify` | Backup | 10 | 49.9102 | 63.2673 | 19.2 | 177.36 | 0 |
| `detector_322_events_26_rules` | ThreatDetector | 30 | 253.6515 | 348.153 | 3.8 | 1235.6 | 0 |
