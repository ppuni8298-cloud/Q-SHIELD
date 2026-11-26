# Q-SHIELD Phase 5: Deterministic Crash Injection & Idempotent Recovery

## 1. Crash Injection Safeguards

Deterministic crash simulation is implemented solely for demonstration and verification via `CRASH_INJECTION_POINTS` in [rotation.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/keys/rotation.py):

1. `AFTER_PREPARE`
2. `AFTER_BACKUP`
3. `AFTER_NODE_1_ACK`
4. `AFTER_NODE_2_ACK`
5. `BEFORE_COMMIT`
6. `AFTER_COMMIT`
7. `DURING_RETIRE`
8. `AFTER_REVOCATION_TOMBSTONE`

Security gate: if `settings.demo_mode` is `False`, both `/keys/rotate?crash_at=...`, `/keys/rotations/{id}/advance`, and `/keys/crash-injection` fail closed with HTTP `403 CRASH_INJECTION_DISABLED`.

In all 8 points, durable DB/keystore checkpoint state is committed *before* `SimulatedCrashError` is raised.

## 2. Recovery Decision Table

Implemented in `recover_single_operation` and `recover_rotations` ([manager.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/recovery/manager.py)):

| Observed Crash Point / Journal State | `committed` | Action Taken | Final Status | Key & Data State |
|---|---|---|---|---|
| `AFTER_PREPARE`, `AFTER_BACKUP`, `AFTER_NODE_1_ACK`, `AFTER_NODE_2_ACK`, `BEFORE_COMMIT` | `False` | Clear node `staged_key_version`, restore non-tombstoned `from_key` to `ACTIVE`, mark unused `to_key` `REVOKED` + tombstone. | `RECOVERED_PRE_COMMIT` | Pre-cutoff `from_version` remains active and vault resources remain decryptable under `from_version`. |
| `AFTER_COMMIT`, `DURING_RETIRE` | `True` | Finalize remaining resources to `to_version`, set node `accepted_key_version = to_version` and `cutoff_epoch = to_version`, retire `from_key`, activate `to_key`. | `RECOVERED_POST_COMMIT` | Cutover completed across all nodes; data decryptable under `to_version`. |
| `AFTER_REVOCATION_TOMBSTONE` (or any tombstoned target/source key) | Any | Never reactivate revoked/compromised keys (`RevocationTombstone` takes absolute precedence). | `FAILED_CLOSED` | Tombstoned keys stay terminal (`REVOKED`/`COMPROMISED`); old/compromised key access denied. |
| Tampered/corrupted `journal_hash` | Any | Refuse replay. | `FAILED_CLOSED` | `failure_info = "JOURNAL_HASH_MISMATCH"`. |
| Repeated recovery call on already recovered/completed op | Any | No-op (`idempotent_noop = True`). | Unchanged | Zero duplicate transitions or mutations. |

## 3. Endpoint Access

- `POST /api/v1/keys/rotations/{operation_id}/recover` (`recovery:run` permission: `security_operator`, `admin`)
- `POST /api/v1/keys/recovery/run` (`recovery:run` permission: `security_operator`, `admin`)
- `POST /api/v1/keys/crash-injection` (`key:manage` permission, `demo_mode=True` required)
