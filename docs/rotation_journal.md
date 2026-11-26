# Q-SHIELD Phase 5: Durable Rotation Journal Architecture

## 1. Schema & Integrity Model

Durable state transitions are recorded in `rotation_operations` ([models.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/db/models.py#L292-L332)) and migrated via Alembic revision `52aba4db4c26` ([52aba4db4c26_phase5_rotation_journal_and_backups.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/alembic/versions/52aba4db4c26_phase5_rotation_journal_and_backups.py)).

Key columns:
- `operation_id`, `purpose`, `from_key_id`, `to_key_id`, `from_version`, `to_version`
- `phase`: `PREPARE | DISTRIBUTE | COMMIT | RETIRE`
- `status`: `IN_PROGRESS | COMMITTED | COMPLETED | RECOVERED_PRE_COMMIT | RECOVERED_POST_COMMIT | FAILED_CLOSED`
- `grace_policy`: `ZERO_GRACE | CONTROLLED_IN_FLIGHT_ONLY`
- `backup_id`: link to pre-rotation verified `BackupManifest`
- `committed`: monotonic boolean flag distinguishing pre-commit rollback from post-commit roll-forward
- `commit_at`, `node_acks_json`, `failure_info`, `recovery_notes`, `correlation_id`
- `journal_hash`: canonical SHA-256 digest computed by `compute_journal_hash(op)` over immutable/progressive state fields

## 2. Persistence & Journal Tamper Detection

Before committing any stage transition (`PREPARE`, `backup_id` checkpoint, `DISTRIBUTE`, `COMMIT`, `RETIRE`, or `recover_single_operation`), Q-SHIELD recomputes `journal_hash = compute_journal_hash(op)` inside the same SQLite transaction.

During crash recovery ([manager.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/recovery/manager.py)), `recover_single_operation` recomputes `compute_journal_hash(op)` first:
- If the stored `journal_hash` does not match, recovery refuses unsafe state replay, transitions `status = "FAILED_CLOSED"`, sets `failure_info = "JOURNAL_HASH_MISMATCH"`, and commits.

## 3. SQLite / Windows Local File Durability Caveats

- SQLite is configured with `WAL` journal mode and `busy_timeout=5000ms` so committed checkpoints survive abrupt process termination (`os._exit`), verified by cross-process subprocess crash tests.
- In non-HSM local mode (`LocalEncryptedKeyStore` JSON envelopes and encrypted backup files), atomic write/close semantics ensure persisted file checkpoints before raising crash signals; on consumer Windows NTFS volumes, hardware write-back caching behavior ultimately bounds OS-level `fsync` guarantees after power loss.
