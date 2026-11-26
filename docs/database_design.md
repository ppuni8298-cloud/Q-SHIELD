# Q-SHIELD — Database Design (Phase 2)

**Engine:** SQLite 3 (offline/demo default, portable SQLAlchemy 2 schema)  
**ORM / Migrations:** `SQLAlchemy==2.1.9` + `Alembic==1.20.1` (`backend/alembic/versions/3c456ff37b93_initial_schema.py`)  
**Connection Pragmas:**
- `PRAGMA foreign_keys=ON`
- `PRAGMA journal_mode=WAL`
- `PRAGMA busy_timeout=5000`
- `PRAGMA synchronous=FULL`

---

## 1. Complete Table Inventory (25 Tables)

### A. Master Build Prompt Section 12 Tables (23 Tables)

| # | Table Name | Phase 2 Role | Key Columns & Constraints |
|---|---|---|---|
| 1 | `users` | Active/disabled synthetic identities & RBAC roles | `id` (PK), `display_name`, `role` (`CHECK` in `owner`/`security_operator`/`admin`/`auditor`), `enabled`, `is_synthetic`, `created_at`, `updated_at` |
| 2 | `devices` | Enrolled devices, ownership, state & optimistic version | `id` (PK), `owner_id` (FK `users.id` RESTRICT), `credential_fingerprint` (UNIQUE), `state` (`PENDING`/`TRUSTED`/`SUSPENDED`/`REVOKED`), `state_version`, `enrolled_at`, `revoked_at`, `replaced_by_device_id` |
| 3 | `sessions` | Hashed bearer sessions bound to actor & device | `id` (PK), `token_hash` (UNIQUE SHA-256), `actor_id` (FK `users.id`), `device_id` (FK `devices.id`), `peer_id`, `auth_strength`, `version`, `state` (`ACTIVE`/`EXPIRED`/`REVOKED`), `issued_at`, `expires_at`, `revoked_at` |
| 4 | `resources` | Protected-resource metadata, owner & key version | `id` (PK), `owner_id` (FK `users.id`), `type`, `metadata_json`, `key_version`, `state` (`ACTIVE`/`DISABLED`), `created_at`, `updated_at` |
| 5 | `resource_permissions` | Explicit actor/role permissions per resource | `id` (PK), `resource_id` (FK `resources.id` CASCADE), `subject_type` (`actor`/`role`), `subject_id`, `permission`, `UNIQUE(resource_id, subject_type, subject_id, permission)` |
| 6 | `encrypted_objects` | *Phase 3 schema placeholder* (AEAD envelopes) | `id` (PK), `resource_id` (FK `resources.id`), `ciphertext_ref`, `nonce`, `aead_envelope`, `version`, `integrity` |
| 7 | `key_metadata` | Key version/state metadata (NO private keys) | `key_id` (PK), `purpose`, `algorithm`, `version`, `state` (`PREPARED`..`COMPROMISED`), `UNIQUE(purpose, version)` |
| 8 | `rotation_operations` | *Phase 5 schema placeholder* (rotation journal) | `operation_id` (PK), `from_version`, `to_version`, `phase`, `actor_id`, `committed`, `journal_hash` |
| 9 | `node_registry` | *Phase 4 schema placeholder* (simulated nodes) | `node_id` (PK), `service`, `health`, `current_epoch`, `latency_profile`, `last_event_seq` |
| 10 | `node_acknowledgements` | *Phase 4 schema placeholder* (node acks) | `id` (PK), `operation_id`, `node_id` (FK `node_registry.node_id`), `status`, `ack_at`, `enforced_at` |
| 11 | `revocation_tombstones` | Durable non-reactivable revocation tombstones | `id` (PK), `target_type` (`actor`/`device`/`key`/`session`), `target_id`, `revocation_epoch`, `reason`, `UNIQUE(target_type, target_id)` |
| 12 | `incidents` | Active/closed incidents (queried by Policy Step 9) | `id` (PK), `type`, `severity`, `state`, `actor_or_target`, `blocks_access`, `reason`, `created_at`, `closed_at` |
| 13 | `audit_events` | *Phase 6 schema placeholder* (hash-chained events) | `sequence` (PK), `event_id` (UNIQUE), `actor_id`, `action`, `decision`, `reason_code`, `correlation_id`, `prev_hash`, `event_hash` |
| 14 | `audit_checkpoints` | *Phase 6 schema placeholder* (signed checkpoints) | `sequence` (PK), `root_hash`, `signature_metadata`, `created_at` |
| 15 | `access_requests` | Persisted 10-step policy evaluation decisions | `request_id` (PK), `actor_id`, `resource_id`, `device_id`, `action`, `decision` (`ALLOW`/`DENY`), `reason`, `correlation_id`, `steps_json`, `timestamp` |
| 16 | `messages` | *Phase 8 schema placeholder* (E2E encrypted envelopes) | `message_id` (PK), `sender_id`, `recipient_id`, `session_id`, `encrypted_envelope`, `status` |
| 17 | `sessions_crypto` | *Phase 8 schema placeholder* (peer protocol metadata) | `id` (PK), `peer_binding`, `protocol_state_metadata`, `created_at` |
| 18 | `replay_records` | *Phase 8 schema placeholder* (durable replay ledger) | `id` (PK), `recipient_id`, `session_id`, `sequence_or_msg_id`, `accepted`, `expires_at`, `UNIQUE(recipient_id, session_id, sequence_or_msg_id)` |
| 19 | `detector_events` | *Phase 7 schema placeholder* (ingested events) | `id` (PK), `event_source`, `schema_version`, `ingest_time`, `event_time`, `label`, `payload_json` |
| 20 | `alerts` | *Phase 7 schema placeholder* (explainable alerts) | `id` (PK), `rule_id`, `severity`, `explanation`, `actor_id`, `services_json`, `event_refs_json`, `status` |
| 21 | `benchmarks` | *Phase 10 schema placeholder* (measured metrics) | `id` (PK), `run_id`, `environment_metadata`, `operation`, `stats_json`, `created_at` |
| 22 | `backup_manifests` | *Phase 5 schema placeholder* (verified backup metadata) | `backup_id` (PK), `version`, `integrity_auth_data`, `verified_status`, `created_at` |
| 23 | `settings` | Safe non-secret configuration flags | `key` (PK), `value`, `updated_at` |

### B. Phase 2 Normalized Domain Support Tables (2 Tables)

| # | Table Name | Purpose | Key Columns & Constraints |
|---|---|---|---|
| 24 | `role_permissions` | Normalized RBAC permission matrix | `id` (PK), `role`, `action`, `scope`, `description`, `UNIQUE(role, action, scope)` |
| 25 | `device_state_history` | Immutable audit trail of device state transitions | `id` (PK), `device_id` (FK `devices.id` CASCADE), `from_state`, `to_state`, `state_version`, `changed_by`, `reason`, `correlation_id`, `created_at` |

---

## 2. Migration & Corruption Safety Commands
- **Apply migrations from empty DB:**
  ```sh
  .venv\Scripts\python.exe -m alembic -c backend/alembic.ini upgrade head
  ```
- **Health & Integrity Check:** `verify_database_health()` executes `PRAGMA quick_check` and confirms core table existence; `validate_sqlite_file_or_raise()` detects missing or corrupt SQLite files and fails safely (`503 DATABASE_NOT_READY`).
