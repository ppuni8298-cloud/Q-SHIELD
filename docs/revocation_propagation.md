# Q-SHIELD — Revocation Event Model & Propagation Engine (Phase 4)

**Modules:** [backend/app/revocation/coordinator.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/revocation/coordinator.py), [backend/app/nodes/simulator.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/nodes/simulator.py)

---

## 1. Authorized Revocation Event Creation (`POST /api/v1/revocations`)

- **Authorization:** Requires `revocation:issue` (`security_operator` or `admin`), non-empty `reason`, and explicit `confirmation: true`. Owners and Auditors are rejected (`403`).
- **Supported Subjects:** `actor`, `device`, `key`, `session`.
- **Atomic Central Commit:** Inside one SQLite transaction:
  1. Mutates central state immediately (`User.enabled=False`, `Device.state="REVOKED"`, `KeyMetadata.state="REVOKED"`, `UserSession.state="REVOKED"`, plus cascading session revocation for actor/device).
  2. Writes/updates durable `RevocationTombstone` with monotonic `revocation_epoch`.
  3. Persists `RevocationEvent` (`event_id`, strictly monotonic `sequence_number`, `sim_clock_ms`, `created_at`, `issued_by`, `correlation_id`, canonical SHA-256 `integrity_sha256`, and **ML-DSA-65** `signature_b64` signed by `key-revocation-signer-v1` from `LocalEncryptedKeyStore`).
  4. Enqueues `NodeEventInbox` (`QUEUED`) for every registered node (`3–7` nodes) and marks nodes `UNSYNCHRONIZED` until processed.

---

## 2. Per-Node Event Processing & Failure Rules

Each node processes inbox items independently:
1. **Authenticity Verification:** Verifies `integrity_sha256` and ML-DSA-65 signature against `revocation_signer_public_key_b64`. Invalid digest/signature fails (`FAILED_SIGNATURE`) and never marks converged.
2. **Fault Handling:**
   - `OFFLINE` / `PARTITIONED`: Event remains `QUEUED` (`DEFERRED_OFFLINE`); node stays `UNSYNCHRONIZED`.
   - `DROP_EVENTS`: Marked `DROPPED`; node stays `UNSYNCHRONIZED` until healed & re-propagated.
   - `PROCESSING_ERROR`: Marked `FAILED`; node marked `DEGRADED`/`FAILED`.
3. **Out-of-Order Protection:** Older-sequence replay (`deliver_out_of_order=True` with `seq < node.last_event_seq`) is logged as `STALE_IGNORED` and never rolls back `last_event_seq`, `current_epoch`, or newer revocations.
4. **Duplicate Idempotency:** Already-enforced `event_id` (checked via `NodeAcknowledgement`) is logged as `DUPLICATE_IGNORED` with zero duplicate acknowledgements.
5. **Monotonic Enforcement:** Updates `local_revocations_json`, advances `last_event_seq` / `current_epoch`, writes `NodeAcknowledgement(status="ENFORCED")`, flushes inbox state, and recomputes `sync_status`.
