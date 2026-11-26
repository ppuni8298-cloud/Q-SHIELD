# Q-SHIELD Phase 6: Audit Chain Verification Specification

## 1. Read-Only Independent Verifier

Implemented in [verifier.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/audit/verifier.py) via `verify_audit_records(...)` (pure sequence verifier usable on exported JSON packages without database access) and `verify_ledger_db(...)` (full or bounded SQLite read-only inspection).

Crucial guarantee: verification **never** repairs, rewrites, truncates, or re-hashes tampered database records, and never reports `valid = True` when inspection terminates early due to an error.

## 2. Exact Detection Matrix

| Tampering / Fault Condition | Failure Category Returned |
|---|---|
| Missing required canonical fields, non-dict payload, or unparseable timestamp | `INVALID_CANONICAL_SERIALIZATION` |
| Unsupported `schema_version` (`!= qshield.audit.v1`) | `INVALID_SCHEMA_VERSION` |
| Unsupported `hash_algorithm` (`!= SHA-256`) | `INVALID_HASH_ALGORITHM` |
| Repeated `sequence` integer in inspected records | `DUPLICATE_SEQUENCE` |
| Genesis record starts at `sequence != 1` | `MISSING_GENESIS_OR_SEQUENCE_GAP` |
| Sequence decreases across adjacent records | `REORDERED_EVENTS` |
| Gap between adjacent sequence numbers (`seq != prev_seq + 1`) / deleted event | `SEQUENCE_GAP_OR_DELETED_EVENT` |
| Predecessor sequence missing on range check | `MISSING_PREDECESSOR_EVENT` |
| Genesis `prev_hash != "0" * 64` | `INVALID_GENESIS_RECORD` |
| Record `prev_hash != previous event's computed event_hash` (inserted/reordered/swapped chain link) | `PREV_HASH_MISMATCH` |
| Recomputed `SHA-256` digest differs from stored `event_hash` (modified payload, metadata, or `event_hash`) | `EVENT_HASH_OR_PAYLOAD_MISMATCH` |

## 3. Structured Verification Output

Returned via `AuditVerificationResult` and `POST /api/v1/audit/verify`:
- `valid`: boolean overall verdict
- `verified_event_count` & `total_events_inspected`
- `first_sequence`, `last_sequence`, `head_hash`
- `first_invalid_sequence`, `first_invalid_event_id`, `failure_category`
- `expected_hash`, `actual_hash`, `detail`, `verified_at`
