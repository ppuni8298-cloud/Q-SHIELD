# Q-SHIELD Phase 6: Append-Only Audit Ledger Design

## 1. Module Architecture & Storage Schema

Implemented across:
- [canonical.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/audit/canonical.py): Deterministic canonical encoding, secret redaction, log-injection control-character escaping, and SHA-256 chain hashing.
- [ledger.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/audit/ledger.py): Concurrency-serialized append-only writer, SQLAlchemy ORM mutation/deletion guards, and durable JSONL outbox fallback.
- [models.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/db/models.py#L458-L524) + Alembic revision [82894fe890ee_phase6_audit_ledger_and_evidence.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/alembic/versions/82894fe890ee_phase6_audit_ledger_and_evidence.py): Normalized `audit_events`, `audit_checkpoints`, and `audit_evidence_receipts` tables.

Every `AuditEvent` record stores: `sequence` (>= 1, unique PK), `event_id` (unique), `event_type`, `event_category`, `timestamp_utc`, `actor_id`, `action`, `target_type`, `target_id`, `decision` (`outcome`), `reason_code`, `correlation_id`, `source_component`, `payload_json`, `prev_hash`, `event_hash`, `hash_algorithm` (`"SHA-256"`), and `schema_version` (`"qshield.audit.v1"`).

## 2. Deterministic Canonical Serialization

1. **Unicode:** All string keys and values pass through Unicode `NFC` normalization (`unicodedata.normalize("NFC", value)`).
2. **Log Injection Defense:** `sanitize_audit_text` escapes `\n` -> `\\n`, `\r` -> `\\r`, `\t` -> `\\t`, and C0/DEL control bytes (`< 0x20` or `0x7f`) before persistence.
3. **Secret Redaction:** `redact_sensitive_fields` recursively replaces values under keys containing secret tokens (`password`, `secret`, `token`, `private_key`, `key_material`, `shared_secret`, `plaintext`, `master_key`, `wrapping_key`, `dek`, `kek`, `signing_key`, `raw_key`) with `"[REDACTED]"` while allowing non-secret IDs (`key_id`, `key_version`, etc.).
4. **Numeric, Null, and Object Rules:** `None` -> `null`; `bool` preserved cleanly; `-0.0` normalized to `0.0`; `NaN`/`Infinity` rejected (`allow_nan=False`); dict keys sorted lexicographically by NFC codepoints; UTF-8 compact JSON (`separators=(",", ":")`, `ensure_ascii=False`).
5. **Timestamp Normalization:** Converted to explicit UTC microsecond ISO-8601 format (`YYYY-MM-DDTHH:MM:SS.ffffff+00:00`).

## 3. Exact Hash Construction & Genesis Behavior

- **Genesis Previous Hash (`sequence == 1`):**
  `AUDIT_GENESIS_PREV_HASH = "0000000000000000000000000000000000000000000000000000000000000000"` (`"0" * 64`).
- **Chain Digest Formula:**
  Let `C` be `canonical_json_bytes(canonical_body)` over the 17 normalized fields (`schema_version`, `hash_algorithm`, `sequence`, `event_id`, `timestamp_utc`, `event_type`, `event_category`, `actor_id`, `target_type`, `target_id`, `action`, `outcome`, `reason_code`, `correlation_id`, `source_component`, `payload`, `prev_hash`).
  Then:
  `event_hash = SHA-256(b"QSHIELD-AUDIT-EVENT-V1|" + ascii(prev_hash) + b"|" + ascii(str(sequence)) + b"|" + C).hexdigest()`

## 4. Append-Only Enforcement, Coverage & Failure Semantics

- **Application & ORM Protections:** SQLAlchemy `Session` `before_flush` listener rejects any ORM update (`session.dirty` modified `AuditEvent`) or delete (`session.deleted` `AuditEvent`) with `AuditAppendOnlyError` (`409 AUDIT_APPEND_ONLY_VIOLATION`). `update_audit_event` and `delete_audit_event` always raise `AuditAppendOnlyError`. `/api/v1/audit/*` exposes zero `PUT`, `PATCH`, or `DELETE` endpoints.
- **Coverage:** Integrated into authentication (`demo_login` success/fail, token rejection, logout, session revoke), authorization (`require_permission` denials, role changes, self-escalation block), identities, devices (enroll/approve/suspend/restore/revoke/re-enroll), simulated nodes (configure, availability, restart, propagation, convergence, stale-node and old-key cutoff denials), keys & vault (generate, transition, rotation stages/failures, recovery, backups, encrypt, decrypt, AEAD verification failures), and policy evaluation (`ALLOW` / `DENY`).
- **Transaction & Failure Semantics:** Security mutations and `AccessRequest` decisions commit atomically with their `AuditEvent` inside `audit_write_lock()`. If audit persistence fails during an `ALLOW` policy evaluation, `ZeroTrustPolicyEngine` rolls back and fails closed (`DENY_INTERNAL_ERROR`). If audit fails on a denied path, the denial is never converted to `ALLOW`, and standalone database failures write a sanitized record to `settings.audit_outbox_path`.

## 5. Honest Security Boundary (Tamper Evidence vs Absolute Immutability)

Cryptographic hash chaining and signed external evidence provide **tamper evidence**, not impossible OS-level absolute immutability: an adversary holding unrestricted privileged OS/filesystem access to the SQLite `.sqlite3` file can alter local rows directly. That tampering is exposed after-the-fact by the read-only chain verifier, externally held ML-DSA-65 checkpoints/receipts, and exported evidence packages.
