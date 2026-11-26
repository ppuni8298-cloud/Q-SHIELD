# Q-SHIELD Phase 6: External Verifiable Evidence Export

## 1. Export Package Schema (`qshield.audit.export.v1`)

Generated via `export_evidence_package` (`POST /api/v1/audit/export`, restricted to `audit:export` permission: `security_operator`, `admin`, `auditor`; hard-capped at `MAX_EXPORT_EVENTS = 5000` events per package to protect memory and query bounds):

- `export_schema_version`: `"qshield.audit.export.v1"`
- `ledger_id`: `"qshield-control-plane-audit-v1"`
- `hash_algorithm`: `"SHA-256"`
- `export_created_at`: UTC ISO-8601 timestamp
- `first_sequence`, `last_sequence`
- `expected_prev_hash`, `genesis_hash`
- `previous_checkpoint`: latest checkpoint <= `last_sequence` (when present)
- `final_chain_head_hash`
- `signer_public_key_b64`
- `receipt`: signed `EXPORT` `AuditEvidenceReceipt`
- `events`: canonically serialized, secret-redacted event records (`first_sequence..last_sequence`)

All payload secrets and protected resource plaintexts remain absent/redacted.

## 2. Independent Offline Verification Procedure

`verify_exported_package(package, public_key_b64=...)` (also exposed at `POST /api/v1/audit/export/verify`) validates an export without trusting server `"valid"` flags or reading database state:
1. Validates `export_schema_version == "qshield.audit.export.v1"` and non-empty `events`.
2. Recomputes the full SHA-256 chain over `events` via `verify_audit_records`, checking contiguous sequences `first_sequence..last_sequence`, missing events, duplicates, reordering, genesis hash, and `expected_prev_hash`.
3. Confirms `final_chain_head_hash` equals the verified tail event hash.
4. Independently verifies `receipt` `ML-DSA-65` signature and range/head bindings against the supplied `public_key_b64`.
