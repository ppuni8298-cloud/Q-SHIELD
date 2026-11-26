# Q-SHIELD Phase 6: Signed Audit Checkpoints & Evidence Receipts

## 1. Cryptographic Algorithm & Key Custody

- **Signature Algorithm:** `ML-DSA-65` (`pqcrypto.sign.ml_dsa_65`: public key `1952` bytes, secret key `4032` bytes, signature `3309` bytes) exposed via `MLDSA65Provider`.
- **Purpose-Separated Signing Key:** `key-audit-signer-v1` (`purpose="audit"`, separate from `key-revocation-signer-v1` `purpose="signing"` and `vault_kek` encryption keys). Private key bytes remain exclusively inside `LocalEncryptedKeyStore` and are never emitted in database tables, API payloads, receipts, exports, or logs.
- **Public Verification Key Distribution:** Public key Base64 (`audit_signer_public_key_b64`) is stored in `settings` and embedded cleanly in exported packages for independent verification.

## 2. Signed Checkpoints (`AuditCheckpoint`)

Implemented in `create_audit_checkpoint` and `verify_checkpoint_record` ([evidence.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/audit/evidence.py)):
1. Verifies the ledger via `verify_ledger_db` first; refuses checkpoint creation (`409 AUDIT_CHAIN_INVALID`) if any integrity error exists.
2. Canonical JSON over `{checkpoint_id, ledger_id, schema_version, first_sequence, last_sequence, root_hash, signature_algorithm, signer_key_id, created_at}` is signed with `ML-DSA-65`.

## 3. Evidence Receipts (`AuditEvidenceReceipt`)

Each receipt (`EVENT` or `EXPORT`) cryptographically binds:
- `receipt_id`, `receipt_type`, `ledger_id`, `schema_version` (`qshield.audit.receipt.v1`)
- `event_id`, `sequence`, `first_sequence`, `last_sequence`
- `event_hash`, `chain_head_hash`
- `signature_algorithm`, `signer_key_id`, `created_at`
- Detached `ML-DSA-65` signature (`signature_b64`), independently verifiable offline via `verify_receipt_data(...)` or raw `ml_dsa_65.verify(...)`.

*(Threat boundary caveat: if an attacker gains both full host filesystem access and master keystore material, they could re-sign forged checkpoints; retaining checkpoints/exports externally mitigates local host compromise.)*
