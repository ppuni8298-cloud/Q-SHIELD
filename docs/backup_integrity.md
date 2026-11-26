# Q-SHIELD Phase 5: Backup Encryption, Verification & Anti-Rollback Integrity

## 1. Cryptographic Design

Implemented in [service.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/backups/service.py):

- **Payload Encryption (Confidentiality + Authenticity):** Keystore snapshot + control-plane metadata payload is encrypted using **AES-256-GCM** with a unique 96-bit nonce and bound canonical AAD (`backup_id`, `schema_version`, `created_at`, `active_epoch`, `max_revocation_epoch`).
- **Key Derivation:** Backup encryption key is derived via **HKDF-SHA-256** from either `QSHIELD_BACKUP_SECRET` or a local random 256-bit `qshield_backup_master.seed` stored in `keystore_dir` (never stored inside backup files or SQLite).
- **Manifest Integrity & PQ Authenticity:** Canonical JSON metadata (excluding digest/signature) is hashed with **SHA-256** (`manifest_sha256`) and signed with **ML-DSA-65** (`key-revocation-signer-v1`), verified using the persisted public key (`revocation_signer_public_key_b64`).
- **Zero Secret Leakage:** Raw private keys / secret key bytes never appear unencrypted in backup manifests, API responses, database rows, or logs.

## 2. Fail-Closed Verification Checks

`verify_backup` enforces all checks before permitting verification pass or restoration:
1. Backup manifest row exists (`BACKUP_NOT_FOUND`).
2. `schema_version == "qshield.backup.v1"` (`BACKUP_UNSUPPORTED_VERSION`).
3. Required manifest/archive fields present and parseable (`BACKUP_INCOMPLETE_MANIFEST`).
4. On-disk archive file exists (`BACKUP_FILE_MISSING`).
5. Archive `manifest_sha256` matches recomputed digest and DB manifest digest (`BACKUP_MANIFEST_TAMPERED`).
6. ML-DSA-65 signature verifies against current control-plane public key (`BACKUP_SIGNATURE_INVALID`).
7. **Anti-Rollback Check:** If live DB has `max(RevocationEvent.sequence_number) > backup.max_revocation_epoch` OR any `RevocationTombstone` with `revocation_epoch > backup.max_revocation_epoch`, or contains tombstones targeting keys recorded as active in the snapshot that post-date the backup epoch, verification marks `verification_status = "STALE_REJECTED"`, `verified = False`, and raises `409 BACKUP_STALE_ANTI_ROLLBACK`.
8. HKDF + AES-256-GCM decryption verifies ciphertext, tag, and AAD (`BACKUP_DECRYPT_FAILED`).

## 3. Safe Idempotent Restoration

`restore_backup` requires explicit `confirmation=True` (`400 CONFIRMATION_REQUIRED` otherwise), executes full `verify_backup` first, and restores keystore secrets with `preserve_keys=tombstoned_key_ids` so revoked/compromised keys are never reactivated or silently overwritten. Re-running `restore_backup` is idempotent.
