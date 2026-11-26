# Q-SHIELD — Vault Envelope Encryption Specification (Phase 3)

**Implementation:** [backend/app/vault/crypto_vault.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/vault/crypto_vault.py)

---

## 1. Encryption & AAD Binding
Every protected resource encrypted via `POST /api/v1/resources/{resource_id}/encrypt` receives:
1. A fresh random 256-bit DEK (`AESGCM.generate_key(256)`).
2. A fresh random 96-bit nonce (`secrets.token_bytes(12)`), guarded against reuse under the same key.
3. Deterministic JSON Associated Authenticated Data (`qshield.vault.aad.v1`) binding:
   - `schema_version`
   - `resource_id`
   - `owner_id`
   - `resource_type`
   - `algorithm` (`"AES-256-GCM"`)
   - `key_version`
   - `timestamp_utc`
   - `expires_at_utc`
4. DEK wrapped via `HKDF-SHA-256(vault_kek, purpose="vault_dek", context={resource_id, key_version})` + AES-256-GCM and saved in `LocalEncryptedKeyStore` (never in SQLite).
5. Non-secret `encrypted_objects` record in SQLite (`ciphertext_ref`, `nonce`, `aead_envelope`, `version`, `integrity` SHA-256).

---

## 2. Fail-Closed Decryption Order (`POST /api/v1/resources/{resource_id}/decrypt`)
1. Run Phase 2 10-step `ZeroTrustPolicyEngine` (`actor`, `session`, `device`, `resource`, `key_version`, `incidents`).
2. Verify `EncryptedObject` metadata matches `Resource` (`resource_id`, `owner_id`, `resource_type`, `key_version`).
3. Verify `EncryptedObject.integrity` digest matches stored nonce/ciphertext/envelope.
4. Verify `vault_kek` is `ACTIVE` (never `REVOKED`/`COMPROMISED`).
5. Unwrap DEK from `LocalEncryptedKeyStore` and verify AES-256-GCM tag + AAD.
6. Release `plaintext` **only** after all checks and AEAD authentication succeed; any failure returns `403`/`409`/`503` with zero plaintext.
