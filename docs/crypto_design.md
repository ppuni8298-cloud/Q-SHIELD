# Q-SHIELD — Cryptographic Design Specification (Phase 3)

**Rule:** Zero custom cryptographic algorithms. Every primitive is backed by vetted, pinned libraries inspected directly in `.venv` (Python `3.12.10`).

---

## 1. Verified Libraries & Exact APIs

| Primitive | Purpose | Library & Pinned Version | Verified API / Parameters |
|---|---|---|---|
| **ML-KEM-768** | Post-quantum KEM for `protected_read` interop & shared-secret establishment | `pqcrypto==0.4.0` (`pqcrypto.kem.ml_kem_768`) | `generate_keypair()`, `encrypt(pk)`, `decrypt(sk, ct)`; `PUBLIC_KEY_SIZE=1184`, `SECRET_KEY_SIZE=2400`, `CIPHERTEXT_SIZE=1088`, `PLAINTEXT_SIZE=32` |
| **ML-DSA-65** | Post-quantum signature foundation for receipts, backups, and checkpoints | `pqcrypto==0.4.0` (`pqcrypto.sign.ml_dsa_65`) | `generate_keypair()`, `sign(sk, msg)`, `verify(pk, msg, sig)`; `PUBLIC_KEY_SIZE=1952`, `SECRET_KEY_SIZE=4032`, `SIGNATURE_SIZE=3309` |
| **AES-256-GCM** | Authenticated encryption of protected vault resources & local encrypted keystore | `cryptography==50.0.2` (`cryptography.hazmat.primitives.ciphers.aead.AESGCM`) | 256-bit key (`32` bytes), 96-bit CSPRNG nonce (`12` bytes), `encrypt(nonce, data, aad)`, `decrypt(nonce, data, aad)` (`InvalidTag` on tamper) |
| **HKDF-SHA-256** | Purpose-separated key derivation (KEK -> DEK wrapping, keystore master, sessions) | `cryptography==50.0.2` (`cryptography.hazmat.primitives.kdf.hkdf.HKDF`) | `HKDF(algorithm=hashes.SHA256(), length=32, salt=..., info=...)` |
| **HMAC-SHA-256** | Exact `protected_read` proof (`UTF8(challenge + body)`) & constant-time verification | Python 3.12 stdlib (`hmac`, `hashlib`) | `hmac.new(key, msg, hashlib.sha256).hexdigest()`, `hmac.compare_digest()` |
| **SHA-256** | Integrity digests (non-authenticating checksums only) | Python 3.12 stdlib (`hashlib`) | `hashlib.sha256(data).hexdigest()` |
| **CSPRNG** | Nonces, DEKs, KEKs, master seed, opaque tokens | Python 3.12 stdlib (`secrets`) & `AESGCM.generate_key(256)` | OS CSPRNG (`os.urandom` / `secrets.token_bytes`) |

> **Important Distinction (Integrity vs. Authentication):** Unkeyed SHA-256 detects accidental corruption only and does NOT authenticate origin. Origin/tamper authentication relies on AES-256-GCM tags, HMAC-SHA-256 with secret keys, or ML-DSA-65 signatures.

---

## 2. Cryptographic Flows

```text
protected_read (Phase 1 Toolkit Adapter — Unchanged & Isolated):
  Authorize(actor->asset)
    -> Decode & validate raw ML-KEM-768 public_key (std Base64, 1184 bytes)
    -> (ct, shared_secret) = ml_kem_768.encrypt(pk)
    -> proof = HMAC-SHA256(shared_secret, UTF8(challenge + exact_stored_body)) [no separator, lowercase hex]
    -> Return {"ciphertext": b64(ct), "proof": proof}

Envelope Vault Encryption (Phase 3 Backend):
  Authorize(owner/admin)
    -> Fetch active vault_kek (version V) from LocalEncryptedKeyStore
    -> dek = AESGCM.generate_key(256)  [random 32-byte per-resource DEK]
    -> aad = canonical_json(schema_version, resource_id, owner_id, resource_type, algorithm, key_version, timestamp_utc, expires_at_utc)
    -> (content_nonce, content_ct) = AES256GCM.encrypt(dek, plaintext, aad)
    -> wrap_key = HKDF-SHA256(kek, salt=f"qshield-dek-wrap-salt-v{V}", purpose="vault_dek", context={resource_id, key_version})
    -> (wrap_nonce, wrapped_dek) = AES256GCM.encrypt(wrap_key, dek, aad)
    -> Store wrapped_dek in LocalEncryptedKeyStore; store non-secret EncryptedObject + integrity SHA-256 in SQLite
```

---

## 3. HKDF-SHA-256 Purpose Labels & Context Format
`build_hkdf_info(purpose, context)` serializes canonical JSON:
`{"context":{...},"domain":"qshield-hkdf-v1","purpose":"<purpose>"}`
Allowed `purpose` labels: `kem`, `signing`, `vault_dek`, `vault_kek`, `session`, `audit`, `keystore_master`, `messaging`.

---

## 4. Self-Test & Known Answer Tests (`backend/app/crypto/selftest.py`)
Executed on `GET /api/v1/ready` and `GET /api/v1/crypto/selftest`:
1. FIPS 180-4 SHA-256 KAT (`"abc"`)
2. RFC 4231 HMAC-SHA-256 Test Case 1 KAT + constant-time negative verification
3. RFC 5869 HKDF-SHA-256 Test Case 1 KAT + context separation check
4. Live ML-KEM-768 keygen/encapsulate/decapsulate + wrong-key mismatch check
5. Live AES-256-GCM roundtrip + ciphertext & AAD tamper rejection (`AEADError`)
6. Live ML-DSA-65 keygen/sign/verify + tampered-message rejection
