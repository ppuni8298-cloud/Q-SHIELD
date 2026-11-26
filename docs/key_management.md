# Q-SHIELD — Key Management & Local Key Storage (Phase 3)

**Modules:** [backend/app/keys/lifecycle.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/keys/lifecycle.py), [backend/app/keys/service.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/keys/service.py), [backend/app/crypto/keystore.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/crypto/keystore.py)

---

## 1. Key Lifecycle State Machine

Valid states: `PREPARED`, `ACTIVE`, `ROTATING`, `ACTIVE_NEW`, `RETIRED`, `REVOKED`, `COMPROMISED`.

Allowed transitions:
- `PREPARED` -> `ACTIVE`, `REVOKED`, `COMPROMISED`
- `ACTIVE` -> `ROTATING`, `RETIRED`, `REVOKED`, `COMPROMISED`
- `ROTATING` -> `ACTIVE_NEW`, `REVOKED`, `COMPROMISED`
- `ACTIVE_NEW` -> `ACTIVE`, `RETIRED`, `REVOKED`, `COMPROMISED`
- `RETIRED` -> `REVOKED`, `COMPROMISED`
- `REVOKED` -> *(Terminal: zero outgoing transitions; writes `RevocationTombstone`)*
- `COMPROMISED` -> *(Terminal: zero outgoing transitions; writes `RevocationTombstone`)*

Key-purpose separation enforces distinct key records for `kem`, `signing`, `vault_kek`, `vault_dek`, `session`, and `audit`.

---

## 2. Local Encrypted Key Store Design & Honest Limitations

- **Storage Location:** Outside repo root and static directories, under configurable `QSHIELD_KEYSTORE_DIR` (defaults to `<tempdir>/qshield/keystore` or `$TRACK4_STATE_DIR/keystore`).
- **Protection Mechanism:** All secret bytes (`vault_kek`, wrapped `vault_dek`, ML-KEM/ML-DSA private keys) are stored inside `qshield_keystore.enc.json` encrypted via `AES-256-GCM` (`AAD = b"qshield.local.keystore.envelope.v1"`) using a master key derived via `HKDF-SHA-256`.
- **Master Key Source:**
  - If `QSHIELD_KEYSTORE_SECRET` environment variable is supplied, master key derives from that secret.
  - Otherwise (offline local demo mode), a 32-byte CSPRNG seed is generated into `qshield_master.seed` with `0o600` permissions (where OS supports POSIX modes).
- **SQLite Hygiene:** `key_metadata` stores `key_id`, `purpose`, `algorithm`, `version`, `state`, and timestamps ONLY—zero private keys or raw secrets.
- **Fail-Closed Behavior:** Missing seed, missing envelope, tampered ciphertext/tag, or purpose mismatch raises `KeyStoreError` and denies operations without releasing secrets or plaintext.
- **Explicit Prototype Limitations:**
  - **Not an HSM:** This is a local sandbox-only key store. An adversary with full OS/host file access to both `qshield_keystore.enc.json` and `qshield_master.seed` (or `QSHIELD_KEYSTORE_SECRET`) could unwrap local demo keys.
  - Windows NTFS ACLs do not enforce Unix `0600` mode bits identically to Linux `chmod`.
