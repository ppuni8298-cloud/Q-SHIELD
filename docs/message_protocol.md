# Q-SHIELD — Phase 8 Message Protocol & Cryptographic Binding (`qshield.msg.aad.v1`)

**Cryptographic Primitives (Zero Custom Crypto):**
- Key Establishment: `ML-KEM-768` (`pqcrypto==0.4.0`, `PUBLIC_KEY_SIZE=1184`, `CIPHERTEXT_SIZE=1088`, `PLAINTEXT_SIZE=32`)
- Key Derivation & Ratchet: `HKDF-SHA-256` (`cryptography==50.0.2`)
- Authenticated Encryption: `AES-256-GCM` (`32`-byte key, `12`-byte OS CSPRNG nonce)
- Resumption Token MAC: `HMAC-SHA-256` (Python stdlib `hmac`, verified in constant time)

---

## 1. Key Establishment & Context Separation

Upon session establish or resumption (`generation = G`, `key_version = V`):
1. Execute ephemeral ML-KEM-768 exchange (`run_ephemeral_mlkem768_exchange`) yielding `32`-byte `shared_secret` and `1088`-byte ciphertext (`kem_ct_b64`). Immediately discard ephemeral secret key (`esk`) and raw `shared_secret` after derivation.
2. Derive purpose-separated keys via `derive_key_hkdf_sha256` with salt `qshield-msg-session-salt-v{V}-gen{G}`:
   - **`purpose="messaging"`, `role="session_chain"`** -> initial 32-byte generation `chain_key`.
   - **`purpose="session"`, `role="resumption_mac"`** -> 32-byte `resumption_mac_key` used exclusively for `qsr_v1` resumption tokens.
3. For each message at `(generation=G, sequence=S)`, `ratchet_message_key` derives:
   - `msg_key` (`step="message_aead"`) -> used once for `AES-256-GCM` and deleted from `LocalEncryptedKeyStore` immediately after recipient decryption.
   - `next_chain_key` (`step="chain_advance"`) -> replaces previous generation `chain_key`.

---

## 2. Canonical Envelope & AES-GCM AAD Metadata (`qshield.msg.aad.v1`)

Every encrypted message binds the exact canonical JSON UTF-8 representation (`separators=(",", ":")`, `sort_keys=True`) of:

| Field | Description |
|---|---|
| `schema_version` | Fixed `"qshield.msg.aad.v1"` |
| `algorithm` | Fixed `"AES-256-GCM"` |
| `sender_id` | Authenticated sender user ID |
| `recipient_id` | Authenticated intended recipient user ID |
| `message_id` | Unique opaque `msg-*` identifier |
| `session_id` | Parent `CryptoSession.id` (`csess-*`) |
| `session_generation` | Integer session generation (`>= 1`) |
| `sequence` | Monotonic per-session send sequence (`>= 1`) |
| `key_version` | Active `"messaging"` key version (`KeyMetadata.version`) |
| `nonce_b64` | Standard Base64 of `12`-byte CSPRNG GCM nonce |
| `created_at_utc` | ISO-8601 UTC message creation timestamp |
| `expires_at_utc` | ISO-8601 UTC message expiry timestamp |

---

## 3. Fail-Closed Recipient Verification & Replay Prevention

Before `AES256GCMProvider.decrypt(...)` runs:
1. Caller must authenticate as `msg.recipient_id` using the session-bound `recipient_device_id` (`403 DENY_WRONG_RECIPIENT` / `DENY_RECIPIENT_DEVICE_MISMATCH` otherwise).
2. Session state must be `ESTABLISHED` and unexpired; both peers, devices, messaging key version, and simulated nodes must be free of revocations.
3. Message expiry `now < expires_at` is enforced (`403 DENY_MESSAGE_EXPIRED`).
4. Durable `ReplayRecord` uniqueness on `(recipient_id, session_id, "msg:{message_id}")` AND `(recipient_id, session_id, "seq:{generation}:{sequence}")` rejects duplicates (`409 REPLAY_DETECTED`) and emits audited replay events.
5. Explicit envelope binding (`sender_id`, `recipient_id`, `session_id`, `key_version`) and reconstructed `aad_sha256` are checked; any 1-bit tamper in ciphertext, tag, nonce, or AAD triggers `InvalidTag` -> `403 AEAD_INTEGRITY_FAILED` releasing **zero plaintext**.
6. Only upon successful decryption does the backend record accepted `ReplayRecord` rows and erase `msg-key:{message_id}` from `LocalEncryptedKeyStore`.
