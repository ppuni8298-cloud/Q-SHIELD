# Q-SHIELD — Phase 8 Honest Forward Secrecy Analysis

**Assessed Verdict:** **`PARTIAL (Ephemeral ML-KEM-768 + Symmetric Chain Erasure Verified Against Long-Term Signing/Vault Keys; Control-Plane Keystore Boundary Applies)`**

---

## 1. Key Material Inventory: What Is Erased vs Retained

| Key Material | Lifecycle Handling | Verification Status |
|---|---|---|
| **Ephemeral ML-KEM-768 secret key (`esk`)** | Generated ephemerally during establishment/resumption (`run_ephemeral_mlkem768_exchange`); deleted from memory (`del esk`) immediately after decapsulation verification and **never written to SQLite or keystore**. | `ephemeral_key_erased=True` |
| **Raw ML-KEM shared secret (`ss`)** | Consumed once by HKDF-SHA-256 (`derive_session_generation_keys`) and deleted (`del shared_secret`) immediately; never stored. | Erased post-derivation |
| **Per-message AEAD key (`msg-key:{id}`)** | Stored temporarily inside AES-GCM `LocalEncryptedKeyStore` while encrypted message awaits async delivery (`QUEUED` / `IN_TRANSIT`), then **deleted (`keystore.delete_key`) immediately upon successful recipient decryption**. | Verified (`test_14` asserts `has_key(...) is False`) |
| **Previous generation `chain_key`** | Deleted (`keystore.delete_key(chain_keystore_id(..., old_gen))`) when session resumes and re-keys via fresh ML-KEM-768 (`test_18`). | Verified |
| **Current active `chain_key` & `resumption_mac_key`** | Retained inside `LocalEncryptedKeyStore` (`qshield_keystore.enc.json` protected by `qshield_master.seed`) while the session remains `ESTABLISHED`/`SUSPENDED`. Deleted when session is `REVOKED`/`COMPROMISED`. | Retained for stateless REST persistence |

---

## 2. Security Evaluation Against Compromise Scenarios

1. **Compromise of Long-Term Vault / Signing / Audit Keys Only (`vault_kek`, `key-revocation-signer-v1`, `key-audit-signer-v1`):**
   - **Cannot recover historical or active messaging sessions.** Compromising long-term signing or vault KEKs gives zero capability to decapsulate recorded ephemeral ML-KEM-768 ciphertexts (`test_20`), because those keys do not wrap messaging session secrets and ephemeral `esk` was never stored.
2. **Compromise After Delivery of Delivered Messages (Active `chain_key` Leakage Only):**
   - Because HKDF forward-ratchets `chain_key_{S} -> chain_key_{S+1}` (one-way SHA-256 KDF) and `msg-key:{id}` is deleted upon delivery, obtaining `chain_key_{S+1}` does **not** allow recomputing already-delivered `msg_key_{S}` or decrypting previously delivered messages in that session.
3. **Honest Prototype Limitations (Why FS is `PARTIAL`, NOT Full End-to-End Double-Ratchet):**
   - **Single-Host Control-Plane Keystore Boundary:** Because Q-SHIELD runs as a stateless FastAPI local control-plane monolith rather than two physically isolated endpoint devices with client-side enclave storage, active `chain_key`s and undelivered (`QUEUED`) `msg-key:{id}` entries reside encrypted in `LocalEncryptedKeyStore` (`qshield_keystore.enc.json`). An adversary who compromises **both** the host filesystem (`qshield_master.seed` + `qshield_keystore.enc.json`) and SQLite **prior** to message delivery/revocation could unwrap queued message keys.
   - **No Per-Message Asymmetric Ratchet / Break-In Recovery:** Within a single session generation, ratcheting is symmetric (HKDF). If an active `chain_key` at sequence `S` is exfiltrated, subsequent messages `S+1..` remain exposed until the next peer-bound resumption (`POST /sessions/{id}/resume`) performs a fresh ephemeral ML-KEM-768 re-keying (`generation += 1`).

For these reasons, Q-SHIELD explicitly documents Forward Secrecy as **`PARTIAL (Control-Plane Mediated)`** in code (`CryptoSession.forward_secrecy_status`), API responses (`SessionEstablishResponse.forward_secrecy_note`), and evidence artifacts.
