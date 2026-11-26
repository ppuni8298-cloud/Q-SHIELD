# Q-SHIELD — Phase 8 Peer-Bound Session Resumption

**Endpoint:** `POST /api/v1/messages/sessions/{session_id}/resume`  
**Implementation:** `resume_messaging_session(...)` in [session_manager.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/messaging/session_manager.py)

---

## 1. Resumption Token Format & Storage Hygiene

- **Format:** `qsr_v1.<urlsafe_b64_payload>.<hmac_sha256_hex>`
- **Bound Claims:** `session_id`, `initiator_id`, `recipient_id`, `initiator_device_id`, `recipient_device_id`, `generation`, `key_version`, `nonce` (16 random CSPRNG bytes), `issued_at_utc`, `expires_at_utc`.
- **Storage Hygiene:** Only `SHA-256(resumption_token)` is stored in `sessions_crypto.resumption_token_hash`. The plaintext token is returned strictly once upon establishment or successful resumption and NEVER logged to audit payloads.

---

## 2. Mandatory 7-Step Resumption Verification Checklist

Every `resume_messaging_session` request fails closed unless **all** checks pass:
1. **Terminal/Revocation State:** Session state is NOT `REVOKED` or `COMPROMISED` (`403 DENY_SESSION_*`), NOT `EXPIRED`, and currently in `SUSPENDED` or `ESTABLISHED`.
2. **Session Expiry:** `now < CryptoSession.expires_at` (transitions stale session to `EXPIRED` and rejects `403 DENY_SESSION_EXPIRED`).
3. **Peer & Device Binding:** Authenticated caller (`ctx.user.id`, `ctx.device.id`) and requested `peer_id` match either `(initiator_id, recipient_id)` with `initiator_device_id` OR `(recipient_id, initiator_id)` with `recipient_device_id`. Any cross-peer or wrong-device attempt is denied (`403 DENY_RESUMPTION_PEER_MISMATCH` / `DENY_RESUMPTION_DEVICE_MISMATCH`) and audited (`MSG_SESSION_RESUME_DENIED`).
4. **Live Zero-Trust Re-Evaluation:** Runs `verify_messaging_peers_and_trust(...)` verifying both identities enabled, zero `actor`/`device`/`key` tombstones, both devices `TRUSTED`, `KeyMetadata` `ACTIVE`, and zero local node revocations across `node_registry`. Old session credentials **cannot** resurrect revoked authorization.
5. **Single-Use Anti-Replay Check:** Constant-time hash compare (`verify_token_hash`) against `sessions_crypto.resumption_token_hash`. Replaying a previously consumed token immediately rejects with `409 RESUMPTION_TOKEN_REPLAYED_OR_INVALID`.
6. **HMAC-SHA-256 & Claim Match:** Validates token signature with `msg-resmac:{session_id}` in constant time and verifies `session_id`, `initiator_id`, `recipient_id`, `generation`, and `key_version` claims.
7. **Fresh Re-Keying & Token Rotation:** Transitions `SUSPENDED -> RESUMING -> ESTABLISHED`, runs a fresh ephemeral ML-KEM-768 key exchange, increments `generation += 1`, derives new HKDF generation chain/MAC keys, **deletes previous generation chain key**, and rotates a brand-new single-use `next_resumption_token`.
