# Q-SHIELD — Phase 8 End-to-End Secure Messaging Architecture

**Status:** Implemented & Tested (Phase 8)  
**Scope:** End-to-end encrypted peer messaging, durable replay prevention, simulated node delivery reliability, and peer-bound session resumption integrated with Phases 1–7 (identity, devices, keystore, revocation coordinator, node simulator, append-only audit ledger, and deterministic detector).

---

## 1. Component Overview

- [crypto_channel.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/messaging/crypto_channel.py) — Reuses vetted Phase 3 cryptographic primitives (`MLKEM768Provider`, `HKDF-SHA-256`, `AES256GCMProvider`, `hmac_sha256_hex` / `verify_hmac_sha256_hex`, `sha256_hex`, and OS CSPRNG). Enforces strict 12-byte nonces, canonical 12-field AAD metadata binding, and fail-closed recipient/sender/session/key-version verification before releasing plaintext.
- [session_manager.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/messaging/session_manager.py) — Implements the explicit 8-state `CryptoSession` state machine (`NEW`, `NEGOTIATING`, `ESTABLISHED`, `SUSPENDED`, `RESUMING`, `EXPIRED`, `REVOKED`, `COMPROMISED`), peer/device/key/node trust checks, ephemeral ML-KEM-768 establishment with key erasure, HMAC-SHA-256 single-use resumption token lifecycle, and revocation propagation hooks.
- [message_service.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/messaging/message_service.py) — Implements sender authorization, symmetric HKDF message-key ratcheting, database nonce/sequence uniqueness, read-only envelope verification, recipient-bound authenticated decryption with post-delivery key erasure, durable `ReplayRecord` persistence, and `_MESSAGE_RECEIVE_LOCK` race protection.
- [delivery_simulator.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/messaging/delivery_simulator.py) — Simulates normal relay delivery, bounded packet loss recovery vs dead-letter, delay/TTL interactions, bounded out-of-order recovery buffering, duplicate delivery blocking, node disconnection/reconnection, and idempotent acknowledgements via `node_registry` and `message_deliveries`.
- [api/v1/messaging.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/api/v1/messaging.py) & [schemas/messaging.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/schemas/messaging.py) — Exposes authenticated, RBAC-gated `/api/v1/messages/*` endpoints.

---

## 2. Trust, Revocation, Audit & Detector Integration

1. **Zero-Trust Verification (`verify_messaging_peers_and_trust`):** Every session establish, send, receive, and resume checks both peer accounts, `RevocationTombstone` records (`actor`, `device`, `key`), `TRUSTED` device ownership, active `"messaging"` `KeyMetadata`, and simulated `NodeRegistry.local_revocations_json`.
2. **Revocation Invalidation:** Issuing a revocation through [revocation/coordinator.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/revocation/coordinator.py) invokes `invalidate_messaging_sessions_for_subject`, immediately setting matching `CryptoSession` rows to `REVOKED` and deleting retained chain/resumption keys from `LocalEncryptedKeyStore`.
3. **Audit Ledger & Secrecy:** All lifecycle events (`MSG_SESSION_ESTABLISHED`, `MSG_SESSION_SUSPENDED`, `MSG_SESSION_RESUMED`, `MSG_SESSION_RESUME_DENIED`, `MSG_SESSION_REVOKED`, `MSG_SENT`, `MSG_DELIVERED`, `MSG_DECRYPT_FAILED`, `MSG_REPLAY_REJECTED`, `MSG_DELIVERY_SIMULATED`, `MSG_DELIVERY_ACKED`, `MSG_DUPLICATE_ACK_IGNORED`) write hash-chained records with **zero plaintext, shared secrets, or resumption tokens**.
4. **Detector Linkage:** Repeated `MSG_REPLAY_REJECTED` (`action="receive_message"`, `reason_code="REPLAY_DETECTED"`) events are ingested cleanly by Phase 7's `RULE-TMP-001` deterministic replay detector.
