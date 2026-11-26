# Q-SHIELD — Phase 8 Session Management State Machine

**Implementation:** [backend/app/messaging/session_manager.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/messaging/session_manager.py) (`CryptoSession` / `sessions_crypto`)

---

## 1. Explicit 8-State Lifecycle

Valid states (`ck_sessions_crypto_state`):
`NEW`, `NEGOTIATING`, `ESTABLISHED`, `SUSPENDED`, `RESUMING`, `EXPIRED`, `REVOKED`, `COMPROMISED`.

### Allowed State Transitions (`SESSION_ALLOWED_TRANSITIONS`)

| From State | Allowed Next States | Notes |
|---|---|---|
| `NEW` | `NEGOTIATING`, `REVOKED`, `COMPROMISED` | Initial transient establishment entry state |
| `NEGOTIATING` | `ESTABLISHED`, `EXPIRED`, `REVOKED`, `COMPROMISED` | ML-KEM-768 & HKDF key establishment phase |
| `ESTABLISHED` | `SUSPENDED`, `EXPIRED`, `REVOKED`, `COMPROMISED` | Active sending & receiving permitted ONLY in `ESTABLISHED` |
| `SUSPENDED` | `RESUMING`, `EXPIRED`, `REVOKED`, `COMPROMISED` | Paused; send/receive blocked fail-closed until resumed |
| `RESUMING` | `ESTABLISHED`, `SUSPENDED`, `EXPIRED`, `REVOKED`, `COMPROMISED` | Verification & ML-KEM-768 re-keying prior to re-activating |
| `EXPIRED` | `REVOKED`, `COMPROMISED` | **Terminal for messaging/resumption** |
| `REVOKED` | *(none — terminal)* | **Terminal; all keys erased, resumption disallowed** |
| `COMPROMISED` | *(none — terminal)* | **Terminal; all keys erased, resumption disallowed** |

---

## 2. Control Endpoints & Authorization Rules

- `POST /api/v1/messages/sessions`: Requires `messaging:use`; caller becomes authenticated `initiator_id` + bound `initiator_device_id`, selects `recipient_id` + `recipient_device_id` (distinct identity pair), validates devices `TRUSTED` and active keys, transitions `NEW -> NEGOTIATING -> ESTABLISHED`.
- `GET /api/v1/messages/sessions` & `GET /api/v1/messages/sessions/{id}`: Returns cryptographic metadata and FS status (`auditor`/`secops`/`admin` see all; `owner` sees own peer sessions only). Never exposes chain keys, shared secrets, or plaintext tokens.
- `POST /api/v1/messages/sessions/{id}/suspend`: Requires bound peer or `messaging:manage`, explicit `reason` and `confirmation=True`.
- `POST /api/v1/messages/sessions/{id}/revoke`: Requires bound peer or `messaging:manage`, `reason`, `confirmation=True`, optional `compromised=True`; immediately deletes `msg-chain:{id}:*` and `msg-resmac:{id}` keys from `LocalEncryptedKeyStore`.
- **Automatic Revocation Propagation:** Actor, device, or `"messaging"` key revocations via Phase 4 `/api/v1/revocations` immediately mark active/suspended `CryptoSession`s `REVOKED` and purge session keystore material.
