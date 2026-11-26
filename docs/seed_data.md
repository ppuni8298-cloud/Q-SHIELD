# Q-SHIELD — Synthetic Seed & Reset Data (Phase 2)

**All identities, devices, sessions, tokens, and resources below are 100% synthetic demo fixtures.**  
**Module:** [backend/app/services/seed.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/services/seed.py)

## CLI Commands
- **Idempotent seed:** `.\.venv\Scripts\python.exe -m backend.app.services.seed`
- **Full deterministic reset:** `.\.venv\Scripts\python.exe -m backend.app.services.seed --reset`
- **API reset (Admin only, demo mode):** `POST /api/v1/simulation/reset` with `{"reason": "...", "confirmation": true}`

## Seeded Identities & Documented Demo Bearer Tokens
*(Tokens are hashed with SHA-256 before storage in `sessions.token_hash`; plaintext tokens are never stored in SQLite.)*

| User ID | Role | Enabled | Valid Device | Synthetic Demo Token (`Authorization: Bearer ...`) |
|---|---|---|---|---|
| `user-alex` | `owner` | `True` | `dev-alex-trusted` | `qshield-demo-token-user-alex` |
| `user-blair` | `owner` | `True` | `dev-blair-trusted` | `qshield-demo-token-user-blair` |
| `user-secops` | `security_operator` | `True` | `dev-secops-trusted` | `qshield-demo-token-user-secops` |
| `user-admin` | `admin` | `True` | `dev-admin-trusted` | `qshield-demo-token-user-admin` |
| `user-auditor` | `auditor` | `True` | `dev-auditor-trusted` | `qshield-demo-token-user-auditor` |
| `user-disabled` | `owner` | `False` | *(none)* | *(cannot authenticate)* |

Additional seeded states for testing:
- **Devices:** `dev-alex-pending` (`PENDING`), `dev-alex-suspended` (`SUSPENDED`), `dev-alex-revoked` (`REVOKED` + tombstone).
- **Sessions:** `sess-alex-expired` (`qshield-demo-token-user-alex-expired`), `sess-alex-revoked` (`qshield-demo-token-user-alex-revoked`).
- **Key Metadata Stubs:** `key-v1-active` (`version=1`, `ACTIVE`), `key-v0-revoked` (`version=0`, `REVOKED`).
- **Resources:** `res-alex-brief` (allow), `res-blair-ledger` (wrong owner deny for Alex), `res-disabled-archive` (`DISABLED`), `res-revoked-key-doc` (`key_version=0` -> Step 8 deny), `res-incident-locked` (`inc-seed-block-01` -> Step 9 deny), `res-shared-policy` (explicit `ResourcePermission` for `user-alex`).
