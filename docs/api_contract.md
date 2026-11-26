# Q-SHIELD — Phase 2 REST API Contract (`/api/v1`)

**Base Prefix:** `/api/v1`  
**OpenAPI Schema:** `GET /api/v1/openapi.json`  
**Auth Mechanism:** `Authorization: Bearer <opaque-token>` (SHA-256 hashed in `sessions.token_hash`; no raw secrets stored).  
**Correlation:** Every response includes `X-Correlation-Id` header and `correlation_id` in JSON body.  
**Error Contract:** Sanitized `{"error": {"code": "...", "message": "...", "correlation_id": "..."}}` with zero stack traces, tokens, or protected resource content.

---

## Implemented Phase 2 Endpoints

| Method & Path | Auth / Required Permission | Purpose | Key Status Codes |
|---|---|---|---|
| `GET /api/v1/health` | Public | Liveness + `demo_mode`/`offline_mode` flags | `200` |
| `GET /api/v1/ready` | Public | SQLite `PRAGMA quick_check` + schema readiness | `200`, `503` |
| `POST /api/v1/auth/demo-login` | Public (`demo_mode=true` only) | Authenticate synthetic actor + `TRUSTED` owned device; return opaque bearer token | `200`, `403`, `422` |
| `POST /api/v1/auth/logout` | Bearer session | Revoke caller's current session | `200`, `401` |
| `GET /api/v1/auth/me` | Bearer session | Return caller actor, active session, and permissions | `200`, `401`, `403` |
| `GET /api/v1/auth/sessions` | `session:read` or `session:read_own` | Paginated session listing (owners scoped to self) | `200`, `401`, `403` |
| `POST /api/v1/auth/sessions/{id}/revoke` | `session:revoke` + `reason` + `confirmation=true` | Administratively revoke session | `200`, `400`, `401`, `403`, `404` |
| `GET /api/v1/users` | `identity:read` | Paginated user listing | `200`, `401`, `403` |
| `GET /api/v1/users/{id}` | `identity:read` or self | User detail + device IDs + active session count | `200`, `401`, `403`, `404` |
| `POST /api/v1/users` | `identity:manage` + `reason` + `confirmation=true` | Create synthetic user | `201`, `400`, `403`, `409` |
| `PATCH /api/v1/users/{id}` | `identity:manage` + `reason` + `confirmation=true` | Update display name, enabled state (writes/clears actor tombstone), or role (self-role change forbidden) | `200`, `400`, `403`, `404` |
| `GET /api/v1/roles` | `role:read` | List RBAC roles and permissions | `200`, `401`, `403` |
| `GET /api/v1/devices` | Bearer session (`device:read` or own) | Paginated device listing (owners scoped to own) | `200`, `401`, `403` |
| `GET /api/v1/devices/{id}` | Bearer session (`device:read` or owner) | Device detail | `200`, `401`, `403`, `404` |
| `GET /api/v1/devices/{id}/history` | Bearer session (`device:read` or owner) | Immutable device state transition history | `200`, `401`, `403`, `404` |
| `POST /api/v1/devices/enroll` | `device:enroll` | Enroll device (`owner` -> own `PENDING` only; operator/admin -> `PENDING`/`TRUSTED`) | `201`, `403`, `404`, `409` |
| `POST /api/v1/devices/{id}/approve` | `device:approve` + `reason` + `confirmation=true` | Transition `PENDING -> TRUSTED` (rejects `REVOKED`) | `200`, `400`, `403`, `404`, `409` |
| `POST /api/v1/devices/{id}/suspend` | `device:suspend` + `reason` + `confirmation=true` | Transition `TRUSTED -> SUSPENDED` | `200`, `400`, `403`, `404`, `409` |
| `POST /api/v1/devices/{id}/restore` | `device:restore` + `reason` + `confirmation=true` | Transition `SUSPENDED -> TRUSTED` (permanently rejects `REVOKED`) | `200`, `400`, `403`, `404`, `409` |
| `POST /api/v1/devices/{id}/revoke` | `device:revoke` + `reason` + `confirmation=true` | Transition to `REVOKED`, create durable tombstone, revoke bound sessions | `200`, `400`, `403`, `404` |
| `POST /api/v1/devices/re-enroll` | `device:re_enroll` + `reason` + `confirmation=true` | Revoke old device, block old fingerprint, enroll distinct replacement (`TRUSTED` if operator/admin, `PENDING` if owner) | `201`, `400`, `403`, `404`, `409` |
| `GET /api/v1/resources` | Bearer session (`resource:read_meta` or own) | Paginated resource metadata listing | `200`, `401`, `403` |
| `POST /api/v1/resources` | `resource:create` | Create synthetic resource metadata | `201`, `403`, `404`, `409` |
| `GET /api/v1/resources/{id}` | Bearer session (`resource:read_meta` or owner) | Resource metadata detail | `200`, `401`, `403`, `404` |
| `POST /api/v1/resources/{id}/access` | Bearer session | Execute 10-step zero-trust policy check for caller's session/device; returns metadata on `ALLOW`, `403` with zero metadata on `DENY` | `200`, `401`, `403` |
| `POST /api/v1/policy/evaluate` | `policy:evaluate` or `policy:evaluate_own` | Run deterministic 10-step policy trace (owners restricted to own `actor_id`) | `200`, `401`, `403` |
| `POST /api/v1/simulation/reset` | `simulation:reset` (`admin` + `demo_mode` + `reason` + `confirmation=true`) | Reset database to deterministic synthetic seed baseline | `200`, `400`, `401`, `403` |
