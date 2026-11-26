# Q-SHIELD — Deterministic 10-Step Zero-Trust Policy Specification (Phase 2)

**Implementation:** [backend/app/policy/engine.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/policy/engine.py) & [backend/app/policy/interfaces.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/policy/interfaces.py)

Every policy decision runs strictly in order 1 -> 10, defaults to `DENY`, persists a decision record in `access_requests`, and fails closed (`DENY_INTERNAL_ERROR`) on any unexpected error.

| Step | Check Name | Failure Reason Codes | Interface / Source |
|---|---|---|---|
| 1 | Parse and validate request | `DENY_INVALID_REQUEST` | Opaque ID regex (`^[A-Za-z0-9._:-]{1,128}$`) |
| 2 | Identity active | `DENY_UNKNOWN_IDENTITY`, `DENY_IDENTITY_DISABLED` | `users` + `revocation_tombstones` (`actor`) |
| 3 | Authenticated session valid and bound to identity | `DENY_SESSION_NOT_FOUND`, `DENY_SESSION_IDENTITY_MISMATCH` | `sessions` |
| 4 | Session not expired or revoked | `DENY_SESSION_REVOKED`, `DENY_SESSION_EXPIRED`, `DENY_SESSION_INACTIVE` | `sessions.state`, `revoked_at`, `expires_at` |
| 5 | Device enrolled, owned by actor, trusted and not revoked | `DENY_SESSION_DEVICE_MISMATCH`, `DENY_DEVICE_NOT_FOUND`, `DENY_DEVICE_OWNERSHIP_MISMATCH`, `DENY_DEVICE_REVOKED`, `DENY_DEVICE_SUSPENDED`, `DENY_DEVICE_PENDING`, `DENY_DEVICE_UNTRUSTED` | `devices` + `revocation_tombstones` (`device`) |
| 6 | Actor has permission for resource and action | `DENY_ROLE_PERMISSION_DENIED`, `DENY_RESOURCE_PERMISSION_DENIED` | `ROLE_PERMISSION_DEFINITIONS`, `resources.owner_id`, `resource_permissions` |
| 7 | Resource exists and is not disabled | `DENY_RESOURCE_NOT_FOUND`, `DENY_RESOURCE_DISABLED` | `resources` |
| 8 | Key version active and not revoked/compromised | `DENY_KEY_NOT_FOUND`, `DENY_KEY_REVOKED`, `DENY_KEY_INACTIVE` | `KeyValidityChecker` (`MetadataKeyValidityChecker` on `key_metadata` in Phase 2) |
| 9 | Incident and policy denial check | `DENY_ACTIVE_INCIDENT` | `IncidentDenialChecker` (`TableIncidentDenialChecker` on `incidents` in Phase 2) |
| 10 | Final decision & correlation | `ALLOW_AUTHORIZED` or failing step code (`DENY_INTERNAL_ERROR` on exception) | Persisted to `access_requests` |
