# Q-SHIELD Phase 5: Phased Key Rotation & Zero-Grace Cutoff Design

## 1. Objectives

Phase 5 implements production-grade, fail-closed key rotation across `LocalEncryptedKeyStore`, envelope-encrypted vault objects (`EncryptedObject` + wrapped DEKs), SQLite metadata (`KeyMetadata`, `RotationOperation`, `InFlightTransfer`), and the simulated multi-node registry (`NodeRegistry`, `NodeAcknowledgement`).

Implemented modules:
- [rotation.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/keys/rotation.py)
- [service.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/keys/service.py)
- [lifecycle.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/keys/lifecycle.py)
- [simulator.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/nodes/simulator.py)
- [rotation_backup.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/api/v1/rotation_backup.py)

## 2. Explicit 4-Stage Rotation State Machine

Every rotation executes sequentially through `PREPARE -> DISTRIBUTE -> COMMIT -> RETIRE`:

| Stage | Journal `committed` | Key Metadata States | Vault & Node Behavior |
|---|---|---|---|
| `PREPARE` | `False` | New key generated into `LocalEncryptedKeyStore` as `PREPARED` (`to_version = from_version + 1`); old key transitions `ACTIVE -> ROTATING`. | Automatic pre-rotation backup (`create_backup`) is created and its `backup_id` persisted on `RotationOperation`. Existing resources keep `key_version = from_version` and remain decryptable. |
| `DISTRIBUTE` | `False` | Old key remains `ROTATING`; new key remains `PREPARED`. | For `vault_kek`, DEKs are unwrapped via old KEK, re-encrypted with updated `to_version` AAD, and pre-staged alongside `to_version` wrapped DEKs without altering `Resource.key_version`. All healthy nodes record `staged_key_version = to_version` (`ACKED`); offline/faulty nodes record `DEFERRED`. |
| `COMMIT` | `True` (atomic cutover) | New key transitions `PREPARED -> ACTIVE_NEW`. | All healthy nodes transition `accepted_key_version = to_version` and `cutoff_epoch = max(cutoff_epoch, to_version)`. Offline/faulty nodes still advance `cutoff_epoch` so they fail closed on old keys upon recovery. Resources flip to `to_version` (unless deferred strictly for `CONTROLLED_IN_FLIGHT_ONLY`). |
| `RETIRE` | `True` | Old key transitions `ROTATING -> RETIRED`; new key transitions `ACTIVE_NEW -> ACTIVE`. | Any lingering `STARTED` in-flight transfers are `ABORTED`; remaining resources move to `to_version`; `RotationOperation.status` transitions to `COMPLETED`. |

## 3. Single-Active-Rotation Concurrency Guard

Both service-layer pre-checks (`execute_rotation`) and a SQLite partial unique index (`uq_active_rotation_per_purpose` on `rotation_operations(purpose) WHERE status = 'IN_PROGRESS'`) enforce at most one active rotation per key purpose (`409 ROTATION_ALREADY_IN_PROGRESS`).

## 4. Continuity & Zero-Grace Cutoff Policy

- **Default (`ZERO_GRACE`)**: Upon `COMMIT`, every simulated node sets `cutoff_epoch = to_version` and rejects any request targeting `resource.key_version < node.cutoff_epoch` with `DENY_NODE_OLD_KEY_CUTOFF`. Pre-existing `InFlightTransfer` rows on `from_version` are marked `ABORTED` and denied completion (`403 DENY_OLD_KEY_CUTOFF` / `DENY_TRANSFER_KEY_REVOKED`).
- **Optional (`CONTROLLED_IN_FLIGHT_ONLY`)**: Only explicitly registered pre-cutoff `InFlightTransfer` rows (`allow_post_cutoff=True`, `state='STARTED'`) on non-revoked keys are allowed to finish post-commit reads (`transfer_id` matched explicitly in `node_evaluate_access`) before `RETIRE`. New post-cutoff requests without an authorized pre-cutoff transfer are immediately denied (`DENY_NODE_OLD_KEY_CUTOFF`). At `RETIRE`, old key enters `RETIRED` and all continuity ends.
