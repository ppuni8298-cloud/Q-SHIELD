"""Phase 5 Idempotent Crash Recovery Manager.

Recovers interrupted RotationOperation records deterministically:
1. Verifies durable journal_hash before taking any action; mismatches FAIL CLOSED.
2. Enforces irreversible RevocationTombstone precedence (NEVER reactivates revoked/compromised keys).
3. Uncommitted rotations (`committed=False`: PREPARE or DISTRIBUTE) roll back safely:
   - Staged node keys cleared; old key stays/restores ACTIVE; unused staged key retired/revoked safely.
   - Pre-cutoff resource key versions remain intact and decryptable.
4. Committed rotations (`committed=True`: COMMIT or DURING_RETIRE) roll forward cleanly:
   - Upgrades any pending resources, enforces cutoff_epoch & accepted_key_version across all nodes,
     retires old key, promotes non-tombstoned new key to ACTIVE, marks RECOVERED_POST_COMMIT.
5. Idempotent under repeated calls: re-running recovery after completion performs zero destructive mutations.
"""

from __future__ import annotations

from dataclasses import dataclass
import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.audit.ledger import append_audit_event, audit_write_lock
from backend.app.crypto.keystore import LocalEncryptedKeyStore
from backend.app.db.models import KeyMetadata, RevocationTombstone, RotationOperation, utc_now
from backend.app.keys.lifecycle import TERMINAL_KEY_STATES, validate_key_transition
from backend.app.keys.rotation import (
    _finalize_all_resources_at_retire,
    compute_journal_hash,
)
from backend.app.nodes.simulator import commit_cutoff_on_nodes, rollback_staged_key_on_nodes


@dataclass(frozen=True)
class RecoveryOutcome:
    operation_id: str
    previous_phase: str
    previous_status: str
    final_status: str
    action_taken: str
    idempotent_noop: bool
    notes: str


def _has_tombstone(db: Session, key_id: str) -> bool:
    return (
        db.scalar(
            select(RevocationTombstone.id).where(
                RevocationTombstone.target_type == "key",
                RevocationTombstone.target_id == key_id,
            )
        )
        is not None
    )


def recover_single_operation(
    db: Session,
    keystore: LocalEncryptedKeyStore,
    op: RotationOperation,
) -> RecoveryOutcome:
    """Recover one interrupted RotationOperation idempotently and fail-closed on corruption/tombstones."""
    prev_phase = op.phase
    prev_status = op.status

    if op.status in ("COMPLETED", "RECOVERED_PRE_COMMIT", "RECOVERED_POST_COMMIT", "FAILED_CLOSED"):
        return RecoveryOutcome(
            operation_id=op.operation_id,
            previous_phase=prev_phase,
            previous_status=prev_status,
            final_status=op.status,
            action_taken="NOOP_ALREADY_FINALIZED",
            idempotent_noop=True,
            notes=op.recovery_notes or "Operation already in terminal/recovered state.",
        )

    # 1. Verify journal hash integrity FIRST
    expected_hash = compute_journal_hash(op)
    if expected_hash != op.journal_hash:
        with audit_write_lock():
            op.status = "FAILED_CLOSED"
            op.failure_info = "JOURNAL_HASH_MISMATCH"
            op.recovery_notes = "Journal integrity verification failed; refused unsafe recovery."
            op.updated_at = utc_now()
            append_audit_event(
                db,
                event_type="CRASH_RECOVERY_FAILED",
                event_category="RECOVERY",
                actor_id="system",
                action="recover_rotation",
                target_type="rotation",
                target_id=op.operation_id,
                outcome="DENY",
                reason_code="JOURNAL_HASH_MISMATCH",
                correlation_id=op.correlation_id,
                source_component="recovery_manager",
                payload={"previous_phase": prev_phase, "action_taken": "HALTED_JOURNAL_CORRUPTION"},
                commit=False,
            )
            db.commit()
        db.refresh(op)
        return RecoveryOutcome(
            operation_id=op.operation_id,
            previous_phase=prev_phase,
            previous_status=prev_status,
            final_status=op.status,
            action_taken="HALTED_JOURNAL_CORRUPTION",
            idempotent_noop=False,
            notes=op.recovery_notes,
        )

    from_key = db.get(KeyMetadata, op.from_key_id)
    to_key = db.get(KeyMetadata, op.to_key_id)
    to_tombstoned = to_key is None or to_key.state in TERMINAL_KEY_STATES or _has_tombstone(db, op.to_key_id)
    from_tombstoned = from_key is None or from_key.state in TERMINAL_KEY_STATES or _has_tombstone(db, op.from_key_id)

    # 2. Pre-commit recovery (`committed == False`)
    if not op.committed:
        acks = rollback_staged_key_on_nodes(db, operation_id=op.operation_id, restore_version=op.from_version)
        op.node_acks_json = json.dumps(acks, separators=(",", ":"), sort_keys=True)

        # Tombstone unused staged key or keep existing terminal state (never reactivate!)
        if to_key is not None and to_key.state not in TERMINAL_KEY_STATES:
            to_key.state = "REVOKED"
            to_key.revoked_at = utc_now()
            if not _has_tombstone(db, to_key.key_id):
                db.add(
                    RevocationTombstone(
                        target_type="key",
                        target_id=to_key.key_id,
                        revocation_epoch=max(1, op.to_version),
                        reason="Aborted pre-commit staged key during crash recovery",
                        created_at=utc_now(),
                    )
                )

        # Restore from_key ONLY if NOT revoked/compromised/tombstoned
        if from_key is not None and not from_tombstoned and from_key.state == "ROTATING":
            validate_key_transition("ROTATING", "ACTIVE")
            from_key.state = "ACTIVE"

        if from_tombstoned:
            op.status = "FAILED_CLOSED"
            op.failure_info = "SOURCE_KEY_TOMBSTONED"
            op.recovery_notes = "Pre-commit crash rolled back staged key; source key tombstoned and left inactive."
        else:
            op.status = "RECOVERED_PRE_COMMIT"
            op.recovery_notes = (
                f"Rolled back uncommitted rotation from phase '{prev_phase}'; restored '{op.from_key_id}' ACTIVE."
            )
        with audit_write_lock():
            op.updated_at = utc_now()
            op.journal_hash = compute_journal_hash(op)
            append_audit_event(
                db,
                event_type="CRASH_RECOVERY_EXECUTED",
                event_category="RECOVERY",
                actor_id="system",
                action="recover_pre_commit",
                target_type="rotation",
                target_id=op.operation_id,
                outcome="DENY" if from_tombstoned else "ALLOW",
                reason_code=op.status,
                correlation_id=op.correlation_id,
                source_component="recovery_manager",
                payload={"previous_phase": prev_phase, "final_status": op.status, "from_key_id": op.from_key_id, "to_key_id": op.to_key_id},
                commit=False,
            )
            db.commit()
        db.refresh(op)
        return RecoveryOutcome(
            operation_id=op.operation_id,
            previous_phase=prev_phase,
            previous_status=prev_status,
            final_status=op.status,
            action_taken="ROLLBACK_PRE_COMMIT",
            idempotent_noop=False,
            notes=op.recovery_notes,
        )

    # 3. Post-commit recovery (`committed == True`)
    # Check tombstones strictly FIRST — never reactivate a revoked/compromised to_key!
    if to_tombstoned:
        commit_cutoff_on_nodes(
            db,
            operation_id=op.operation_id,
            new_version=op.to_version,
            cutoff_epoch=op.to_version,
        )
        if from_key is not None and from_key.state not in TERMINAL_KEY_STATES and from_key.state != "RETIRED":
            from_key.state = "RETIRED"
        op.status = "FAILED_CLOSED"
        op.failure_info = "TARGET_KEY_TOMBSTONED_POST_COMMIT"
        op.recovery_notes = (
            "Post-commit target key has a revocation tombstone; kept tombstoned and refused reactivation."
        )
        with audit_write_lock():
            op.updated_at = utc_now()
            op.journal_hash = compute_journal_hash(op)
            append_audit_event(
                db,
                event_type="CRASH_RECOVERY_FAILED",
                event_category="RECOVERY",
                actor_id="system",
                action="recover_post_commit",
                target_type="rotation",
                target_id=op.operation_id,
                outcome="DENY",
                reason_code="TARGET_KEY_TOMBSTONED_POST_COMMIT",
                correlation_id=op.correlation_id,
                source_component="recovery_manager",
                payload={"previous_phase": prev_phase, "to_key_id": op.to_key_id},
                commit=False,
            )
            db.commit()
        db.refresh(op)
        return RecoveryOutcome(
            operation_id=op.operation_id,
            previous_phase=prev_phase,
            previous_status=prev_status,
            final_status=op.status,
            action_taken="FAIL_CLOSED_TOMBSTONE_PRECEDENCE",
            idempotent_noop=False,
            notes=op.recovery_notes,
        )

    # Safe roll-forward after commit
    if op.purpose == "vault_kek":
        _finalize_all_resources_at_retire(db, from_version=op.from_version, to_version=op.to_version)

    node_acks = commit_cutoff_on_nodes(
        db,
        operation_id=op.operation_id,
        new_version=op.to_version,
        cutoff_epoch=op.to_version,
    )
    if from_key is not None and not from_tombstoned and from_key.state not in TERMINAL_KEY_STATES and from_key.state != "RETIRED":
        from_key.state = "RETIRED"

    if to_key is not None and to_key.state in ("PREPARED", "ACTIVE_NEW"):
        validate_key_transition(to_key.state, "ACTIVE")
        to_key.state = "ACTIVE"
        if to_key.activated_at is None:
            to_key.activated_at = utc_now()

    with audit_write_lock():
        op.phase = "RETIRE"
        op.status = "RECOVERED_POST_COMMIT"
        op.node_acks_json = json.dumps(node_acks, separators=(",", ":"), sort_keys=True)
        op.recovery_notes = f"Rolled forward committed rotation from phase '{prev_phase}' to completed cutoff v{op.to_version}."
        op.updated_at = utc_now()
        op.journal_hash = compute_journal_hash(op)
        append_audit_event(
            db,
            event_type="CRASH_RECOVERY_EXECUTED",
            event_category="RECOVERY",
            actor_id="system",
            action="recover_post_commit",
            target_type="rotation",
            target_id=op.operation_id,
            outcome="ALLOW",
            reason_code="RECOVERED_POST_COMMIT",
            correlation_id=op.correlation_id,
            source_component="recovery_manager",
            payload={"previous_phase": prev_phase, "to_key_id": op.to_key_id, "to_version": op.to_version},
            commit=False,
        )
        db.commit()
    db.refresh(op)

    return RecoveryOutcome(
        operation_id=op.operation_id,
        previous_phase=prev_phase,
        previous_status=prev_status,
        final_status=op.status,
        action_taken="ROLLFORWARD_POST_COMMIT",
        idempotent_noop=False,
        notes=op.recovery_notes,
    )


def recover_rotations(
    db: Session,
    keystore: LocalEncryptedKeyStore,
    *,
    operation_id: str | None = None,
) -> list[RecoveryOutcome]:
    """Recover a specific rotation operation or all interrupted IN_PROGRESS operations."""
    if operation_id is not None:
        op = db.get(RotationOperation, operation_id)
        if op is None:
            return []
        return [recover_single_operation(db, keystore, op)]

    pending = list(
        db.scalars(
            select(RotationOperation)
            .where(RotationOperation.status == "IN_PROGRESS")
            .order_by(RotationOperation.created_at)
        ).all()
    )
    return [recover_single_operation(db, keystore, op) for op in pending]
