"""Extensible interfaces for Policy Step 8 (Key Validity) and Step 9 (Incidents).

Phase 2 uses SQLite metadata checks through these clean interfaces without
prematurely implementing Phase 3 cryptographic key operations or Phase 4/7
distributed node / incident detectors.
"""

from __future__ import annotations

from typing import Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.db.models import InFlightTransfer, Incident, KeyMetadata, RotationOperation


class KeyValidityChecker(Protocol):
    """Interface for Policy Step 8 key-version validity checks."""

    def is_key_version_valid(self, db: Session, key_version: int) -> tuple[bool, str, str]:
        """Return (is_valid, reason_code, detail)."""


class IncidentDenialChecker(Protocol):
    """Interface for Policy Step 9 active incident/policy denial checks."""

    def check_blocking_incident(
        self,
        db: Session,
        *,
        actor_id: str,
        device_id: str,
        resource_id: str,
    ) -> tuple[bool, str, str]:
        """Return (is_allowed, reason_code, detail)."""


class MetadataKeyValidityChecker:
    """Phase 2 implementation reading key_metadata state without Phase 3 crypto logic."""

    def is_key_version_valid(self, db: Session, key_version: int) -> tuple[bool, str, str]:
        records = list(
            db.scalars(select(KeyMetadata).where(KeyMetadata.version == key_version)).all()
        )
        if not records:
            return False, "DENY_KEY_NOT_FOUND", f"No key metadata registered for version {key_version}."
        for rec in records:
            if rec.state in ("REVOKED", "COMPROMISED"):
                return False, "DENY_KEY_REVOKED", f"Key {rec.key_id} (v{key_version}) is {rec.state}."
        if any(rec.state in ("ACTIVE", "ACTIVE_NEW") for rec in records):
            return True, "OK_KEY_ACTIVE", f"Key version {key_version} is ACTIVE."
        for rec in records:
            if rec.state == "ROTATING":
                rot = db.scalar(
                    select(RotationOperation).where(
                        RotationOperation.from_key_id == rec.key_id,
                        RotationOperation.status == "IN_PROGRESS",
                    )
                )
                if rot is not None and not rot.committed:
                    return True, "OK_KEY_ACTIVE", f"Key version {key_version} is pre-commit ROTATING."
                if (
                    rot is not None
                    and rot.committed
                    and rot.grace_policy == "CONTROLLED_IN_FLIGHT_ONLY"
                    and db.scalar(
                        select(InFlightTransfer.transfer_id).where(
                            InFlightTransfer.key_version == key_version,
                            InFlightTransfer.state == "STARTED",
                            InFlightTransfer.allow_post_cutoff.is_(True),
                        )
                    )
                    is not None
                ):
                    return True, "OK_KEY_ACTIVE", f"Key version {key_version} allowed for pre-cutoff in-flight transfer."
        states = ",".join(sorted({rec.state for rec in records}))
        return False, "DENY_KEY_INACTIVE", f"Key version {key_version} is not ACTIVE (states: {states})."


class TableIncidentDenialChecker:
    """Phase 2 implementation checking active blocking incidents targeting actor/device/resource."""

    def check_blocking_incident(
        self,
        db: Session,
        *,
        actor_id: str,
        device_id: str,
        resource_id: str,
    ) -> tuple[bool, str, str]:
        targets = (actor_id, device_id, resource_id)
        blocking = db.scalar(
            select(Incident).where(
                Incident.actor_or_target.in_(targets),
                Incident.state.in_(("OPEN", "CONTAINING")),
                Incident.blocks_access.is_(True),
            )
        )
        if blocking is not None:
            return (
                False,
                "DENY_ACTIVE_INCIDENT",
                f"Blocked by active incident {blocking.id} on target '{blocking.actor_or_target}'.",
            )
        return True, "OK_NO_BLOCKING_INCIDENT", "No active blocking incident for actor, device, or resource."
