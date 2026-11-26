"""Protected-resource metadata lookup and creation (Phase 2 — prior to Phase 3 AEAD vault)."""

from __future__ import annotations

import json

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.db.models import Resource, User
from backend.app.schemas.vault import ResourceCreateRequest


class VaultServiceError(Exception):
    """Domain error for Phase 2 protected-resource metadata operations."""

    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


def parse_resource_metadata(resource: Resource) -> dict[str, str]:
    try:
        parsed = json.loads(resource.metadata_json)
        if isinstance(parsed, dict):
            return {str(k): str(v) for k, v in parsed.items()}
    except ValueError:
        pass
    return {}


def list_resources(
    db: Session,
    *,
    owner_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[Resource], int]:
    query = select(Resource)
    count_q = select(func.count()).select_from(Resource)
    if owner_id is not None:
        query = query.where(Resource.owner_id == owner_id)
        count_q = count_q.where(Resource.owner_id == owner_id)
    total = db.scalar(count_q) or 0
    items = list(db.scalars(query.order_by(Resource.id).limit(limit).offset(offset)).all())
    return items, int(total)


def get_resource_or_raise(db: Session, resource_id: str) -> Resource:
    resource = db.get(Resource, resource_id)
    if resource is None:
        raise VaultServiceError(404, "RESOURCE_NOT_FOUND", "Requested resource does not exist.")
    return resource


def create_resource(db: Session, req: ResourceCreateRequest, *, acting_user: User) -> Resource:
    if acting_user.role == "owner" and req.owner_id != acting_user.id:
        raise VaultServiceError(403, "FORBIDDEN_CROSS_OWNER_CREATE", "Owners may only create resources for themselves.")
    owner = db.get(User, req.owner_id)
    if owner is None or not owner.enabled:
        raise VaultServiceError(404, "OWNER_INVALID", "Specified owner does not exist or is disabled.")
    if db.get(Resource, req.id) is not None:
        raise VaultServiceError(409, "RESOURCE_ALREADY_EXISTS", "Resource ID already exists.")

    res = Resource(
        id=req.id,
        owner_id=req.owner_id,
        type=req.type,
        metadata_json=json.dumps(req.metadata),
        key_version=req.key_version,
        state="ACTIVE",
    )
    db.add(res)
    db.commit()
    db.refresh(res)
    return res
