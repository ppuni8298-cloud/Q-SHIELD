"""Opaque token generation, SHA-256 hashing, and UTC datetime helpers."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import secrets


def generate_opaque_token() -> str:
    """Generate a high-entropy opaque bearer token (never stored in plaintext)."""
    return secrets.token_urlsafe(32)


def hash_token(raw_token: str) -> str:
    """Hash a bearer token with SHA-256 for storage and lookup."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def verify_token_hash(raw_token: str, expected_hash: str) -> bool:
    """Compare token hash in constant time."""
    return hmac.compare_digest(hash_token(raw_token), expected_hash)


def ensure_utc(dt: datetime) -> datetime:
    """Normalize SQLite-loaded datetimes to timezone-aware UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
