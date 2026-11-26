"""Reusable SHA-256 integrity digest and constant-time HMAC-SHA-256 helpers.

Note: SHA-256 is an unkeyed collision-resistant integrity digest, NOT message
authentication. Authentication requires a keyed primitive such as HMAC-SHA-256
or ML-DSA / AEAD.
"""

from __future__ import annotations

import hashlib
import hmac


def sha256_hex(data: bytes) -> str:
    """Compute lowercase hexadecimal SHA-256 digest (integrity check only, not auth)."""
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    return hashlib.sha256(data).hexdigest()


def hmac_sha256_hex(key: bytes, message: bytes) -> str:
    """Compute lowercase hexadecimal HMAC-SHA-256."""
    if not isinstance(key, bytes) or len(key) == 0:
        raise ValueError("HMAC key must be non-empty bytes")
    if not isinstance(message, bytes):
        raise TypeError("message must be bytes")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def verify_hmac_sha256_hex(key: bytes, message: bytes, candidate_hex: str) -> bool:
    """Verify a lowercase hexadecimal HMAC-SHA-256 digest in constant time."""
    if not isinstance(candidate_hex, str) or len(candidate_hex) != 64:
        return False
    if candidate_hex != candidate_hex.lower():
        return False
    expected = hmac_sha256_hex(key, message)
    return hmac.compare_digest(expected, candidate_hex)


def compute_protected_read_proof(shared_secret: bytes, challenge: str, stored_body: str) -> str:
    """Compute the exact Track 4 protected_read proof: HMAC-SHA256(ss, UTF8(challenge + body))."""
    if not isinstance(challenge, str) or not isinstance(stored_body, str):
        raise TypeError("challenge and stored_body must be str")
    return hmac_sha256_hex(shared_secret, (challenge + stored_body).encode("utf-8"))
