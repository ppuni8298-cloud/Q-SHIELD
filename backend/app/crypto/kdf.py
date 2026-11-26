"""HKDF-SHA-256 key derivation with strict purpose-separated context binding."""

from __future__ import annotations

import json
from typing import Final

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ALLOWED_KEY_PURPOSES: Final[frozenset[str]] = frozenset(
    {
        "kem",
        "signing",
        "vault_dek",
        "vault_kek",
        "session",
        "audit",
        "keystore_master",
        "messaging",
    }
)


class KDFError(ValueError):
    """Sanitized key derivation error without exposing key material."""


def build_hkdf_info(purpose: str, context: dict[str, str | int] | None = None) -> bytes:
    """Build deterministic UTF-8 info bytes binding purpose label and structured context."""
    if purpose not in ALLOWED_KEY_PURPOSES:
        raise KDFError(f"Unsupported key derivation purpose: {purpose}")
    normalized_ctx = {str(k): str(v) for k, v in sorted((context or {}).items())}
    payload = json.dumps(
        {"domain": "qshield-hkdf-v1", "purpose": purpose, "context": normalized_ctx},
        separators=(",", ":"),
        sort_keys=True,
    )
    return payload.encode("utf-8")


def derive_key_hkdf_sha256(
    input_key_material: bytes,
    *,
    salt: bytes,
    purpose: str,
    context: dict[str, str | int] | None = None,
    length: int = 32,
) -> bytes:
    """Derive a purpose-separated key using HKDF-SHA-256 (cryptography library)."""
    if not isinstance(input_key_material, bytes) or len(input_key_material) == 0:
        raise KDFError("Input keying material must be non-empty bytes.")
    if not isinstance(salt, bytes):
        raise KDFError("Salt must be bytes.")
    if length < 16 or length > 64:
        raise KDFError("Derived key length must be between 16 and 64 bytes.")

    info = build_hkdf_info(purpose, context)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt if len(salt) > 0 else None,
        info=info,
    )
    return hkdf.derive(input_key_material)
