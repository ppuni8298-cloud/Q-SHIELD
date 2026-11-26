"""AES-256-GCM authenticated encryption with canonical AAD binding and nonce hygiene."""

from __future__ import annotations

import json
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AES_256_KEY_BYTES = 32
GCM_NONCE_BYTES = 12
VAULT_AAD_SCHEMA_VERSION = "qshield.vault.aad.v1"


class AEADError(ValueError):
    """Sanitized AEAD encryption/decryption error; never releases plaintext."""


def build_resource_aad_bytes(
    *,
    resource_id: str,
    owner_id: str,
    resource_type: str,
    key_version: int,
    timestamp_utc: str,
    algorithm: str = "AES-256-GCM",
    schema_version: str = VAULT_AAD_SCHEMA_VERSION,
    expires_at_utc: str | None = None,
) -> bytes:
    """Serialize resource metadata deterministically for AES-GCM associated authenticated data."""
    aad_obj: dict[str, str | int | None] = {
        "schema_version": schema_version,
        "resource_id": resource_id,
        "owner_id": owner_id,
        "resource_type": resource_type,
        "algorithm": algorithm,
        "key_version": int(key_version),
        "timestamp_utc": timestamp_utc,
        "expires_at_utc": expires_at_utc,
    }
    return json.dumps(aad_obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


class AES256GCMProvider:
    """Vetted AES-256-GCM wrapper enforcing 256-bit keys, 96-bit nonces, and non-reuse tracking."""

    ALGORITHM = "AES-256-GCM"

    def __init__(self) -> None:
        # Tracks nonces generated/used per key fingerprint in-process to prevent accidental reuse.
        self._seen_nonces: set[tuple[str, bytes]] = set()

    @staticmethod
    def generate_dek() -> bytes:
        """Generate a fresh random 256-bit AES key using cryptography's CSPRNG wrapper."""
        return AESGCM.generate_key(bit_length=256)

    @staticmethod
    def generate_nonce() -> bytes:
        """Generate a fresh random 96-bit nonce via OS CSPRNG."""
        return secrets.token_bytes(GCM_NONCE_BYTES)

    def encrypt(
        self,
        key: bytes,
        plaintext: bytes,
        associated_data: bytes,
        *,
        nonce: bytes | None = None,
    ) -> tuple[bytes, bytes]:
        """Encrypt plaintext with AES-256-GCM and return (nonce, ciphertext_with_tag)."""
        if not isinstance(key, bytes) or len(key) != AES_256_KEY_BYTES:
            raise AEADError("AES-256-GCM key must be 32 bytes.")
        if not isinstance(plaintext, bytes) or not isinstance(associated_data, bytes):
            raise AEADError("Plaintext and associated_data must be bytes.")

        chosen_nonce = nonce if nonce is not None else self.generate_nonce()
        if not isinstance(chosen_nonce, bytes) or len(chosen_nonce) != GCM_NONCE_BYTES:
            raise AEADError("AES-GCM nonce must be 12 bytes.")

        # Enforce strict no-nonce-reuse invariant per key.
        import hashlib

        key_tag = hashlib.sha256(key).hexdigest()
        pair = (key_tag, chosen_nonce)
        if pair in self._seen_nonces:
            raise AEADError("Nonce reuse under the same AES-256-GCM key is forbidden.")
        self._seen_nonces.add(pair)

        ciphertext_and_tag = AESGCM(key).encrypt(chosen_nonce, plaintext, associated_data)
        return chosen_nonce, ciphertext_and_tag

    @staticmethod
    def decrypt(
        key: bytes,
        nonce: bytes,
        ciphertext_and_tag: bytes,
        associated_data: bytes,
    ) -> bytes:
        """Authenticate tag and AAD before returning plaintext; fail closed on any error."""
        if not isinstance(key, bytes) or len(key) != AES_256_KEY_BYTES:
            raise AEADError("AES-256-GCM key must be 32 bytes.")
        if not isinstance(nonce, bytes) or len(nonce) != GCM_NONCE_BYTES:
            raise AEADError("AES-GCM nonce must be 12 bytes.")
        if not isinstance(ciphertext_and_tag, bytes) or len(ciphertext_and_tag) < 16:
            raise AEADError("Malformed AES-GCM ciphertext payload.")
        if not isinstance(associated_data, bytes):
            raise AEADError("associated_data must be bytes.")

        try:
            return AESGCM(key).decrypt(nonce, ciphertext_and_tag, associated_data)
        except InvalidTag as exc:
            raise AEADError("AEAD authentication tag or AAD verification failed.") from exc
