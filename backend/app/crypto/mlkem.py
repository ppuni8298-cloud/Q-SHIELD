"""ML-KEM-768 post-quantum KEM provider backed by pqcrypto==0.4.0."""

from __future__ import annotations

import base64
import binascii

from pqcrypto.kem import ml_kem_768


class MLKEMError(ValueError):
    """Sanitized ML-KEM error that never exposes key material or shared secrets."""


class MLKEM768Provider:
    """Wrapper around pqcrypto.kem.ml_kem_768 with strict length and Base64 validation."""

    ALGORITHM: str = ml_kem_768.ALGORITHM
    PUBLIC_KEY_SIZE: int = ml_kem_768.PUBLIC_KEY_SIZE
    SECRET_KEY_SIZE: int = ml_kem_768.SECRET_KEY_SIZE
    CIPHERTEXT_SIZE: int = ml_kem_768.CIPHERTEXT_SIZE
    SHARED_SECRET_SIZE: int = ml_kem_768.PLAINTEXT_SIZE

    @classmethod
    def generate_keypair(cls) -> tuple[bytes, bytes]:
        """Generate a raw ML-KEM-768 (public_key, secret_key) pair."""
        return ml_kem_768.generate_keypair()

    @classmethod
    def decode_public_key_b64(cls, public_key_b64: str) -> bytes:
        """Decode standard Base64 and validate exact ML-KEM-768 public key byte size."""
        if not isinstance(public_key_b64, str) or not public_key_b64 or not public_key_b64.isascii():
            raise MLKEMError("Public key must be a non-empty ASCII Base64 string.")
        try:
            raw = base64.b64decode(public_key_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise MLKEMError("Malformed standard Base64 public key.") from exc
        if len(raw) != cls.PUBLIC_KEY_SIZE:
            raise MLKEMError(f"ML-KEM-768 public key must be exactly {cls.PUBLIC_KEY_SIZE} bytes.")
        return raw

    @classmethod
    def encapsulate(cls, public_key: bytes) -> tuple[bytes, bytes]:
        """Encapsulate a fresh shared secret against a validated ML-KEM-768 public key."""
        if not isinstance(public_key, bytes) or len(public_key) != cls.PUBLIC_KEY_SIZE:
            raise MLKEMError(f"ML-KEM-768 public key must be {cls.PUBLIC_KEY_SIZE} bytes.")
        ciphertext, shared_secret = ml_kem_768.encrypt(public_key)
        return ciphertext, shared_secret

    @classmethod
    def decapsulate(cls, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate a shared secret using secret_key and ciphertext."""
        if not isinstance(secret_key, bytes) or len(secret_key) != cls.SECRET_KEY_SIZE:
            raise MLKEMError(f"ML-KEM-768 secret key must be {cls.SECRET_KEY_SIZE} bytes.")
        if not isinstance(ciphertext, bytes) or len(ciphertext) != cls.CIPHERTEXT_SIZE:
            raise MLKEMError(f"ML-KEM-768 ciphertext must be {cls.CIPHERTEXT_SIZE} bytes.")
        return ml_kem_768.decrypt(secret_key, ciphertext)
