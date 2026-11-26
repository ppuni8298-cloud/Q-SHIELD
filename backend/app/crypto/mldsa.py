"""ML-DSA-65 post-quantum digital signature provider backed by pqcrypto==0.4.0."""

from __future__ import annotations

from pqcrypto.sign import ml_dsa_65


class MLDSAError(ValueError):
    """Sanitized ML-DSA signature error that never exposes secret keys."""


class MLDSA65Provider:
    """Wrapper around pqcrypto.sign.ml_dsa_65 with strict length validation."""

    ALGORITHM: str = ml_dsa_65.ALGORITHM
    PUBLIC_KEY_SIZE: int = ml_dsa_65.PUBLIC_KEY_SIZE
    SECRET_KEY_SIZE: int = ml_dsa_65.SECRET_KEY_SIZE
    MAX_SIGNATURE_SIZE: int = ml_dsa_65.SIGNATURE_SIZE

    @classmethod
    def generate_keypair(cls) -> tuple[bytes, bytes]:
        """Generate a raw ML-DSA-65 (public_key, secret_key) pair."""
        return ml_dsa_65.generate_keypair()

    @classmethod
    def sign(cls, secret_key: bytes, message: bytes) -> bytes:
        """Sign message bytes with a validated ML-DSA-65 secret key."""
        if not isinstance(secret_key, bytes) or len(secret_key) != cls.SECRET_KEY_SIZE:
            raise MLDSAError(f"ML-DSA-65 secret key must be {cls.SECRET_KEY_SIZE} bytes.")
        if not isinstance(message, bytes):
            raise MLDSAError("Message to sign must be bytes.")
        return ml_dsa_65.sign(secret_key, message)

    @classmethod
    def verify(cls, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify an ML-DSA-65 signature; return False on invalid signature/length."""
        if not isinstance(public_key, bytes) or len(public_key) != cls.PUBLIC_KEY_SIZE:
            raise MLDSAError(f"ML-DSA-65 public key must be {cls.PUBLIC_KEY_SIZE} bytes.")
        if not isinstance(message, bytes) or not isinstance(signature, bytes):
            return False
        if len(signature) == 0 or len(signature) > cls.MAX_SIGNATURE_SIZE:
            return False
        return bool(ml_dsa_65.verify(public_key, message, signature))
