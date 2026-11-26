"""Cryptographic channel primitives for E2E messaging: ML-KEM-768, HKDF-SHA-256, AES-256-GCM AAD & HMAC tokens.

Uses strictly vetted Phase 3 cryptographic abstractions (zero hand-rolled algorithms).
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
from typing import Any

from backend.app.crypto.aead import AEADError, AES256GCMProvider, GCM_NONCE_BYTES
from backend.app.crypto.hmac_hash import hmac_sha256_hex, sha256_hex, verify_hmac_sha256_hex
from backend.app.crypto.kdf import derive_key_hkdf_sha256
from backend.app.crypto.mlkem import MLKEM768Provider

MESSAGE_AAD_SCHEMA_VERSION = "qshield.msg.aad.v1"
RESUMPTION_TOKEN_PREFIX = "qsr_v1"

# Process-wide AEAD provider enforcing unique nonces per key across requests.
_MESSAGING_AEAD = AES256GCMProvider()


class MessagingError(Exception):
    """Sanitized domain error for secure messaging; never exposes plaintext or secrets."""

    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


def build_message_aad_bytes(
    *,
    schema_version: str = MESSAGE_AAD_SCHEMA_VERSION,
    sender_id: str,
    recipient_id: str,
    message_id: str,
    session_id: str,
    session_generation: int,
    sequence: int,
    key_version: int,
    algorithm: str = "AES-256-GCM",
    nonce_b64: str,
    created_at_utc: str,
    expires_at_utc: str,
) -> bytes:
    """Serialize all authenticated message metadata deterministically for AES-GCM AAD."""
    aad_obj: dict[str, str | int] = {
        "algorithm": algorithm,
        "created_at_utc": created_at_utc,
        "expires_at_utc": expires_at_utc,
        "key_version": int(key_version),
        "message_id": message_id,
        "nonce_b64": nonce_b64,
        "recipient_id": recipient_id,
        "schema_version": schema_version,
        "sender_id": sender_id,
        "sequence": int(sequence),
        "session_generation": int(session_generation),
        "session_id": session_id,
    }
    return json.dumps(aad_obj, separators=(",", ":"), sort_keys=True).encode("utf-8")


def derive_session_generation_keys(
    *,
    shared_secret: bytes,
    session_id: str,
    initiator_id: str,
    recipient_id: str,
    key_version: int,
    generation: int,
) -> tuple[bytes, bytes]:
    """Derive purpose-separated chain key and resumption HMAC key via HKDF-SHA-256."""
    salt = f"qshield-msg-session-salt-v{key_version}-gen{generation}".encode("utf-8")
    base_ctx = {
        "session_id": session_id,
        "initiator_id": initiator_id,
        "recipient_id": recipient_id,
        "key_version": key_version,
        "generation": generation,
    }
    chain_key = derive_key_hkdf_sha256(
        shared_secret,
        salt=salt,
        purpose="messaging",
        context={**base_ctx, "role": "session_chain"},
        length=32,
    )
    resumption_mac_key = derive_key_hkdf_sha256(
        shared_secret,
        salt=salt,
        purpose="session",
        context={**base_ctx, "role": "resumption_mac"},
        length=32,
    )
    return chain_key, resumption_mac_key


def ratchet_message_key(
    *,
    chain_key: bytes,
    session_id: str,
    sender_id: str,
    recipient_id: str,
    key_version: int,
    generation: int,
    sequence: int,
) -> tuple[bytes, bytes]:
    """Advance symmetric HKDF ratchet: returns (per_message_aead_key, next_chain_key)."""
    salt = f"qshield-msg-ratchet-v{key_version}-g{generation}-s{sequence}".encode("utf-8")
    ctx = {
        "session_id": session_id,
        "sender_id": sender_id,
        "recipient_id": recipient_id,
        "key_version": key_version,
        "generation": generation,
        "sequence": sequence,
    }
    msg_key = derive_key_hkdf_sha256(
        chain_key,
        salt=salt,
        purpose="messaging",
        context={**ctx, "step": "message_aead"},
        length=32,
    )
    next_chain = derive_key_hkdf_sha256(
        chain_key,
        salt=salt,
        purpose="messaging",
        context={**ctx, "step": "chain_advance"},
        length=32,
    )
    return msg_key, next_chain


def run_ephemeral_mlkem768_exchange(recipient_public_key_b64: str | None = None) -> tuple[bytes, str, bytes]:
    """Execute ephemeral ML-KEM-768 encapsulation/decapsulation and return (shared_secret, kem_ct_b64, transcript_sha).

    If recipient_public_key_b64 is omitted, generates a fresh ephemeral ML-KEM-768 keypair,
    verifies decapsulation, and erases the ephemeral secret key immediately before returning.
    If recipient_public_key_b64 is supplied (external client/interop mode), validates & encapsulates
    against that public key cleanly without private key access.
    """
    if recipient_public_key_b64 is not None:
        try:
            pk = MLKEM768Provider.decode_public_key_b64(recipient_public_key_b64)
            kem_ct, ss = MLKEM768Provider.encapsulate(pk)
            ct_b64 = base64.b64encode(kem_ct).decode("ascii")
            return ss, ct_b64, sha256_hex(kem_ct).encode("utf-8")
        except ValueError as exc:
            raise MessagingError(400, "INVALID_KEM_PUBLIC_KEY", str(exc)) from exc

    epk, esk = MLKEM768Provider.generate_keypair()
    kem_ct, ss_sender = MLKEM768Provider.encapsulate(epk)
    ss_recipient = MLKEM768Provider.decapsulate(esk, kem_ct)
    ok = hmac.compare_digest(ss_sender, ss_recipient)
    # Explicitly clear ephemeral secret key references immediately after decapsulation
    del esk
    del ss_recipient
    if not ok:
        del ss_sender
        raise MessagingError(500, "KEM_EXCHANGE_MISMATCH", "ML-KEM-768 shared secret verification failed.")
    ct_b64 = base64.b64encode(kem_ct).decode("ascii")
    return ss_sender, ct_b64, sha256_hex(kem_ct).encode("utf-8")


def create_resumption_token(
    *,
    mac_key: bytes,
    session_id: str,
    initiator_id: str,
    recipient_id: str,
    initiator_device_id: str,
    recipient_device_id: str,
    generation: int,
    key_version: int,
    nonce_hex: str,
    issued_at_utc: str,
    expires_at_utc: str,
) -> str:
    """Construct HMAC-SHA-256 authenticated, peer-bound session resumption token."""
    payload = {
        "session_id": session_id,
        "initiator_id": initiator_id,
        "recipient_id": recipient_id,
        "initiator_device_id": initiator_device_id,
        "recipient_device_id": recipient_device_id,
        "generation": generation,
        "key_version": key_version,
        "nonce": nonce_hex,
        "issued_at_utc": issued_at_utc,
        "expires_at_utc": expires_at_utc,
    }
    raw_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(raw_bytes).decode("ascii")
    sig_hex = hmac_sha256_hex(mac_key, raw_bytes)
    return f"{RESUMPTION_TOKEN_PREFIX}.{payload_b64}.{sig_hex}"


def parse_and_verify_resumption_token(mac_key: bytes, token: str) -> dict[str, Any]:
    """Validate structure and constant-time HMAC-SHA-256 signature of a resumption token."""
    if not isinstance(token, str) or not token.startswith(f"{RESUMPTION_TOKEN_PREFIX}."):
        raise MessagingError(403, "INVALID_RESUMPTION_TOKEN", "Resumption token prefix or format is invalid.")
    parts = token.split(".")
    if len(parts) != 3:
        raise MessagingError(403, "INVALID_RESUMPTION_TOKEN", "Malformed resumption token structure.")
    _, payload_b64, sig_hex = parts
    try:
        raw_bytes = base64.urlsafe_b64decode(payload_b64.encode("ascii"))
        payload = json.loads(raw_bytes.decode("utf-8"))
    except (ValueError, binascii.Error, UnicodeDecodeError) as exc:
        raise MessagingError(403, "INVALID_RESUMPTION_TOKEN", "Resumption token payload cannot be decoded.") from exc
    if not verify_hmac_sha256_hex(mac_key, raw_bytes, sig_hex):
        raise MessagingError(403, "RESUMPTION_TOKEN_HMAC_INVALID", "Resumption token HMAC verification failed.")
    if not isinstance(payload, dict):
        raise MessagingError(403, "INVALID_RESUMPTION_TOKEN", "Resumption token payload must be a JSON object.")
    return payload


def encrypt_message_envelope(
    *,
    message_key: bytes,
    plaintext: bytes,
    message_id: str,
    session_id: str,
    session_generation: int,
    sequence: int,
    sender_id: str,
    recipient_id: str,
    key_version: int,
    created_at_utc: str,
    expires_at_utc: str,
    explicit_nonce: bytes | None = None,
) -> tuple[dict[str, Any], str]:
    """Encrypt message payload with AES-256-GCM binding all required AAD metadata fields."""
    nonce = explicit_nonce if explicit_nonce is not None else AES256GCMProvider.generate_nonce()
    if len(nonce) != GCM_NONCE_BYTES:
        raise MessagingError(400, "INVALID_NONCE", "AES-256-GCM nonce must be 12 bytes.")
    nonce_b64 = base64.b64encode(nonce).decode("ascii")
    aad_bytes = build_message_aad_bytes(
        sender_id=sender_id,
        recipient_id=recipient_id,
        message_id=message_id,
        session_id=session_id,
        session_generation=session_generation,
        sequence=sequence,
        key_version=key_version,
        algorithm="AES-256-GCM",
        nonce_b64=nonce_b64,
        created_at_utc=created_at_utc,
        expires_at_utc=expires_at_utc,
    )
    try:
        used_nonce, ct_and_tag = _MESSAGING_AEAD.encrypt(message_key, plaintext, aad_bytes, nonce=nonce)
    except AEADError as exc:
        raise MessagingError(409, "NONCE_OR_AEAD_ERROR", str(exc)) from exc
    if used_nonce != nonce:
        raise MessagingError(500, "NONCE_MISMATCH", "Internal nonce generation error.")

    envelope = {
        "schema_version": MESSAGE_AAD_SCHEMA_VERSION,
        "message_id": message_id,
        "session_id": session_id,
        "session_generation": session_generation,
        "sequence": sequence,
        "sender_id": sender_id,
        "recipient_id": recipient_id,
        "key_version": key_version,
        "algorithm": "AES-256-GCM",
        "nonce_b64": nonce_b64,
        "ciphertext_b64": base64.b64encode(ct_and_tag).decode("ascii"),
        "created_at_utc": created_at_utc,
        "expires_at_utc": expires_at_utc,
        "aad_sha256": sha256_hex(aad_bytes),
    }
    return envelope, nonce_b64


def verify_and_decrypt_message_envelope(
    *,
    message_key: bytes,
    envelope: dict[str, Any],
    expected_sender_id: str,
    expected_recipient_id: str,
    expected_session_id: str,
    expected_key_version: int,
) -> bytes:
    """Validate authenticated envelope bindings BEFORE AEAD decryption; fail closed with zero plaintext on error."""
    if envelope.get("schema_version") != MESSAGE_AAD_SCHEMA_VERSION:
        raise MessagingError(400, "UNSUPPORTED_ENVELOPE_SCHEMA", "Unsupported message envelope schema version.")
    if envelope.get("algorithm") != "AES-256-GCM":
        raise MessagingError(400, "UNSUPPORTED_ALGORITHM", "Message algorithm must be AES-256-GCM.")
    if envelope.get("sender_id") != expected_sender_id:
        raise MessagingError(403, "DENY_SENDER_MISMATCH", "Envelope sender_id does not match authenticated expected sender.")
    if envelope.get("recipient_id") != expected_recipient_id:
        raise MessagingError(403, "DENY_RECIPIENT_MISMATCH", "Envelope recipient_id does not match authenticated recipient.")
    if envelope.get("session_id") != expected_session_id:
        raise MessagingError(403, "DENY_SESSION_MISMATCH", "Envelope session_id does not match active session.")
    if int(envelope.get("key_version", -1)) != int(expected_key_version):
        raise MessagingError(403, "DENY_KEY_VERSION_MISMATCH", "Envelope key_version does not match session key version.")

    try:
        nonce = base64.b64decode(str(envelope["nonce_b64"]), validate=True)
        ct_and_tag = base64.b64decode(str(envelope["ciphertext_b64"]), validate=True)
        aad_bytes = build_message_aad_bytes(
            schema_version=str(envelope["schema_version"]),
            sender_id=expected_sender_id,
            recipient_id=expected_recipient_id,
            message_id=str(envelope["message_id"]),
            session_id=expected_session_id,
            session_generation=int(envelope["session_generation"]),
            sequence=int(envelope["sequence"]),
            key_version=int(expected_key_version),
            algorithm=str(envelope["algorithm"]),
            nonce_b64=str(envelope["nonce_b64"]),
            created_at_utc=str(envelope["created_at_utc"]),
            expires_at_utc=str(envelope["expires_at_utc"]),
        )
    except (KeyError, ValueError, TypeError, binascii.Error) as exc:
        raise MessagingError(400, "MALFORMED_ENVELOPE", "Encrypted message envelope fields are malformed.") from exc

    if sha256_hex(aad_bytes) != envelope.get("aad_sha256"):
        raise MessagingError(403, "AAD_METADATA_MISMATCH", "Message AAD metadata digest does not match authenticated header.")

    try:
        return AES256GCMProvider.decrypt(message_key, nonce, ct_and_tag, aad_bytes)
    except AEADError as exc:
        raise MessagingError(403, "AEAD_INTEGRITY_FAILED", "Authenticated decryption failed; no plaintext released.") from exc
