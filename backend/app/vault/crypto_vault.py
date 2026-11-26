"""Envelope encryption and policy-gated decryption for protected resources.

Workflow:
- Encrypt: generate random 256-bit DEK -> encrypt body with AES-256-GCM + unique
  96-bit nonce + canonical metadata AAD -> derive key-wrapping key via HKDF-SHA-256
  from active KEK in LocalEncryptedKeyStore -> wrap DEK with AES-256-GCM -> persist
  non-secret EncryptedObject row + wrapped DEK in LocalEncryptedKeyStore.
- Decrypt: run Phase 2 10-step ZeroTrustPolicyEngine -> verify key metadata active ->
  unwrap DEK from LocalEncryptedKeyStore -> verify AES-256-GCM tag and AAD -> release
  plaintext ONLY after authentication succeeds.
"""

from __future__ import annotations

import base64
import binascii
import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.audit.ledger import append_audit_event, audit_write_lock, record_audit_safe
from backend.app.auth.dependencies import AuthContext
from backend.app.crypto.aead import AEADError, AES256GCMProvider, build_resource_aad_bytes
from backend.app.crypto.hmac_hash import sha256_hex
from backend.app.crypto.kdf import derive_key_hkdf_sha256
from backend.app.crypto.keystore import KeyStoreError, LocalEncryptedKeyStore
from backend.app.db.models import EncryptedObject, Resource, utc_now
from backend.app.keys.lifecycle import KeyLifecycleError
from backend.app.keys.service import get_active_kek_metadata
from backend.app.policy.engine import ZeroTrustPolicyEngine
from backend.app.schemas.policy import PolicyEvalRequest
from backend.app.vault.service import VaultServiceError, get_resource_or_raise


class CryptoVaultError(Exception):
    """Sanitized vault cryptography error; never contains plaintext or secret bytes."""

    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


_aead = AES256GCMProvider()
_policy_engine = ZeroTrustPolicyEngine()


def _dek_keystore_id(resource_id: str, version: int) -> str:
    return f"wrapped-dek:{resource_id}:v{version}"


def _derive_kek_wrapping_key(kek_bytes: bytes, *, resource_id: str, key_version: int) -> bytes:
    return derive_key_hkdf_sha256(
        kek_bytes,
        salt=f"qshield-dek-wrap-salt-v{key_version}".encode("utf-8"),
        purpose="vault_dek",
        context={"resource_id": resource_id, "key_version": key_version},
        length=32,
    )


def encrypt_resource_content(
    db: Session,
    keystore: LocalEncryptedKeyStore,
    *,
    ctx: AuthContext,
    resource_id: str,
    plaintext: str,
    expires_at_utc: str | None = None,
) -> EncryptedObject:
    """Authorize caller, generate per-resource DEK, encrypt with AES-256-GCM + AAD, and wrap DEK."""
    # Verify resource exists and caller owns it (or is admin).
    try:
        resource = get_resource_or_raise(db, resource_id)
    except VaultServiceError as exc:
        raise CryptoVaultError(exc.status_code, exc.code, exc.message) from None

    if resource.owner_id != ctx.user.id and ctx.user.role != "admin":
        raise CryptoVaultError(403, "FORBIDDEN_RESOURCE_ENCRYPT", "Only resource owner or admin may encrypt.")

    if resource.state != "ACTIVE":
        raise CryptoVaultError(409, "RESOURCE_DISABLED", "Cannot encrypt a disabled resource.")

    try:
        kek_meta = get_active_kek_metadata(db, resource.key_version)
        kek_bytes = keystore.get_secret_bytes(kek_meta.key_id, expected_purpose="vault_kek")
    except (KeyLifecycleError, KeyStoreError) as exc:
        code = getattr(exc, "code", "KEYSTORE_UNAVAILABLE")
        status = getattr(exc, "status_code", 503)
        raise CryptoVaultError(status, code, "Active encryption key is unavailable or revoked.") from None

    timestamp_iso = utc_now().isoformat()
    aad_bytes = build_resource_aad_bytes(
        resource_id=resource.id,
        owner_id=resource.owner_id,
        resource_type=resource.type,
        key_version=resource.key_version,
        timestamp_utc=timestamp_iso,
        expires_at_utc=expires_at_utc,
    )

    dek = _aead.generate_dek()
    content_nonce, content_ct = _aead.encrypt(dek, plaintext.encode("utf-8"), aad_bytes)

    wrap_key = _derive_kek_wrapping_key(kek_bytes, resource_id=resource.id, key_version=resource.key_version)
    wrap_nonce, wrapped_dek_ct = _aead.encrypt(wrap_key, dek, aad_bytes)
    wrapped_dek_blob = json.dumps(
        {
            "kek_id": kek_meta.key_id,
            "key_version": resource.key_version,
            "wrap_nonce_b64": base64.b64encode(wrap_nonce).decode("ascii"),
            "wrapped_dek_b64": base64.b64encode(wrapped_dek_ct).decode("ascii"),
        },
        separators=(",", ":"),
    ).encode("utf-8")

    try:
        keystore.put_secret_bytes(
            _dek_keystore_id(resource.id, resource.key_version),
            purpose="vault_dek",
            secret_bytes=wrapped_dek_blob,
        )
    except KeyStoreError:
        raise CryptoVaultError(503, "KEYSTORE_WRITE_FAILED", "Unable to persist wrapped resource DEK.") from None

    ct_b64 = base64.b64encode(content_ct).decode("ascii")
    nonce_b64 = base64.b64encode(content_nonce).decode("ascii")
    envelope_meta = {
        "schema_version": "qshield.vault.aad.v1",
        "algorithm": "AES-256-GCM",
        "resource_id": resource.id,
        "owner_id": resource.owner_id,
        "resource_type": resource.type,
        "key_version": resource.key_version,
        "kek_id": kek_meta.key_id,
        "timestamp_utc": timestamp_iso,
        "expires_at_utc": expires_at_utc,
    }
    envelope_json = json.dumps(envelope_meta, separators=(",", ":"), sort_keys=True)
    integrity = sha256_hex((nonce_b64 + ":" + ct_b64 + ":" + envelope_json).encode("utf-8"))

    existing = db.scalar(
        select(EncryptedObject).where(
            EncryptedObject.resource_id == resource.id,
            EncryptedObject.version == resource.key_version,
        )
    )
    if existing is not None:
        existing.ciphertext_ref = ct_b64
        existing.nonce = nonce_b64
        existing.aead_envelope = envelope_json
        existing.integrity = integrity
        enc_obj = existing
    else:
        enc_obj = EncryptedObject(
            resource_id=resource.id,
            ciphertext_ref=ct_b64,
            nonce=nonce_b64,
            aead_envelope=envelope_json,
            version=resource.key_version,
            integrity=integrity,
        )
        db.add(enc_obj)

    with audit_write_lock():
        if existing is None:
            db.flush()
        append_audit_event(
            db,
            event_type="RESOURCE_ENCRYPTED",
            event_category="CRYPTO",
            actor_id=ctx.user.id,
            action="encrypt_resource",
            target_type="resource",
            target_id=resource.id,
            outcome="ALLOW",
            reason_code="RESOURCE_ENCRYPTED_AES256GCM",
            correlation_id=ctx.correlation_id,
            source_component="crypto_vault",
            payload={"key_version": resource.key_version, "kek_id": kek_meta.key_id, "algorithm": "AES-256-GCM"},
            commit=False,
        )
        db.commit()
    db.refresh(enc_obj)
    return enc_obj


def get_encrypted_metadata_or_raise(db: Session, resource: Resource) -> EncryptedObject:
    enc_obj = db.scalar(
        select(EncryptedObject)
        .where(EncryptedObject.resource_id == resource.id, EncryptedObject.version == resource.key_version)
        .order_by(EncryptedObject.id.desc())
    )
    if enc_obj is None:
        raise CryptoVaultError(404, "ENCRYPTED_OBJECT_NOT_FOUND", "No encrypted payload found for resource.")
    return enc_obj


def decrypt_resource_content(
    db: Session,
    keystore: LocalEncryptedKeyStore,
    *,
    ctx: AuthContext,
    resource_id: str,
) -> tuple[str, EncryptedObject, str]:
    """Run 10-step zero-trust policy, unwrap DEK, verify AEAD tag+AAD, and release plaintext only on success."""
    decision = _policy_engine.evaluate(
        db,
        PolicyEvalRequest(
            actor_id=ctx.user.id,
            session_id=ctx.session.id,
            device_id=ctx.device.id,
            resource_id=resource_id,
            action="read",
        ),
        correlation_id=ctx.correlation_id,
    )
    if decision.decision != "ALLOW":
        raise CryptoVaultError(403, decision.reason_code, "Access denied by zero-trust policy.")

    try:
        resource = get_resource_or_raise(db, resource_id)
    except VaultServiceError as exc:
        raise CryptoVaultError(exc.status_code, exc.code, exc.message) from None

    enc_obj = get_encrypted_metadata_or_raise(db, resource)

    try:
        kek_meta = get_active_kek_metadata(db, resource.key_version)
        envelope = json.loads(enc_obj.aead_envelope)
        if (
            envelope.get("resource_id") != resource.id
            or envelope.get("owner_id") != resource.owner_id
            or envelope.get("resource_type") != resource.type
            or int(envelope.get("key_version", -1)) != resource.key_version
        ):
            raise CryptoVaultError(409, "METADATA_MISMATCH", "Encrypted envelope metadata mismatches resource record.")

        expected_integrity = sha256_hex(
            (enc_obj.nonce + ":" + enc_obj.ciphertext_ref + ":" + enc_obj.aead_envelope).encode("utf-8")
        )
        if expected_integrity != enc_obj.integrity:
            raise CryptoVaultError(409, "ENVELOPE_INTEGRITY_FAILED", "Encrypted envelope integrity digest mismatch.")

        aad_bytes = build_resource_aad_bytes(
            resource_id=str(envelope["resource_id"]),
            owner_id=str(envelope["owner_id"]),
            resource_type=str(envelope["resource_type"]),
            key_version=int(envelope["key_version"]),
            timestamp_utc=str(envelope["timestamp_utc"]),
            algorithm=str(envelope["algorithm"]),
            schema_version=str(envelope["schema_version"]),
            expires_at_utc=envelope.get("expires_at_utc"),
        )

        kek_bytes = keystore.get_secret_bytes(kek_meta.key_id, expected_purpose="vault_kek")
        wrapped_blob = json.loads(
            keystore.get_secret_bytes(
                _dek_keystore_id(resource.id, resource.key_version),
                expected_purpose="vault_dek",
            ).decode("utf-8")
        )
        wrap_nonce = base64.b64decode(wrapped_blob["wrap_nonce_b64"], validate=True)
        wrapped_dek = base64.b64decode(wrapped_blob["wrapped_dek_b64"], validate=True)
        wrap_key = _derive_kek_wrapping_key(kek_bytes, resource_id=resource.id, key_version=resource.key_version)
        dek = _aead.decrypt(wrap_key, wrap_nonce, wrapped_dek, aad_bytes)

        content_nonce = base64.b64decode(enc_obj.nonce, validate=True)
        content_ct = base64.b64decode(enc_obj.ciphertext_ref, validate=True)
        plaintext_bytes = _aead.decrypt(dek, content_nonce, content_ct, aad_bytes)
        plaintext = plaintext_bytes.decode("utf-8")
    except CryptoVaultError as exc:
        record_audit_safe(
            db,
            event_type="CRYPTO_VERIFICATION_FAILED",
            event_category="PROTECTED_ACCESS",
            actor_id=ctx.user.id,
            action="decrypt_resource",
            target_type="resource",
            target_id=resource_id,
            outcome="DENY",
            reason_code=exc.code,
            correlation_id=ctx.correlation_id,
            source_component="crypto_vault",
            commit=True,
        )
        raise
    except (KeyLifecycleError, KeyStoreError, AEADError, ValueError, KeyError, binascii.Error, UnicodeDecodeError):
        record_audit_safe(
            db,
            event_type="CRYPTO_VERIFICATION_FAILED",
            event_category="PROTECTED_ACCESS",
            actor_id=ctx.user.id,
            action="decrypt_resource",
            target_type="resource",
            target_id=resource_id,
            outcome="DENY",
            reason_code="DECRYPTION_AUTHENTICATION_FAILED",
            correlation_id=ctx.correlation_id,
            source_component="crypto_vault",
            commit=True,
        )
        raise CryptoVaultError(
            409,
            "DECRYPTION_AUTHENTICATION_FAILED",
            "Cryptographic verification failed; no plaintext released.",
        ) from None

    append_audit_event(
        db,
        event_type="RESOURCE_DECRYPTED",
        event_category="PROTECTED_ACCESS",
        actor_id=ctx.user.id,
        action="decrypt_resource",
        target_type="resource",
        target_id=resource_id,
        outcome="ALLOW",
        reason_code="DECRYPTION_AUTHORIZED",
        correlation_id=ctx.correlation_id,
        source_component="crypto_vault",
        payload={"key_version": resource.key_version, "request_id": decision.request_id},
        commit=True,
    )
    return plaintext, enc_obj, decision.request_id
