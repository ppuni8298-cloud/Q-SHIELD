"""Independent tests for ML-KEM-768, ML-DSA-65, AES-256-GCM, HKDF, HMAC, KATs, and LocalEncryptedKeyStore."""

from __future__ import annotations

import base64
import hashlib
import hmac
from pathlib import Path

from pqcrypto.kem import ml_kem_768
import pytest

from backend.app.crypto.aead import AEADError, AES256GCMProvider, build_resource_aad_bytes
from backend.app.crypto.hmac_hash import (
    compute_protected_read_proof,
    hmac_sha256_hex,
    sha256_hex,
    verify_hmac_sha256_hex,
)
from backend.app.crypto.kdf import KDFError, derive_key_hkdf_sha256
from backend.app.crypto.keystore import KeyStoreError, LocalEncryptedKeyStore
from backend.app.crypto.mlkem import MLKEM768Provider, MLKEMError
from backend.app.crypto.mldsa import MLDSA65Provider, MLDSAError
from backend.app.crypto.selftest import run_crypto_selftest


def test_mlkem768_interoperability_and_error_handling() -> None:
    pk, sk = MLKEM768Provider.generate_keypair()
    _, wrong_sk = MLKEM768Provider.generate_keypair()

    assert len(pk) == ml_kem_768.PUBLIC_KEY_SIZE == 1184
    assert len(sk) == ml_kem_768.SECRET_KEY_SIZE == 2400

    pk_b64 = base64.b64encode(pk).decode("ascii")
    decoded_pk = MLKEM768Provider.decode_public_key_b64(pk_b64)
    assert decoded_pk == pk

    ct, ss_enc = MLKEM768Provider.encapsulate(decoded_pk)
    assert len(ct) == ml_kem_768.CIPHERTEXT_SIZE == 1088
    assert len(ss_enc) == ml_kem_768.PLAINTEXT_SIZE == 32

    # Independent decapsulation via raw pqcrypto library
    assert ml_kem_768.decrypt(sk, ct) == ss_enc
    assert MLKEM768Provider.decapsulate(sk, ct) == ss_enc

    # Wrong private key yields implicit-rejection different secret
    assert MLKEM768Provider.decapsulate(wrong_sk, ct) != ss_enc

    # Tampered ciphertext yields different secret
    tampered_ct = bytes([ct[0] ^ 0xFF]) + ct[1:]
    assert MLKEM768Provider.decapsulate(sk, tampered_ct) != ss_enc

    # Invalid Base64 / wrong lengths rejected safely
    for bad in ("not-base64!", base64.b64encode(b"short").decode("ascii"), ""):
        with pytest.raises(MLKEMError):
            MLKEM768Provider.decode_public_key_b64(bad)

    with pytest.raises(MLKEMError):
        MLKEM768Provider.decapsulate(sk, b"bad-ct")


def test_mldsa65_sign_verify_and_tamper() -> None:
    pk, sk = MLDSA65Provider.generate_keypair()
    wrong_pk, _ = MLDSA65Provider.generate_keypair()
    msg = b"qshield-signed-manifest-v1"
    sig = MLDSA65Provider.sign(sk, msg)

    assert MLDSA65Provider.verify(pk, msg, sig) is True
    assert MLDSA65Provider.verify(wrong_pk, msg, sig) is False
    assert MLDSA65Provider.verify(pk, b"qshield-signed-manifest-v2", sig) is False
    bad_sig = bytes([sig[0] ^ 0x01]) + sig[1:]
    assert MLDSA65Provider.verify(pk, msg, bad_sig) is False
    assert MLDSA65Provider.verify(pk, msg, b"") is False

    with pytest.raises(MLDSAError):
        MLDSA65Provider.sign(b"too-short", msg)


def test_aes256_gcm_tamper_aad_and_nonce_uniqueness() -> None:
    provider = AES256GCMProvider()
    key = provider.generate_dek()
    wrong_key = provider.generate_dek()
    aad = build_resource_aad_bytes(
        resource_id="res-1",
        owner_id="user-alex",
        resource_type="synthetic_document",
        key_version=1,
        timestamp_utc="2026-11-26T10:00:00Z",
    )
    plaintext = b"sensitive-synthetic-payload"
    nonce, ct = provider.encrypt(key, plaintext, aad)
    assert len(nonce) == 12
    assert provider.decrypt(key, nonce, ct, aad) == plaintext

    # Nonce reuse with same key forbidden
    with pytest.raises(AEADError):
        provider.encrypt(key, b"another", aad, nonce=nonce)

    # Tamper ciphertext / tag
    with pytest.raises(AEADError):
        provider.decrypt(key, nonce, bytes([ct[0] ^ 0x01]) + ct[1:], aad)
    with pytest.raises(AEADError):
        provider.decrypt(key, nonce, ct[:-1] + bytes([ct[-1] ^ 0x01]), aad)

    # Tamper nonce
    with pytest.raises(AEADError):
        provider.decrypt(key, bytes([nonce[0] ^ 0x01]) + nonce[1:], ct, aad)

    # Tamper AAD metadata
    bad_aad = build_resource_aad_bytes(
        resource_id="res-1",
        owner_id="user-blair",
        resource_type="synthetic_document",
        key_version=1,
        timestamp_utc="2026-11-26T10:00:00Z",
    )
    with pytest.raises(AEADError):
        provider.decrypt(key, nonce, ct, bad_aad)

    # Wrong key and malformed ciphertext
    with pytest.raises(AEADError):
        provider.decrypt(wrong_key, nonce, ct, aad)
    with pytest.raises(AEADError):
        provider.decrypt(key, nonce, b"short", aad)


def test_hkdf_sha256_context_separation_and_reproducibility() -> None:
    ikm = b"kem-shared-secret-32-bytes-value"
    salt = b"qshield-salt-01"

    k1 = derive_key_hkdf_sha256(ikm, salt=salt, purpose="vault_dek", context={"res": "r1", "v": 1})
    k1_again = derive_key_hkdf_sha256(ikm, salt=salt, purpose="vault_dek", context={"v": 1, "res": "r1"})
    k2 = derive_key_hkdf_sha256(ikm, salt=salt, purpose="session", context={"res": "r1", "v": 1})
    k3 = derive_key_hkdf_sha256(ikm, salt=salt, purpose="vault_dek", context={"res": "r2", "v": 1})

    assert len(k1) == 32
    assert k1 == k1_again
    assert len({k1, k2, k3}) == 3

    with pytest.raises(KDFError):
        derive_key_hkdf_sha256(ikm, salt=salt, purpose="unknown_purpose")


def test_hmac_sha256_contract_and_selftest() -> None:
    ss = b"\x11" * 32
    challenge = "chal-99"
    body = "exact-body-\u03bb"
    proof = compute_protected_read_proof(ss, challenge, body)
    expected = hmac.new(ss, (challenge + body).encode("utf-8"), hashlib.sha256).hexdigest()

    assert proof == expected
    assert verify_hmac_sha256_hex(ss, (challenge + body).encode("utf-8"), proof) is True
    assert verify_hmac_sha256_hex(ss, (challenge + ":" + body).encode("utf-8"), proof) is False
    assert verify_hmac_sha256_hex(ss, (challenge + body).encode("utf-8"), proof.upper()) is False
    assert sha256_hex(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

    report = run_crypto_selftest()
    assert report.passed is True
    assert all(report.checks.values())


def test_local_encrypted_keystore_security_and_tamper_failure(tmp_path: Path) -> None:
    ks_dir = tmp_path / "keystore"
    ks = LocalEncryptedKeyStore(ks_dir)
    secret = b"\xAB" * 32
    ks.put_secret_bytes("key-test-1", purpose="vault_kek", secret_bytes=secret)

    # Re-open fresh instance (restart persistence)
    ks2 = LocalEncryptedKeyStore(ks_dir)
    assert ks2.get_secret_bytes("key-test-1", expected_purpose="vault_kek") == secret

    # Key purpose separation enforced
    with pytest.raises(KeyStoreError):
        ks2.get_secret_bytes("key-test-1", expected_purpose="signing")

    # Tampering with encrypted keystore envelope fails closed
    env_file = ks_dir / "qshield_keystore.enc.json"
    raw = env_file.read_text(encoding="utf-8")
    env_file.write_text(raw[:-4] + "AAAA", encoding="utf-8")
    with pytest.raises(KeyStoreError):
        ks2.get_secret_bytes("key-test-1", expected_purpose="vault_kek")

    # Missing seed / missing keystore fails closed
    missing_ks = LocalEncryptedKeyStore(tmp_path / "missing_ks")
    with pytest.raises(KeyStoreError):
        missing_ks.get_secret_bytes("key-test-1", expected_purpose="vault_kek")
