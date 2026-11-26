"""Startup and diagnostic cryptographic self-tests with published KAT vectors.

Never prints, logs, or returns secret keys, derived keys, or plaintexts.
"""

from __future__ import annotations

from dataclasses import dataclass

from backend.app.crypto.aead import AEADError, AES256GCMProvider
from backend.app.crypto.hmac_hash import hmac_sha256_hex, sha256_hex, verify_hmac_sha256_hex
from backend.app.crypto.kdf import derive_key_hkdf_sha256
from backend.app.crypto.mlkem import MLKEM768Provider
from backend.app.crypto.mldsa import MLDSA65Provider


@dataclass(frozen=True)
class CryptoSelfTestReport:
    passed: bool
    checks: dict[str, bool]
    libraries: dict[str, str]
    detail: str


def run_crypto_selftest() -> CryptoSelfTestReport:
    """Execute deterministic KATs and live roundtrip/tamper checks for all crypto providers."""
    import cryptography
    import pqcrypto

    checks: dict[str, bool] = {}

    # 1. FIPS 180-4 SHA-256 KAT ("abc")
    checks["sha256_kat"] = (
        sha256_hex(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )

    # 2. RFC 4231 Test Case 1 HMAC-SHA-256 KAT + constant-time verify
    kat_hmac_key = bytes.fromhex("0b" * 20)
    kat_hmac_msg = b"Hi There"
    kat_hmac_expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    computed_hmac = hmac_sha256_hex(kat_hmac_key, kat_hmac_msg)
    checks["hmac_sha256_kat"] = (
        computed_hmac == kat_hmac_expected
        and verify_hmac_sha256_hex(kat_hmac_key, kat_hmac_msg, kat_hmac_expected)
        and not verify_hmac_sha256_hex(kat_hmac_key, kat_hmac_msg + b"!", kat_hmac_expected)
    )

    # 3. RFC 5869 HKDF-SHA-256 KAT (Test Case 1) + context separation
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    rfc5869_okm = HKDF(
        algorithm=hashes.SHA256(),
        length=42,
        salt=bytes.fromhex("000102030405060708090a0b0c"),
        info=bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
    ).derive(bytes.fromhex("0b" * 22))
    rfc5869_expected = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    )
    d1 = derive_key_hkdf_sha256(b"ikm-selftest-1", salt=b"salt", purpose="vault_dek", context={"id": "1"})
    d2 = derive_key_hkdf_sha256(b"ikm-selftest-1", salt=b"salt", purpose="session", context={"id": "1"})
    checks["hkdf_sha256_kat_and_separation"] = (rfc5869_okm == rfc5869_expected) and (d1 != d2)

    # 4. ML-KEM-768 roundtrip + wrong key separation
    pk1, sk1 = MLKEM768Provider.generate_keypair()
    _pk2, sk2 = MLKEM768Provider.generate_keypair()
    ct, ss_enc = MLKEM768Provider.encapsulate(pk1)
    ss_dec = MLKEM768Provider.decapsulate(sk1, ct)
    ss_wrong = MLKEM768Provider.decapsulate(sk2, ct)
    checks["ml_kem_768_roundtrip"] = (ss_enc == ss_dec) and (ss_wrong != ss_enc)

    # 5. AES-256-GCM roundtrip + ciphertext & AAD tamper rejection
    aead = AES256GCMProvider()
    dek = aead.generate_dek()
    aad = b"selftest-aad-v1"
    nonce, ct_gcm = aead.encrypt(dek, b"selftest-plaintext", aad)
    pt = aead.decrypt(dek, nonce, ct_gcm, aad)
    tamper_ct_rejected = False
    try:
        bad_ct = bytes([ct_gcm[0] ^ 0x01]) + ct_gcm[1:]
        aead.decrypt(dek, nonce, bad_ct, aad)
    except AEADError:
        tamper_ct_rejected = True
    tamper_aad_rejected = False
    try:
        aead.decrypt(dek, nonce, ct_gcm, b"tampered-aad")
    except AEADError:
        tamper_aad_rejected = True
    checks["aes_256_gcm_roundtrip_and_tamper"] = (
        pt == b"selftest-plaintext" and tamper_ct_rejected and tamper_aad_rejected
    )

    # 6. ML-DSA-65 sign/verify + tamper rejection
    dpk, dsk = MLDSA65Provider.generate_keypair()
    sig = MLDSA65Provider.sign(dsk, b"selftest-msg")
    checks["ml_dsa_65_roundtrip"] = (
        MLDSA65Provider.verify(dpk, b"selftest-msg", sig)
        and not MLDSA65Provider.verify(dpk, b"tampered-msg", sig)
    )

    all_passed = all(checks.values())
    return CryptoSelfTestReport(
        passed=all_passed,
        checks=checks,
        libraries={
            "pqcrypto": getattr(pqcrypto, "__version__", "0.4.0"),
            "cryptography": cryptography.__version__,
        },
        detail="All cryptographic self-tests passed." if all_passed else "One or more crypto self-tests failed.",
    )
