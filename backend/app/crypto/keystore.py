"""Encrypted local demo key store (sandbox-only; not an HSM).

Stores sensitive KEKs, wrapped DEKs, and private key bytes outside ordinary
SQLite metadata tables in an AES-256-GCM authenticated JSON envelope file.
Fails closed if master seed/secret or envelope file is missing or tampered.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
from pathlib import Path
import secrets
import threading

from backend.app.crypto.aead import AEADError, AES256GCMProvider
from backend.app.crypto.kdf import derive_key_hkdf_sha256

KEYSTORE_AAD = b"qshield.local.keystore.envelope.v1"
KEYSTORE_FILE_NAME = "qshield_keystore.enc.json"
MASTER_SEED_FILE_NAME = "qshield_master.seed"


class KeyStoreError(RuntimeError):
    """Raised when local keystore cannot be loaded, authenticated, or accessed."""


def _restrict_permissions(path: Path) -> None:
    """Apply restrictive 0600 file permissions where supported by the OS."""
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


class LocalEncryptedKeyStore:
    """Authenticated local key store protected by AES-256-GCM + HKDF-SHA-256."""

    def __init__(self, keystore_dir: Path, master_secret: str | None = None) -> None:
        self.keystore_dir = keystore_dir
        self._master_secret = master_secret
        self._aead = AES256GCMProvider()
        self._envelope_path = keystore_dir / KEYSTORE_FILE_NAME
        self._seed_path = keystore_dir / MASTER_SEED_FILE_NAME
        self._lock = threading.RLock()

    def _resolve_master_key(self, *, create_seed_if_missing: bool) -> bytes:
        if self._master_secret:
            ikm = self._master_secret.encode("utf-8")
            salt = b"qshield-env-master-salt-v1"
        else:
            if not self._seed_path.exists():
                if not create_seed_if_missing:
                    raise KeyStoreError("Local keystore master seed is missing; failing closed.")
                self.keystore_dir.mkdir(parents=True, exist_ok=True)
                seed_bytes = secrets.token_bytes(32)
                self._seed_path.write_bytes(seed_bytes)
                _restrict_permissions(self._seed_path)
            try:
                ikm = self._seed_path.read_bytes()
            except OSError as exc:
                raise KeyStoreError("Unable to read local keystore master seed.") from exc
            if len(ikm) != 32:
                raise KeyStoreError("Corrupt local keystore master seed length.")
            salt = b"qshield-local-seed-salt-v1"

        return derive_key_hkdf_sha256(
            ikm,
            salt=salt,
            purpose="keystore_master",
            context={"keystore_dir": self.keystore_dir.name},
            length=32,
        )

    def _load_entries(self, *, create_if_empty: bool) -> dict[str, dict[str, str]]:
        if not self._envelope_path.exists():
            if not create_if_empty:
                raise KeyStoreError("Encrypted keystore envelope is missing; failing closed.")
            return {}

        master_key = self._resolve_master_key(create_seed_if_missing=False)
        try:
            wrapper = json.loads(self._envelope_path.read_text(encoding="utf-8"))
            nonce = base64.b64decode(wrapper["nonce"], validate=True)
            ciphertext = base64.b64decode(wrapper["ciphertext"], validate=True)
        except (OSError, ValueError, KeyError, binascii.Error, TypeError) as exc:
            raise KeyStoreError("Encrypted keystore envelope is malformed.") from exc

        try:
            plaintext = self._aead.decrypt(master_key, nonce, ciphertext, KEYSTORE_AAD)
            data = json.loads(plaintext.decode("utf-8"))
        except (AEADError, ValueError, UnicodeDecodeError) as exc:
            raise KeyStoreError("Encrypted keystore failed authentication or integrity check.") from exc

        if not isinstance(data, dict) or not isinstance(data.get("entries"), dict):
            raise KeyStoreError("Encrypted keystore payload schema invalid.")
        return data["entries"]

    def _save_entries(self, entries: dict[str, dict[str, str]]) -> None:
        self.keystore_dir.mkdir(parents=True, exist_ok=True)
        master_key = self._resolve_master_key(create_seed_if_missing=True)
        payload = json.dumps({"schema": "v1", "entries": entries}, separators=(",", ":")).encode("utf-8")
        nonce, ciphertext = self._aead.encrypt(master_key, payload, KEYSTORE_AAD)
        wrapper = {
            "schema": "v1",
            "algorithm": "AES-256-GCM",
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }
        tmp_path = self._envelope_path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(wrapper, separators=(",", ":")), encoding="utf-8")
        _restrict_permissions(tmp_path)
        os.replace(tmp_path, self._envelope_path)
        _restrict_permissions(self._envelope_path)

    def reset(self) -> None:
        """Remove keystore envelope and master seed for clean synthetic demo reset."""
        for p in (self._envelope_path, self._seed_path):
            if p.exists():
                p.unlink()

    def put_secret_bytes(self, key_id: str, *, purpose: str, secret_bytes: bytes) -> None:
        """Persist secret key bytes under key_id inside authenticated envelope."""
        if not key_id or not isinstance(secret_bytes, bytes) or len(secret_bytes) == 0:
            raise KeyStoreError("Invalid key_id or secret bytes.")
        with self._lock:
            entries = self._load_entries(create_if_empty=True)
            entries[key_id] = {
                "purpose": purpose,
                "secret_b64": base64.b64encode(secret_bytes).decode("ascii"),
            }
            self._save_entries(entries)

    def get_secret_bytes(self, key_id: str, *, expected_purpose: str) -> bytes:
        """Load and authenticate secret key bytes; verify key-purpose separation."""
        with self._lock:
            entries = self._load_entries(create_if_empty=False)
            entry = entries.get(key_id)
            if entry is None:
                raise KeyStoreError(f"Key '{key_id}' not found in local keystore.")
            if entry.get("purpose") != expected_purpose:
                raise KeyStoreError(
                    f"Key purpose mismatch for '{key_id}': expected '{expected_purpose}', got '{entry.get('purpose')}'."
                )
            try:
                return base64.b64decode(entry["secret_b64"], validate=True)
            except (KeyError, ValueError, binascii.Error) as exc:
                raise KeyStoreError(f"Corrupt key entry '{key_id}'.") from exc

    def has_key(self, key_id: str) -> bool:
        with self._lock:
            if not self._envelope_path.exists():
                return False
            entries = self._load_entries(create_if_empty=False)
            return key_id in entries

    def delete_key(self, key_id: str) -> bool:
        """Securely remove a key entry and re-seal the authenticated keystore envelope."""
        with self._lock:
            if not self._envelope_path.exists():
                return False
            entries = self._load_entries(create_if_empty=False)
            if key_id not in entries:
                return False
            del entries[key_id]
            self._save_entries(entries)
            return True

    def delete_keys_with_prefix(self, prefix: str) -> int:
        """Remove all key entries matching prefix and re-seal keystore envelope."""
        with self._lock:
            if not self._envelope_path.exists():
                return 0
            entries = self._load_entries(create_if_empty=False)
            to_remove = [k for k in entries if k.startswith(prefix)]
            if not to_remove:
                return 0
            for k in to_remove:
                del entries[k]
            self._save_entries(entries)
            return len(to_remove)

    def export_snapshot(self) -> dict[str, dict[str, str]]:
        """Return authenticated copy of keystore entries for encrypted backup packaging only."""
        if not self._envelope_path.exists():
            return {}
        entries = self._load_entries(create_if_empty=False)
        return {k: dict(v) for k, v in entries.items()}

    def import_snapshot(self, entries: dict[str, dict[str, str]], *, preserve_keys: set[str] | None = None) -> None:
        """Restore verified keystore entries without overwriting excluded/revoked key IDs."""
        current = self._load_entries(create_if_empty=True)
        excluded = preserve_keys or set()
        merged = dict(current)
        for key_id, entry in entries.items():
            if key_id in excluded:
                continue
            merged[key_id] = dict(entry)
        self._save_entries(merged)


def get_keystore() -> LocalEncryptedKeyStore:
    """FastAPI dependency returning configured LocalEncryptedKeyStore."""
    from backend.app.config import settings

    return LocalEncryptedKeyStore(Path(settings.keystore_dir), settings.keystore_secret)
