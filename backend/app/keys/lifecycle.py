"""Key lifecycle state machine, purpose separation, and algorithm validation."""

from __future__ import annotations

from typing import Final

KEY_STATES: Final[frozenset[str]] = frozenset(
    {
        "PREPARED",
        "ACTIVE",
        "ROTATING",
        "ACTIVE_NEW",
        "RETIRED",
        "REVOKED",
        "COMPROMISED",
    }
)

TERMINAL_KEY_STATES: Final[frozenset[str]] = frozenset({"REVOKED", "COMPROMISED"})

ALLOWED_KEY_TRANSITIONS: Final[dict[str, frozenset[str]]] = {
    "PREPARED": frozenset({"ACTIVE", "ACTIVE_NEW", "REVOKED", "COMPROMISED"}),
    "ACTIVE": frozenset({"ROTATING", "RETIRED", "REVOKED", "COMPROMISED"}),
    "ROTATING": frozenset({"ACTIVE", "ACTIVE_NEW", "RETIRED", "REVOKED", "COMPROMISED"}),
    "ACTIVE_NEW": frozenset({"ACTIVE", "RETIRED", "REVOKED", "COMPROMISED"}),
    "RETIRED": frozenset({"REVOKED", "COMPROMISED"}),
    "REVOKED": frozenset(),
    "COMPROMISED": frozenset(),
}

KEY_PURPOSES: Final[dict[str, str]] = {
    "kem": "ML-KEM-768",
    "signing": "ML-DSA-65",
    "vault_kek": "HKDF-SHA-256+AES-256-GCM",
    "vault_dek": "AES-256-GCM",
    "session": "HKDF-SHA-256",
    "audit": "ML-DSA-65",
}


class KeyLifecycleError(Exception):
    """Domain error for key lifecycle state or purpose violations."""

    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


def validate_key_purpose(purpose: str) -> str:
    """Validate allowed key purpose and return its vetted algorithm identifier."""
    if purpose not in KEY_PURPOSES:
        raise KeyLifecycleError(400, "INVALID_KEY_PURPOSE", f"Unsupported key purpose: {purpose}")
    return KEY_PURPOSES[purpose]


def validate_key_transition(current_state: str, target_state: str) -> None:
    """Enforce key state machine and terminal non-reactivation invariant."""
    if current_state not in KEY_STATES or target_state not in KEY_STATES:
        raise KeyLifecycleError(400, "INVALID_KEY_STATE", "Unknown key lifecycle state.")
    if current_state in TERMINAL_KEY_STATES:
        raise KeyLifecycleError(
            409,
            "KEY_TERMINAL_STATE",
            f"Keys in terminal state '{current_state}' cannot be reactivated or transitioned.",
        )
    allowed = ALLOWED_KEY_TRANSITIONS.get(current_state, frozenset())
    if target_state not in allowed:
        raise KeyLifecycleError(
            409,
            "INVALID_KEY_TRANSITION",
            f"Transition '{current_state}' -> '{target_state}' is not allowed.",
        )
