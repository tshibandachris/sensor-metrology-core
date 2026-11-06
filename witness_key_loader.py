"""Strict, fail-closed loader for versioned Ed25519 witness public keys.

The registry is public data. This module never loads or handles private keys.
"""
from __future__ import annotations

import base64
import binascii
import json
from pathlib import Path
from typing import TypeGuard


class KeyNotFoundError(ValueError):
    """Raised when a requested key identifier is absent from the registry."""


class KeyRevokedError(ValueError):
    """Raised when a requested public key is explicitly marked as revoked."""


class KeyRegistryFormatError(ValueError):
    """Raised when the registry or a public-key entry is malformed."""


def _is_json_object(value: object) -> TypeGuard[dict[str, object]]:
    """Narrow a decoded JSON value to an object with string keys."""
    return isinstance(value, dict) and all(isinstance(key, str) for key in value)


def _is_registry(value: object) -> TypeGuard[dict[str, object]]:
    """Validate the root object and its required keys mapping."""
    if not _is_json_object(value):
        return False
    keys = value.get("keys")
    return _is_json_object(keys)


def _is_key_entry(value: object) -> TypeGuard[dict[str, object]]:
    """Validate the structural types used by a single key entry."""
    if not _is_json_object(value):
        return False
    public_key = value.get("public_key_b64url")
    revoked = value.get("revoked", False)
    return isinstance(public_key, str) and isinstance(revoked, bool)


class WitnessKeyLoader:
    """Load historical Ed25519 public keys from a trusted JSON registry."""

    def __init__(self, registry_path: str | Path) -> None:
        self._registry_path = Path(registry_path)

    def _read_registry(self) -> dict[str, object]:
        try:
            with self._registry_path.open("r", encoding="utf-8") as registry_file:
                loaded: object = json.load(registry_file)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise KeyRegistryFormatError(
                f"Unable to read a valid witness key registry: {self._registry_path}"
            ) from exc

        if not _is_registry(loaded):
            raise KeyRegistryFormatError(
                "Witness key registry must be a JSON object containing an object-valued 'keys' field."
            )
        return loaded

    @staticmethod
    def _decode_public_key(encoded: str, key_id: str) -> bytes:
        try:
            ascii_value = encoded.encode("ascii")
            decoded = base64.b64decode(
                ascii_value + b"=" * (-len(ascii_value) % 4),
                altchars=b"-_",
                validate=True,
            )
        except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
            raise KeyRegistryFormatError(
                f"Public key for {key_id!r} is not valid Base64url."
            ) from exc

        canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
        if len(decoded) != 32 or canonical != encoded:
            raise KeyRegistryFormatError(
                f"Public key for {key_id!r} must be a canonical 32-byte Base64url Ed25519 key."
            )
        return decoded

    def load_public_key_bytes(self, key_id: str) -> bytes:
        """Return the raw 32-byte public key, rejecting unknown or revoked IDs."""
        if not key_id:
            raise ValueError("key_id must not be empty.")

        registry = self._read_registry()
        keys = registry["keys"]
        if not _is_json_object(keys):
            # Defensive recheck keeps this method safe if the schema evolves.
            raise KeyRegistryFormatError("The registry 'keys' field is malformed.")

        entry_value = keys.get(key_id)
        if entry_value is None:
            raise KeyNotFoundError(f"Witness key {key_id!r} was not found.")

        if not _is_key_entry(entry_value):
            raise KeyRegistryFormatError(
                f"Witness key entry {key_id!r} is malformed."
            )

        if entry_value.get("revoked", False) is True:
            raise KeyRevokedError(f"Witness key {key_id!r} has been revoked.")

        encoded_public_key = entry_value.get("public_key_b64url")
        if not isinstance(encoded_public_key, str):
            raise KeyRegistryFormatError(
                f"Witness key entry {key_id!r} has no textual public key."
            )
        return self._decode_public_key(encoded_public_key, key_id)
