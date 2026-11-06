#!/usr/bin/env python3
"""Generate Ed25519 witness keys and maintain a versioned public-key registry.

Private material is never written to the repository registry. The default
operation requires an encrypted PKCS#8 PEM destination. Printing a raw private
key to stdout is an explicit, opt-in operation for controlled secret injection.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import secrets
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import TypeGuard, TypeAlias

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

KEY_REGISTRY_PATH = Path("docs/trusted_witness_keys.json")
_KEY_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

JSONScalar: TypeAlias = str | int | float | bool | None
JSONValue: TypeAlias = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]


def _is_json_object(value: object) -> TypeGuard[dict[str, JSONValue]]:
    """Narrow a decoded JSON object with string keys."""
    return isinstance(value, dict) and all(isinstance(key, str) for key in value)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _encode_b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def generate_key_pair(key_id: str) -> tuple[str, str]:
    """Return unpadded Base64url raw private and public Ed25519 keys."""
    if not _KEY_ID_PATTERN.fullmatch(key_id):
        raise ValueError("key_id must be 1–128 safe ASCII characters.")
    private_key = ed25519.Ed25519PrivateKey.generate()
    raw_private = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    raw_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _encode_b64url(raw_private), _encode_b64url(raw_public)


def encrypted_pem(private_key_b64url: str, passphrase: str) -> bytes:
    """Serialize a raw Base64url private key as encrypted PKCS#8 PEM."""
    if len(passphrase) < 12:
        raise ValueError("The PEM passphrase must contain at least 12 characters.")
    try:
        encoded = private_key_b64url.encode("ascii")
        raw_private = base64.b64decode(
            encoded + b"=" * (-len(encoded) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise ValueError("Private key must be canonical Base64url.") from exc
    if len(raw_private) != 32 or _encode_b64url(raw_private) != private_key_b64url:
        raise ValueError("The raw Ed25519 private key must be canonical Base64url for 32 bytes.")
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(raw_private)
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode("utf-8")),
    )


def _load_registry(path: Path) -> dict[str, JSONValue]:
    if not path.exists():
        return {"metadata": {"schema_version": "1.0"}, "keys": {}}
    try:
        with path.open("r", encoding="utf-8") as registry_file:
            loaded: object = json.load(registry_file)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Existing public-key registry cannot be read safely: {exc}") from exc
    if not _is_json_object(loaded):
        raise ValueError("Existing public-key registry must be a JSON object.")
    keys_value = loaded.get("keys")
    metadata_value = loaded.get("metadata")
    if not _is_json_object(keys_value) or not _is_json_object(metadata_value):
        raise ValueError("Existing public-key registry has an invalid schema.")
    for existing_id, entry in keys_value.items():
        if not existing_id or not isinstance(entry, dict):
            raise ValueError("Existing public-key registry contains an invalid key entry.")
    return loaded


def update_public_registry(key_id: str, b64url_public_key: str) -> None:
    """Atomically append a public key; never overwrite an existing key ID."""
    if not _KEY_ID_PATTERN.fullmatch(key_id):
        raise ValueError("key_id must be 1–128 safe ASCII characters.")
    try:
        encoded_public_key = b64url_public_key.encode("ascii")
        public_bytes = base64.b64decode(
            encoded_public_key + b"=" * (-len(encoded_public_key) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, UnicodeEncodeError, binascii.Error) as exc:
        raise ValueError("Public key must be valid Base64url.") from exc
    if len(public_bytes) != 32 or _encode_b64url(public_bytes) != b64url_public_key:
        raise ValueError("Public key must be a canonical 32-byte Base64url Ed25519 key.")

    registry_path = KEY_REGISTRY_PATH
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = registry_path.with_name(registry_path.name + ".lock")
    lock_fd: int | None = None
    temp_path: Path | None = None
    try:
        try:
            lock_fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise RuntimeError(
                f"Registry lock already exists at {lock_path}; inspect it before retrying."
            ) from exc
        os.write(lock_fd, f"pid={os.getpid()}\n".encode("ascii"))

        registry = _load_registry(registry_path)
        keys_value = registry.get("keys")
        metadata_value = registry.get("metadata")
        if not _is_json_object(keys_value) or not _is_json_object(metadata_value):
            raise ValueError("Existing public-key registry has an invalid schema.")
        keys = keys_value
        metadata = metadata_value
        if key_id in keys:
            raise ValueError(f"key_id {key_id!r} already exists; refusing to overwrite it.")
        timestamp = _utc_now()
        metadata["schema_version"] = "1.0"
        metadata["last_rotation_utc"] = timestamp
        keys[key_id] = {
            "algorithm": "Ed25519",
            "public_key_b64url": b64url_public_key,
            "activated_at_utc": timestamp,
            "revoked": False,
        }

        temp_fd, temp_name = tempfile.mkstemp(
            prefix=f".{registry_path.name}.", suffix=".tmp", dir=str(registry_path.parent)
        )
        temp_path = Path(temp_name)
        with os.fdopen(temp_fd, "w", encoding="utf-8", newline="\n") as temp_file:
            json.dump(registry, temp_file, indent=2, ensure_ascii=True, sort_keys=True)
            temp_file.write("\n")
            temp_file.flush()
            os.fsync(temp_file.fileno())
        os.replace(temp_path, registry_path)
        temp_path = None
        print(f"Public registry updated: {registry_path}")
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass
        if lock_fd is not None:
            os.close(lock_fd)
            try:
                lock_path.unlink()
            except FileNotFoundError:
                pass


def execute_rotation(
    key_id: str | None = None,
    pem_output: Path | None = None,
    print_private_key: bool = False,
) -> int:
    """Generate one key and publish its public half without leaking private material."""
    if pem_output is None and not print_private_key:
        print(
            "Refusing to generate a key without a secure destination. "
            "Use --pem-output with METROLOGY_KEY_PASSPHRASE, or explicitly opt in "
            "to --print-private-key in a controlled secret-injection session.",
            file=sys.stderr,
        )
        return 2

    print("=== METROLOGY: ED25519 WITNESS KEY ROTATION ===")
    timestamp_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    resolved_key_id = key_id or f"metrology-witness-{timestamp_id}-{secrets.token_hex(4)}"
    try:
        private_key, public_key = generate_key_pair(resolved_key_id)
        if pem_output is not None:
            passphrase = os.environ.get("METROLOGY_KEY_PASSPHRASE", "")
            pem_bytes = encrypted_pem(private_key, passphrase)
            pem_output.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(pem_output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(descriptor, "wb") as pem_file:
                pem_file.write(pem_bytes)
                pem_file.flush()
                os.fsync(pem_file.fileno())
        update_public_registry(resolved_key_id, public_key)
    except (OSError, RuntimeError, ValueError) as err:
        print(f"CRITICAL ROTATION FAILURE: {err}", file=sys.stderr)
        return 1

    print("\n--- SERVER DEPLOYMENT VALUES ---")
    print(f'METROLOGY_KEY_ID="{resolved_key_id}"')
    if print_private_key:
        print(
            "WARNING: raw private key output was explicitly enabled; "
            "do not retain this terminal or CI log.",
            file=sys.stderr,
        )
        print(f'METROLOGY_PRIVATE_KEY="{private_key}"')
    if pem_output is not None:
        print(f"Encrypted private key written to: {pem_output}")
    print("--------------------------------\n")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--key-id", help="Explicit unique key identifier.")
    parser.add_argument(
        "--pem-output",
        type=Path,
        help="Encrypted PKCS#8 PEM destination (must not already exist).",
    )
    parser.add_argument(
        "--print-private-key",
        action="store_true",
        help="UNSAFE opt-in: print the raw private key to stdout for controlled secret injection.",
    )
    args = parser.parse_args()
    return execute_rotation(args.key_id, args.pem_output, args.print_private_key)


if __name__ == "__main__":
    sys.exit(main())
