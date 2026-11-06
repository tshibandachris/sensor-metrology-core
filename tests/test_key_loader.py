"""Unit tests for the strict Ed25519 witness-key registry loader."""
from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path

from witness_key_loader import (
    KeyNotFoundError,
    KeyRegistryFormatError,
    KeyRevokedError,
    WitnessKeyLoader,
)


class WitnessKeyLoaderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.registry_path = Path(self.temp_dir.name) / "trusted_witness_keys.json"
        self.public_key = bytes(range(32))
        self.public_key_b64url = (
            base64.urlsafe_b64encode(self.public_key).rstrip(b"=").decode("ascii")
        )
        self._write_registry(
            {
                "metadata": {"schema_version": "1.0"},
                "keys": {
                    "witness-v1": {
                        "algorithm": "Ed25519",
                        "public_key_b64url": self.public_key_b64url,
                        "revoked": False,
                    }
                },
            }
        )
        self.loader = WitnessKeyLoader(self.registry_path)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _write_registry(self, data: object) -> None:
        self.registry_path.write_text(
            json.dumps(data),
            encoding="utf-8",
        )

    def test_loads_valid_public_key_as_32_raw_bytes(self) -> None:
        loaded = self.loader.load_public_key_bytes("witness-v1")
        self.assertEqual(loaded, self.public_key)
        self.assertEqual(len(loaded), 32)

    def test_unknown_key_raises_key_not_found(self) -> None:
        with self.assertRaises(KeyNotFoundError):
            self.loader.load_public_key_bytes("unknown-witness")

    def test_revoked_key_is_rejected(self) -> None:
        self._write_registry(
            {
                "keys": {
                    "witness-v1": {
                        "public_key_b64url": self.public_key_b64url,
                        "revoked": True,
                    }
                }
            }
        )
        with self.assertRaises(KeyRevokedError):
            self.loader.load_public_key_bytes("witness-v1")

    def test_corrupted_json_is_rejected(self) -> None:
        self.registry_path.write_text("{not-valid-json", encoding="utf-8")
        with self.assertRaises(KeyRegistryFormatError):
            self.loader.load_public_key_bytes("witness-v1")

    def test_invalid_root_or_keys_shape_is_rejected(self) -> None:
        for malformed in ([], {"keys": []}, {"keys": {"witness-v1": []}}):
            with self.subTest(malformed=malformed):
                self._write_registry(malformed)
                with self.assertRaises(KeyRegistryFormatError):
                    self.loader.load_public_key_bytes("witness-v1")

    def test_noncanonical_or_wrong_length_public_key_is_rejected(self) -> None:
        self._write_registry(
            {
                "keys": {
                    "witness-v1": {
                        "public_key_b64url": "AQ",
                        "revoked": False,
                    }
                }
            }
        )
        with self.assertRaises(KeyRegistryFormatError):
            self.loader.load_public_key_bytes("witness-v1")

    def test_non_boolean_revocation_flag_is_rejected(self) -> None:
        self._write_registry(
            {
                "keys": {
                    "witness-v1": {
                        "public_key_b64url": self.public_key_b64url,
                        "revoked": "false",
                    }
                }
            }
        )
        with self.assertRaises(KeyRegistryFormatError):
            self.loader.load_public_key_bytes("witness-v1")


if __name__ == "__main__":
    unittest.main()
