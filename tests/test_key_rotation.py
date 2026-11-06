"""Unit tests for Ed25519 witness-key generation and registry rotation."""
from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

import rotate_witness_keys as rotation


class WitnessKeyRotationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.registry_mock = self.root / "trusted_keys.json"
        self.patcher = patch("rotate_witness_keys.KEY_REGISTRY_PATH", self.registry_mock)
        self.patcher.start()

    def tearDown(self) -> None:
        self.patcher.stop()
        self.temp_dir.cleanup()

    def test_key_pair_generation_format_and_signature(self) -> None:
        private_b64, public_b64 = rotation.generate_key_pair("test-key-id")
        self.assertFalse(private_b64.endswith("="))
        self.assertFalse(public_b64.endswith("="))
        self.assertEqual(len(private_b64), 43)
        self.assertEqual(len(public_b64), 43)
        private_raw = base64.urlsafe_b64decode(private_b64 + "=")
        public_raw = base64.urlsafe_b64decode(public_b64 + "=")
        self.assertEqual(len(private_raw), 32)
        self.assertEqual(len(public_raw), 32)
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_raw)
        message = b"metrology-key-rotation-test"
        private_key.public_key().verify(private_key.sign(message), message)
        self.assertEqual(
            private_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ),
            public_raw,
        )

    def test_encrypted_pem_requires_a_strong_passphrase(self) -> None:
        private_b64, _ = rotation.generate_key_pair("pem-test")
        with self.assertRaises(ValueError):
            rotation.encrypted_pem(private_b64, "short")
        pem = rotation.encrypted_pem(private_b64, "a-long-test-passphrase")
        loaded = serialization.load_pem_private_key(pem, password=b"a-long-test-passphrase")
        self.assertIsInstance(loaded, ed25519.Ed25519PrivateKey)

    def test_registry_accumulates_keys_without_overwriting_history(self) -> None:
        _, public_v1 = rotation.generate_key_pair("key-v1")
        _, public_v2 = rotation.generate_key_pair("key-v2")
        rotation.update_public_registry("key-v1", public_v1)
        rotation.update_public_registry("key-v2", public_v2)
        with self.registry_mock.open("r", encoding="utf-8") as registry_file:
            data = json.load(registry_file)
        self.assertIn("key-v1", data["keys"])
        self.assertIn("key-v2", data["keys"])
        self.assertEqual(data["keys"]["key-v1"]["public_key_b64url"], public_v1)
        self.assertEqual(data["keys"]["key-v2"]["public_key_b64url"], public_v2)
        self.assertFalse(data["keys"]["key-v1"]["revoked"])
        self.assertNotIn("private_key", json.dumps(data))

    def test_duplicate_key_id_is_rejected_without_changing_registry(self) -> None:
        _, public_key = rotation.generate_key_pair("duplicate-test")
        rotation.update_public_registry("duplicate-test", public_key)
        original = self.registry_mock.read_bytes()
        with self.assertRaisesRegex(ValueError, "already exists"):
            rotation.update_public_registry("duplicate-test", public_key)
        self.assertEqual(self.registry_mock.read_bytes(), original)

    def test_malformed_registry_fails_closed(self) -> None:
        self.registry_mock.write_text("{not-json", encoding="utf-8")
        _, public_key = rotation.generate_key_pair("safe-failure")
        with self.assertRaisesRegex(ValueError, "cannot be read safely"):
            rotation.update_public_registry("safe-failure", public_key)
        self.assertEqual(self.registry_mock.read_text(encoding="utf-8"), "{not-json")

    def test_existing_lock_prevents_concurrent_writer(self) -> None:
        _, public_key = rotation.generate_key_pair("locked-test")
        lock_path = self.registry_mock.with_name(self.registry_mock.name + ".lock")
        lock_path.write_text("another writer", encoding="ascii")
        with self.assertRaisesRegex(RuntimeError, "lock already exists"):
            rotation.update_public_registry("locked-test", public_key)
        self.assertFalse(self.registry_mock.exists())


if __name__ == "__main__":
    unittest.main()
