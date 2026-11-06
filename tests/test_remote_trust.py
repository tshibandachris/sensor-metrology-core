"""Protocol and failure-mode tests for the remote trust bridge."""

from __future__ import annotations

import base64
import hashlib
import json
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import URLError

from remote_trust_bridge import RemoteTrustBridge
from remote_trust_stub import RemoteTrustStub


def _chain_hash(previous_hash: str, record_hash: str) -> str:
    return hashlib.sha256(
        f"{previous_hash}:{record_hash}".encode("ascii")
    ).hexdigest()


class RemoteTrustBridgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.stub = RemoteTrustStub()
        self.bridge = RemoteTrustBridge(
            base_url=self.stub.base_url,
            token="test-token",
            target_id="sensor-001",
            trusted_public_keys=self.stub.public_keys,
        )

    def tearDown(self) -> None:
        self.stub.close()

    def test_fetch_verifies_genesis_head(self) -> None:
        head = self.bridge.fetch_expected_chain_head()
        self.assertEqual(head.target_id, "sensor-001")
        self.assertEqual(head.sequence, 0)
        self.assertEqual(head.chain_hash, "0" * 64)

    def test_post_appends_and_fetches_signed_head(self) -> None:
        previous = "0" * 64
        record = hashlib.sha256(b"record-one").hexdigest()
        chain = _chain_hash(previous, record)
        receipt = self.bridge.post_new_chain_head(
            sequence=1,
            previous_hash=previous,
            record_hash=record,
            chain_hash=chain,
            idempotency_key="append-001",
        )
        self.assertEqual(receipt.sequence, 1)
        self.assertEqual(receipt.chain_hash, chain)
        self.assertEqual(receipt.previous_hash, previous)
        self.assertEqual(receipt.record_hash, record)
        remote = self.bridge.fetch_expected_chain_head()
        self.assertEqual(remote.sequence, 1)
        self.assertEqual(remote.chain_hash, chain)

    def test_invalid_local_digest_is_rejected_before_network(self) -> None:
        with self.assertRaises(ValueError):
            self.bridge.post_new_chain_head(
                sequence=1,
                previous_hash="not-a-digest",
                record_hash="0" * 64,
                chain_hash="0" * 64,
                idempotency_key="append-invalid",
            )
        self.assertEqual(self.stub.sequence, 0)

    def test_incorrect_chain_hash_is_rejected_before_network(self) -> None:
        with self.assertRaises(ValueError):
            self.bridge.post_new_chain_head(
                sequence=1,
                previous_hash="0" * 64,
                record_hash="1" * 64,
                chain_hash="2" * 64,
                idempotency_key="append-invalid-chain",
            )
        self.assertEqual(self.stub.sequence, 0)

    def test_network_failure_raises_io_error(self) -> None:
        with patch.object(
            self.bridge._opener, "open", side_effect=URLError("offline")
        ):
            with self.assertRaises(IOError):
                self.bridge.fetch_expected_chain_head()

    def test_malformed_json_raises_runtime_error(self) -> None:
        response = MagicMock()
        response.status = 200
        response.read.return_value = b"{malformed"
        context = MagicMock()
        context.__enter__.return_value = response
        with patch.object(self.bridge._opener, "open", return_value=context):
            with self.assertRaises(RuntimeError):
                self.bridge.fetch_expected_chain_head()

    def test_invalid_bearer_token_is_rejected_by_live_local_server(self) -> None:
        invalid_bridge = RemoteTrustBridge(
            base_url=self.stub.base_url,
            token="invalid-token",
            target_id="sensor-001",
            trusted_public_keys=self.stub.public_keys,
        )
        with self.assertRaises(IOError):
            invalid_bridge.fetch_expected_chain_head()

    def test_malformed_json_from_live_local_server_is_rejected(self) -> None:
        self.stub.malformed_next_get_response = True
        with self.assertRaises(RuntimeError):
            self.bridge.fetch_expected_chain_head()

    def test_invalid_signature_is_rejected(self) -> None:
        payload = {
            "protocol_version": 1,
            "target_id": "sensor-001",
            "sequence": 0,
            "chain_hash": "0" * 64,
            "checkpoint_id": "genesis",
            "issued_at": "2026-11-04T12:00:00Z",
        }
        encoded_payload = base64.urlsafe_b64encode(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).rstrip(b"=").decode("ascii")
        invalid_envelope = {
            "key_id": "test-ed25519-key",
            "payload": encoded_payload,
            "signature": base64.urlsafe_b64encode(b"x" * 64).rstrip(b"=").decode("ascii"),
        }
        with patch.object(self.bridge, "_request", return_value=invalid_envelope):
            with self.assertRaises(RuntimeError):
                self.bridge.fetch_expected_chain_head()

    def test_retry_after_lost_response_returns_original_receipt(self) -> None:
        previous = "0" * 64
        record = hashlib.sha256(b"record-lost-response").hexdigest()
        chain = _chain_hash(previous, record)
        self.stub.drop_next_post_response = True
        with self.assertRaises(IOError):
            self.bridge.post_new_chain_head(
                sequence=1,
                previous_hash=previous,
                record_hash=record,
                chain_hash=chain,
                idempotency_key="append-retry-001",
            )
        receipt = self.bridge.post_new_chain_head(
            sequence=1,
            previous_hash=previous,
            record_hash=record,
            chain_hash=chain,
            idempotency_key="append-retry-001",
        )
        self.assertEqual(receipt.sequence, 1)
        self.assertEqual(receipt.chain_hash, chain)
        self.assertEqual(self.stub.sequence, 1)

    def test_reusing_idempotency_key_with_different_body_fails(self) -> None:
        previous = "0" * 64
        first_record = hashlib.sha256(b"first").hexdigest()
        first_chain = _chain_hash(previous, first_record)
        self.bridge.post_new_chain_head(
            sequence=1,
            previous_hash=previous,
            record_hash=first_record,
            chain_hash=first_chain,
            idempotency_key="same-key",
        )
        second_record = hashlib.sha256(b"second").hexdigest()
        second_chain = _chain_hash(previous, second_record)
        with self.assertRaises(IOError):
            self.bridge.post_new_chain_head(
                sequence=1,
                previous_hash=previous,
                record_hash=second_record,
                chain_hash=second_chain,
                idempotency_key="same-key",
            )
        self.assertEqual(self.stub.sequence, 1)


if __name__ == "__main__":
    unittest.main()
