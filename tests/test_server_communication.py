"""End-to-end integration test for the real witness server and client bridge."""

from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import threading
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from remote_trust_bridge import RemoteTrustBridge
from sensor_trust_server import build_server
from witness_key_loader import WitnessKeyLoader


class ServerCommunicationTests(unittest.TestCase):
    def test_signed_genesis_append_readback_and_idempotent_replay(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        raw_private = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        encoded_private = base64.urlsafe_b64encode(raw_private).rstrip(b"=").decode("ascii")
        with tempfile.TemporaryDirectory() as directory:
            server = build_server(
                database_path=Path(directory) / "witness.sqlite3",
                host="127.0.0.1",
                port=0,
                auth_token="integration-secret",
                private_key_value=encoded_private,
                key_id="integration-key-1",
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                public_key = private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
                bridge = RemoteTrustBridge(
                    base_url=f"http://127.0.0.1:{server.server_address[1]}",
                    token="integration-secret",
                    target_id="integration-sensor",
                    trusted_public_keys={"integration-key-1": public_key},
                )
                genesis = bridge.fetch_expected_chain_head()
                self.assertEqual(genesis.sequence, 0)
                self.assertEqual(genesis.chain_hash, "0" * 64)

                previous_hash = genesis.chain_hash
                record_hash = hashlib.sha256(b"integration-record-001").hexdigest()
                chain_hash = hashlib.sha256(
                    f"{previous_hash}:{record_hash}".encode("ascii")
                ).hexdigest()
                receipt = bridge.post_new_chain_head(
                    sequence=1,
                    previous_hash=previous_hash,
                    record_hash=record_hash,
                    chain_hash=chain_hash,
                    idempotency_key="integration-append-001",
                )
                self.assertEqual(receipt.sequence, 1)
                self.assertEqual(receipt.chain_hash, chain_hash)
                self.assertEqual(receipt.previous_hash, previous_hash)
                self.assertEqual(receipt.record_hash, record_hash)

                readback = bridge.fetch_expected_chain_head()
                self.assertEqual(readback.sequence, 1)
                self.assertEqual(readback.chain_hash, chain_hash)

                replay = bridge.post_new_chain_head(
                    sequence=1,
                    previous_hash=previous_hash,
                    record_hash=record_hash,
                    chain_hash=chain_hash,
                    idempotency_key="integration-append-001",
                )
                self.assertEqual(replay.checkpoint_id, receipt.checkpoint_id)
                self.assertEqual(replay.issued_at, receipt.issued_at)

                wrong_previous = "f" * 64
                next_record = hashlib.sha256(b"integration-record-002").hexdigest()
                next_chain = hashlib.sha256(
                    f"{wrong_previous}:{next_record}".encode("ascii")
                ).hexdigest()
                with self.assertRaises(IOError):
                    bridge.post_new_chain_head(
                        sequence=2,
                        previous_hash=wrong_previous,
                        record_hash=next_record,
                        chain_hash=next_chain,
                        idempotency_key="integration-stale-002",
                    )
                final_head = bridge.fetch_expected_chain_head()
                self.assertEqual(final_head.sequence, 1)
                self.assertEqual(final_head.chain_hash, chain_hash)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


    def test_concurrent_competing_appends_have_one_winner(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        raw_private = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        encoded_private = base64.urlsafe_b64encode(raw_private).rstrip(b"=").decode("ascii")
        with tempfile.TemporaryDirectory() as directory:
            server = build_server(
                database_path=Path(directory) / "concurrent-witness.sqlite3",
                host="127.0.0.1",
                port=0,
                auth_token="integration-secret",
                private_key_value=encoded_private,
                key_id="integration-key-1",
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                public_key = private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
                base_url = f"http://127.0.0.1:{server.server_address[1]}"
                barrier = threading.Barrier(2)
                outcomes: list[tuple[str, object]] = []

                def compete(record: bytes, key: str) -> None:
                    bridge = RemoteTrustBridge(
                        base_url=base_url,
                        token="integration-secret",
                        target_id="concurrent-sensor",
                        trusted_public_keys={"integration-key-1": public_key},
                    )
                    head = bridge.fetch_expected_chain_head()
                    record_hash = hashlib.sha256(record).hexdigest()
                    chain_hash = hashlib.sha256(
                        f"{head.chain_hash}:{record_hash}".encode("ascii")
                    ).hexdigest()
                    barrier.wait(timeout=5)
                    try:
                        receipt = bridge.post_new_chain_head(
                            sequence=1,
                            previous_hash=head.chain_hash,
                            record_hash=record_hash,
                            chain_hash=chain_hash,
                            idempotency_key=key,
                        )
                        outcomes.append(("accepted", receipt))
                    except IOError as exc:
                        outcomes.append(("rejected", exc))

                workers = [
                    threading.Thread(target=compete, args=(b"candidate-a", "candidate-a")),
                    threading.Thread(target=compete, args=(b"candidate-b", "candidate-b")),
                ]
                for worker in workers:
                    worker.start()
                for worker in workers:
                    worker.join(timeout=10)
                    self.assertFalse(worker.is_alive(), "Concurrent append did not finish.")

                self.assertEqual(sum(kind == "accepted" for kind, _ in outcomes), 1)
                self.assertEqual(sum(kind == "rejected" for kind, _ in outcomes), 1)
                final_head = RemoteTrustBridge(
                    base_url=base_url,
                    token="integration-secret",
                    target_id="concurrent-sensor",
                    trusted_public_keys={"integration-key-1": public_key},
                ).fetch_expected_chain_head()
                self.assertEqual(final_head.sequence, 1)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


    def test_verification_with_rotated_and_revoked_keys(self) -> None:
        """Resolve a rotated key dynamically, then reject it after revocation."""
        key_id = "integration-rotated-witness-2026"
        private_key = Ed25519PrivateKey.generate()
        raw_private = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        encoded_private = (
            base64.urlsafe_b64encode(raw_private).rstrip(b"=").decode("ascii")
        )
        raw_public = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        encoded_public = (
            base64.urlsafe_b64encode(raw_public).rstrip(b"=").decode("ascii")
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry_path = root / "trusted_witness_keys.json"
            key_entry: dict[str, object] = {
                "algorithm": "Ed25519",
                "public_key_b64url": encoded_public,
                "activated_at_utc": "2026-11-06T09:00:00Z",
                "revoked": False,
            }
            keys: dict[str, object] = {key_id: key_entry}
            manifest: dict[str, object] = {
                "metadata": {"schema_version": "1.0"},
                "keys": keys,
            }
            registry_path.write_text(
                json.dumps(manifest, sort_keys=True),
                encoding="utf-8",
            )
            loader = WitnessKeyLoader(registry_path)

            server = build_server(
                database_path=root / "rotated-witness.sqlite3",
                host="127.0.0.1",
                port=0,
                auth_token="rotated-integration-secret",
                private_key_value=encoded_private,
                key_id=key_id,
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                bridge = RemoteTrustBridge(
                    base_url=f"http://127.0.0.1:{server.server_address[1]}",
                    token="rotated-integration-secret",
                    target_id="rotated-sensor",
                    witness_key_loader=loader,
                )
                genesis = bridge.fetch_expected_chain_head()
                self.assertEqual(genesis.key_id, key_id)
                self.assertEqual(genesis.sequence, 0)

                previous_hash = genesis.chain_hash
                first_record = hashlib.sha256(b"rotated-record-001").hexdigest()
                first_chain = hashlib.sha256(
                    f"{previous_hash}:{first_record}".encode("ascii")
                ).hexdigest()
                receipt = bridge.post_new_chain_head(
                    sequence=1,
                    previous_hash=previous_hash,
                    record_hash=first_record,
                    chain_hash=first_chain,
                    idempotency_key="rotated-append-001",
                )
                self.assertEqual(receipt.key_id, key_id)
                self.assertEqual(receipt.sequence, 1)
                self.assertEqual(receipt.chain_hash, first_chain)

                key_entry["revoked"] = True
                registry_path.write_text(
                    json.dumps(manifest, sort_keys=True),
                    encoding="utf-8",
                )

                second_record = hashlib.sha256(b"rotated-record-002").hexdigest()
                second_chain = hashlib.sha256(
                    f"{first_chain}:{second_record}".encode("ascii")
                ).hexdigest()
                with self.assertRaisesRegex(RuntimeError, "revoked"):
                    bridge.post_new_chain_head(
                        sequence=2,
                        previous_hash=first_chain,
                        record_hash=second_record,
                        chain_hash=second_chain,
                        idempotency_key="rotated-append-002",
                    )
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
