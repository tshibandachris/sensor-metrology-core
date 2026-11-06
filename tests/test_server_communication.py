"""End-to-end integration test for the real witness server and client bridge."""

from __future__ import annotations

import base64
import hashlib
import tempfile
import threading
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from remote_trust_bridge import RemoteTrustBridge
from sensor_trust_server import build_server


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


if __name__ == "__main__":
    unittest.main()
