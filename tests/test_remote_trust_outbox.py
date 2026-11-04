"""Tests for durable local-to-remote checkpoint outbox reconciliation."""

from __future__ import annotations

import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path
from urllib.error import URLError
from unittest.mock import patch

from chronological_ledger import IntegrityError
from remote_trust_bridge import RemoteTrustBridge, VerifiedChainHead
from remote_trust_outbox import RemoteTrustSynchronizer
from remote_trust_stub import RemoteTrustStub
from transactional_ledger import (
    RemoteCheckpointPendingError,
    TransactionalLedgerManager,
)

TEST_SECRET = b"remote-outbox-test-secret-material"


def _chain_hash(previous_hash: str, record_hash: str) -> str:
    return hashlib.sha256(
        f"{previous_hash}:{record_hash}".encode("ascii")
    ).hexdigest()


class RemoteTrustOutboxTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "ledger.sqlite3"
        self.ledger = TransactionalLedgerManager(
            self.database_path,
            hmac_secret=TEST_SECRET,
            remote_checkpointing=True,
        )
        self.stub = RemoteTrustStub(target_id="ledger-001")
        self.bridge = RemoteTrustBridge(
            base_url=self.stub.base_url,
            token="test-token",
            target_id="ledger-001",
            trusted_public_keys=self.stub.public_keys,
        )
        self.synchronizer = RemoteTrustSynchronizer(self.ledger, self.bridge)

    def tearDown(self) -> None:
        self.stub.close()
        self.temp_dir.cleanup()

    def append_baseline(self, record_id: str = "baseline-001") -> str:
        return self.ledger.append_baseline(
            record_id=record_id,
            target_id="sensor-001",
            execution_version="build-outbox",
            event_timestamp="2026-11-01T08:00:00Z",
            payload={"pressure_pa": 101325},
        )

    def test_local_append_and_outbox_entry_are_atomic(self) -> None:
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute(
                """
                CREATE TRIGGER reject_outbox_insert
                BEFORE INSERT ON remote_checkpoint_outbox
                BEGIN
                    SELECT RAISE(ABORT, 'simulated outbox failure');
                END
                """
            )
            connection.commit()
        finally:
            connection.close()

        with self.assertRaises(sqlite3.IntegrityError):
            self.append_baseline()
        self.assertEqual(self.ledger.verify(), 0)

    def test_pending_checkpoint_blocks_later_appends_until_delivered(self) -> None:
        self.assertEqual(self.append_baseline(), "appended")
        with self.assertRaises(RemoteCheckpointPendingError):
            self.ledger.append_baseline(
                record_id="baseline-002",
                target_id="sensor-002",
                execution_version="build-outbox",
                event_timestamp="2026-11-01T08:01:00Z",
                payload={"pressure_pa": 101400},
            )

        self.assertEqual(self.synchronizer.synchronize_one(), "delivered")
        self.assertEqual(
            self.ledger.append_baseline(
                record_id="baseline-002",
                target_id="sensor-002",
                execution_version="build-outbox",
                event_timestamp="2026-11-01T08:01:00Z",
                payload={"pressure_pa": 101400},
            ),
            "appended",
        )
        self.assertEqual(self.synchronizer.synchronize(), 1)
        self.assertEqual(self.stub.sequence, 2)
        self.assertEqual(self.ledger.verify(), 2)

    def test_existing_history_is_backfilled_once_and_delivered_in_order(self) -> None:
        history_path = Path(self.temp_dir.name) / "history.sqlite3"
        legacy = TransactionalLedgerManager(
            history_path,
            hmac_secret=TEST_SECRET,
        )
        legacy.append_baseline(
            record_id="baseline-001",
            target_id="sensor-001",
            execution_version="build-outbox",
            event_timestamp="2026-11-01T08:00:00Z",
            payload={"pressure_pa": 101325},
        )
        legacy.append_outcome(
            record_id="outcome-001",
            target_id="sensor-001",
            execution_version="build-outbox",
            event_timestamp="2026-11-01T08:01:00Z",
            baseline_ref="baseline-001",
            payload={"pressure_pa": 101410},
        )
        self.assertEqual(legacy.enable_remote_outbox(), 2)
        self.assertEqual(legacy.enable_remote_outbox(), 0)
        synchronizer = RemoteTrustSynchronizer(legacy, self.bridge)
        self.assertEqual(synchronizer.synchronize(), 2)
        self.assertEqual(self.stub.sequence, 2)
        self.assertEqual(legacy.verify(), 2)

    def test_lost_response_is_replayed_with_the_same_idempotency_key(self) -> None:
        self.append_baseline()
        self.stub.drop_next_post_response = True
        with self.assertRaises(IOError):
            self.synchronizer.synchronize_one()

        local_sequence, _, pending = self.ledger.get_remote_checkpoint_state()
        self.assertEqual(local_sequence, 1)
        self.assertIsNotNone(pending)
        if pending is None:
            self.fail("Expected a durable pending checkpoint.")
        self.assertEqual(pending.attempt_count, 1)

        self.assertEqual(self.synchronizer.synchronize_one(), "reconciled")
        self.assertEqual(self.stub.sequence, 1)
        self.assertEqual(self.ledger.get_remote_checkpoint_state()[2], None)

    def test_network_failure_leaves_checkpoint_pending(self) -> None:
        self.append_baseline()
        with patch.object(
            self.bridge._opener, "open", side_effect=URLError("offline")
        ):
            with self.assertRaises(IOError):
                self.synchronizer.synchronize_one()
        pending = self.ledger.get_remote_checkpoint_state()[2]
        self.assertIsNotNone(pending)
        if pending is None:
            self.fail("Expected a durable pending checkpoint.")
        self.assertEqual(pending.attempt_count, 0)
        self.assertEqual(self.stub.sequence, 0)

    def test_outbox_tampering_is_detected_by_ledger_verification(self) -> None:
        self.append_baseline()
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute(
                "UPDATE remote_checkpoint_outbox SET chain_hash = ? WHERE sequence = 1",
                ("f" * 64,),
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(IntegrityError):
            self.ledger.verify()

    def test_remote_divergence_fails_closed_and_keeps_outbox_pending(self) -> None:
        self.append_baseline()
        previous = "0" * 64
        foreign_record = hashlib.sha256(b"foreign-record").hexdigest()
        foreign_chain = _chain_hash(previous, foreign_record)
        self.bridge.post_new_chain_head(
            sequence=1,
            previous_hash=previous,
            record_hash=foreign_record,
            chain_hash=foreign_chain,
            idempotency_key="foreign-checkpoint",
        )

        with self.assertRaises(IntegrityError):
            self.synchronizer.synchronize_one()
        pending = self.ledger.get_remote_checkpoint_state()[2]
        self.assertIsNotNone(pending)
        self.assertEqual(self.stub.sequence, 1)

    def test_ledger_cannot_be_rebound_to_another_remote_target(self) -> None:
        other_bridge = RemoteTrustBridge(
            base_url=self.stub.base_url,
            token="test-token",
            target_id="different-ledger",
            trusted_public_keys=self.stub.public_keys,
        )
        with self.assertRaises(IntegrityError):
            RemoteTrustSynchronizer(self.ledger, other_bridge)

    def test_delivery_rejects_receipt_not_matching_persisted_outbox(self) -> None:
        self.append_baseline()
        pending = self.ledger.get_remote_checkpoint_state()[2]
        self.assertIsNotNone(pending)
        if pending is None:
            self.fail("Expected a durable pending checkpoint.")
        forged = VerifiedChainHead(
            key_id="test-ed25519-key",
            target_id="ledger-001",
            sequence=pending.sequence,
            chain_hash="f" * 64,
            checkpoint_id="forged-checkpoint",
            issued_at="2026-11-04T12:00:00Z",
            previous_hash=pending.previous_hash,
            record_hash=pending.record_hash,
        )
        with self.assertRaises(IntegrityError):
            self.ledger.mark_remote_checkpoint_delivered(forged)
        self.assertIsNotNone(self.ledger.get_remote_checkpoint_state()[2])

    def test_remote_outbox_is_opt_in_for_existing_ledger(self) -> None:
        disabled = TransactionalLedgerManager(
            Path(self.temp_dir.name) / "disabled.sqlite3",
            hmac_secret=TEST_SECRET,
        )
        disabled.append_baseline(
            record_id="local-only",
            target_id="sensor-local",
            execution_version="build-outbox",
            event_timestamp="2026-11-01T08:00:00Z",
            payload={"pressure_pa": 101325},
        )
        with self.assertRaises(ValueError):
            disabled.get_remote_checkpoint_state()


if __name__ == "__main__":
    unittest.main()
