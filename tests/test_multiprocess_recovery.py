"""Process-crash and concurrent remote-reconciliation regression tests."""

from __future__ import annotations

import multiprocessing
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any

from remote_trust_bridge import RemoteTrustBridge
from remote_trust_outbox import RemoteTrustSynchronizer
from remote_trust_stub import RemoteTrustStub
from transactional_ledger import TransactionalLedgerManager

TEST_SECRET = b"multiprocess-recovery-test-secret-material"


def _crash_before_sqlite_commit(database_path: str, ready: Any) -> None:
    import sqlite3

    connection = sqlite3.connect(database_path, isolation_level=None)
    connection.execute("BEGIN IMMEDIATE")
    connection.execute(
        "UPDATE ledger_meta SET head_hash = ? WHERE singleton = 1",
        ("f" * 64,),
    )
    ready.set()
    os._exit(23)


def _commit_then_crash(database_path: str) -> None:
    manager = TransactionalLedgerManager(
        Path(database_path),
        hmac_secret=TEST_SECRET,
        remote_checkpointing=True,
    )
    manager.append_baseline(
        record_id="committed-before-crash",
        target_id="sensor-crash",
        execution_version="crash-test",
        event_timestamp="2026-11-06T08:00:00Z",
        payload={"value": 1},
    )
    os._exit(0)


def _synchronize_in_process(
    database_path: str,
    base_url: str,
    public_key: bytes,
    result_queue: Any,
) -> None:
    try:
        ledger = TransactionalLedgerManager(
            Path(database_path), hmac_secret=TEST_SECRET
        )
        bridge = RemoteTrustBridge(
            base_url=base_url,
            token="test-token",
            target_id="ledger-crash-test",
            trusted_public_keys={"test-ed25519-key": public_key},
        )
        result_queue.put(
            ("ok", RemoteTrustSynchronizer(ledger, bridge).synchronize_one())
        )
    except Exception as exc:
        result_queue.put(("error", type(exc).__name__, str(exc)))


class MultiprocessRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "ledger.sqlite3"
        self.ledger = TransactionalLedgerManager(
            self.database_path,
            hmac_secret=TEST_SECRET,
            remote_checkpointing=True,
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_process_exit_before_commit_rolls_back_partial_metadata(self) -> None:
        context = multiprocessing.get_context("spawn")
        ready = context.Event()
        process = context.Process(
            target=_crash_before_sqlite_commit,
            args=(str(self.database_path), ready),
        )
        process.start()
        self.assertTrue(ready.wait(timeout=10), "Worker did not reach crash point.")
        process.join(timeout=10)
        self.assertFalse(process.is_alive(), "Crash worker did not exit.")
        self.assertEqual(process.exitcode, 23)
        self.assertEqual(self.ledger.verify(), 0)

    def test_process_exit_after_commit_preserves_complete_record(self) -> None:
        context = multiprocessing.get_context("spawn")
        process = context.Process(
            target=_commit_then_crash,
            args=(str(self.database_path),),
        )
        process.start()
        process.join(timeout=20)
        self.assertFalse(process.is_alive(), "Commit worker did not exit.")
        self.assertEqual(process.exitcode, 0)
        self.assertEqual(self.ledger.verify(), 1)
        self.ledger.bind_remote_target("ledger-crash-test")
        state = self.ledger.get_remote_checkpoint_state()
        self.assertEqual(state[0], 1)
        self.assertIsNotNone(state[2])

    def test_two_processes_can_reconcile_the_same_pending_checkpoint(self) -> None:
        self.ledger.append_baseline(
            record_id="concurrent-sync",
            target_id="sensor-sync",
            execution_version="sync-test",
            event_timestamp="2026-11-06T08:00:00Z",
            payload={"value": 2},
        )
        context = multiprocessing.get_context("spawn")
        results = context.Queue()
        with RemoteTrustStub(target_id="ledger-crash-test") as stub:
            processes = [
                context.Process(
                    target=_synchronize_in_process,
                    args=(
                        str(self.database_path),
                        stub.base_url,
                        stub.public_key_bytes,
                        results,
                    ),
                )
                for _ in range(2)
            ]
            try:
                for process in processes:
                    process.start()
                for process in processes:
                    process.join(timeout=30)
                    self.assertFalse(process.is_alive(), "Synchronizer did not exit.")
                    self.assertEqual(process.exitcode, 0)
                outcomes = [results.get(timeout=5) for _ in processes]
            finally:
                for process in processes:
                    if process.is_alive():
                        process.terminate()
                        process.join(timeout=5)

            self.assertEqual([item[0] for item in outcomes], ["ok", "ok"])
            self.assertTrue(
                all(item[1] in {"delivered", "reconciled", "in_sync"} for item in outcomes)
            )
            self.assertEqual(stub.sequence, 1)
            self.assertIsNone(self.ledger.get_remote_checkpoint_state()[2])
            self.assertEqual(self.ledger.verify(), 1)


if __name__ == "__main__":
    unittest.main()
