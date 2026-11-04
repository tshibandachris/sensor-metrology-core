"""Tests for the SQLite transactional chronological ledger."""

from __future__ import annotations

import multiprocessing
import sqlite3
import tempfile
import unittest
from pathlib import Path
from typing import Any

from chronological_ledger import (
    DuplicateConflictError,
    IntegrityError,
    InvalidRecordError,
)
from transactional_ledger import TransactionalLedgerManager

TEST_SECRET = b"transactional-ledger-test-secret-material"


def _append_from_process(
    database_path: str,
    record_id: str,
    target_id: str,
    result_queue: Any,
) -> None:
    try:
        manager = TransactionalLedgerManager(
            Path(database_path),
            hmac_secret=TEST_SECRET,
            timeout_seconds=30,
        )
        result = manager.append_baseline(
            record_id=record_id,
            target_id=target_id,
            execution_version="build-sqlite",
            event_timestamp="2026-11-01T08:00:00Z",
            payload={"pressure_pa": 101325},
        )
        result_queue.put(("ok", result))
    except Exception as exc:
        result_queue.put(("error", type(exc).__name__, str(exc)))


class TransactionalLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "ledger.sqlite3"
        self.ledger = TransactionalLedgerManager(
            self.database_path,
            hmac_secret=TEST_SECRET,
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def append_baseline(self) -> str:
        return self.ledger.append_baseline(
            record_id="baseline-001",
            target_id="sensor-001",
            execution_version="build-sqlite",
            event_timestamp="2026-11-01T08:00:00Z",
            payload={"pressure_pa": 101325},
        )

    def test_baseline_outcome_chain_and_external_head(self) -> None:
        self.assertEqual(self.append_baseline(), "appended")
        self.assertEqual(
            self.ledger.append_outcome(
                record_id="outcome-001",
                target_id="sensor-001",
                execution_version="build-sqlite",
                event_timestamp="2026-11-01T08:01:00Z",
                baseline_ref="baseline-001",
                payload={"pressure_pa": 101410},
            ),
            "appended",
        )
        self.assertEqual(self.ledger.verify(), 2)

        connection = sqlite3.connect(self.database_path)
        try:
            row = connection.execute(
                "SELECT head_hash FROM ledger_meta WHERE singleton = 1"
            ).fetchone()
        finally:
            connection.close()
        if row is None or not isinstance(row[0], str):
            raise AssertionError("Expected a string chain head in ledger metadata.")
        self.assertEqual(self.ledger.verify(expected_head_hash=row[0]), 2)
        with self.assertRaises(IntegrityError):
            self.ledger.verify(expected_head_hash="0" * 64)

    def test_exact_replay_is_idempotent(self) -> None:
        self.assertEqual(self.append_baseline(), "appended")
        self.assertEqual(self.append_baseline(), "already_exists")
        self.assertEqual(self.ledger.verify(), 1)

    def test_conflicting_replay_is_rejected(self) -> None:
        self.append_baseline()
        with self.assertRaises(DuplicateConflictError):
            self.ledger.append_baseline(
                record_id="baseline-replay",
                target_id="sensor-001",
                execution_version="build-sqlite",
                event_timestamp="2026-11-01T08:00:00Z",
                payload={"pressure_pa": 99999},
            )
        self.assertEqual(self.ledger.verify(), 1)

    def test_outcome_requires_existing_matching_baseline(self) -> None:
        with self.assertRaises(InvalidRecordError):
            self.ledger.append_outcome(
                record_id="outcome-orphan",
                target_id="sensor-001",
                execution_version="build-sqlite",
                event_timestamp="2026-11-01T08:01:00Z",
                baseline_ref="missing",
                payload={"pressure_pa": 101400},
            )
        self.assertEqual(self.ledger.verify(), 0)

        self.append_baseline()
        with self.assertRaises(InvalidRecordError):
            self.ledger.append_outcome(
                record_id="outcome-wrong-target",
                target_id="sensor-002",
                execution_version="build-sqlite",
                event_timestamp="2026-11-01T08:01:00Z",
                baseline_ref="baseline-001",
                payload={"pressure_pa": 101400},
            )
        self.assertEqual(self.ledger.verify(), 1)

    def test_retroactive_timestamp_is_rejected(self) -> None:
        self.append_baseline()
        with self.assertRaises(InvalidRecordError):
            self.ledger.append_baseline(
                record_id="baseline-old",
                target_id="sensor-002",
                execution_version="build-sqlite",
                event_timestamp="2026-11-01T07:59:59Z",
                payload={"pressure_pa": 100000},
            )
        self.assertEqual(self.ledger.verify(), 1)

    def test_record_rows_are_append_only_through_sql_api(self) -> None:
        self.append_baseline()
        connection = sqlite3.connect(self.database_path)
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "UPDATE ledger_records SET target_id = 'changed' "
                    "WHERE record_id = 'baseline-001'"
                )
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "DELETE FROM ledger_records WHERE record_id = 'baseline-001'"
                )
        finally:
            connection.close()
        self.assertEqual(self.ledger.verify(), 1)

    def test_integrity_verification_detects_direct_database_tampering(self) -> None:
        self.append_baseline()
        connection = sqlite3.connect(self.database_path)
        try:
            connection.execute("DROP TRIGGER ledger_records_no_update")
            connection.execute(
                "UPDATE ledger_records SET record_json = '{}' "
                "WHERE record_id = 'baseline-001'"
            )
        finally:
            connection.close()
        with self.assertRaises(IntegrityError):
            self.ledger.verify()

    def test_multiprocess_writers_are_serialized_transactionally(self) -> None:
        context = multiprocessing.get_context("spawn")
        results = context.Queue()
        processes = [
            context.Process(
                target=_append_from_process,
                args=(
                    str(self.database_path),
                    f"baseline-process-{index}",
                    f"sensor-process-{index}",
                    results,
                ),
            )
            for index in range(2)
        ]

        try:
            for process in processes:
                process.start()
            for process in processes:
                process.join(timeout=30)
                self.assertFalse(process.is_alive(), "Worker process did not exit.")
                self.assertEqual(process.exitcode, 0)

            outcomes = [results.get(timeout=5) for _ in processes]
            self.assertEqual([item[0] for item in outcomes], ["ok", "ok"])
            self.assertEqual(self.ledger.verify(), 2)
        finally:
            for process in processes:
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
