from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from chronological_ledger import (
    GENESIS_HASH,
    ChronologicalLedgerManager,
    DuplicateConflictError,
    IntegrityError,
    InvalidRecordError,
)


class ChronologicalLedgerIntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.ledger_path = Path(self.temporary_directory.name) / "ledger.jsonl"
        self.secret = b"test-only-hmac-secret-material-32-bytes"
        self.ledger = ChronologicalLedgerManager(
            self.ledger_path,
            hmac_secret=self.secret,
        )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def append_baseline(self) -> str:
        return self.ledger.append_baseline(
            record_id="baseline-001",
            target_id="sensor-001",
            execution_version="build-a1",
            event_timestamp="2026-10-30T08:00:00Z",
            payload={"pressure_pa": 101325, "calibration": "initial"},
        )

    @staticmethod
    def _load_json_object(line: str) -> dict[str, object]:
        value: object = json.loads(line)
        if not isinstance(value, dict):
            raise AssertionError("Expected a JSON object.")
        result: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise AssertionError("Expected string JSON keys.")
            result[key] = item
        return result

    def test_baseline_to_outcome_sequential_chain(self) -> None:
        self.assertEqual(self.append_baseline(), "appended")
        result = self.ledger.append_outcome(
            record_id="outcome-001",
            target_id="sensor-001",
            execution_version="build-a1",
            event_timestamp="2026-10-30T08:05:00Z",
            baseline_ref="baseline-001",
            payload={"pressure_pa": 101410, "status": "measured"},
        )
        self.assertEqual(result, "appended")
        self.assertEqual(self.ledger.verify(), 2)

        lines = self.ledger_path.read_text(encoding="utf-8").splitlines()
        first = self._load_json_object(lines[0])
        second = self._load_json_object(lines[1])

        self.assertEqual(first["previous_hash"], GENESIS_HASH)
        self.assertEqual(second["previous_hash"], first["chain_hash"])
        self.assertNotEqual(first["chain_hash"], second["chain_hash"])
        self.assertIsNotNone(first["signature"])
        self.assertIsNotNone(second["signature"])

        first_record = self._load_json_object(json.dumps(first["record"]))
        second_record = self._load_json_object(json.dumps(second["record"]))
        self.assertEqual(first_record["record_type"], "baseline")
        self.assertEqual(second_record["record_type"], "outcome")
        self.assertEqual(second_record["baseline_ref"], first_record["record_id"])
        self.assertEqual(
            first_record["payload"],
            {"pressure_pa": 101325, "calibration": "initial"},
        )

    def test_retroactive_timestamp_is_rejected(self) -> None:
        self.append_baseline()
        with self.assertRaises(InvalidRecordError):
            self.ledger.append_baseline(
                record_id="baseline-old",
                target_id="sensor-002",
                execution_version="build-a1",
                event_timestamp="2026-10-30T07:59:59Z",
                payload={"pressure_pa": 100000},
            )
        self.assertEqual(self.ledger.verify(), 1)

    def test_composite_key_with_mutated_payload_conflicts(self) -> None:
        self.append_baseline()
        with self.assertRaises(DuplicateConflictError):
            self.ledger.append_baseline(
                record_id="baseline-replayed-differently",
                target_id="sensor-001",
                execution_version="build-a1",
                event_timestamp="2026-10-30T08:00:00Z",
                payload={"pressure_pa": 99999, "calibration": "changed"},
            )
        self.assertEqual(self.ledger.verify(), 1)

    def test_outcome_composite_key_conflicts_on_payload_change(self) -> None:
        self.append_baseline()
        self.ledger.append_outcome(
            record_id="outcome-001",
            target_id="sensor-001",
            execution_version="build-a1",
            event_timestamp="2026-10-30T08:05:00Z",
            baseline_ref="baseline-001",
            payload={"pressure_pa": 101410},
        )
        with self.assertRaises(DuplicateConflictError):
            self.ledger.append_outcome(
                record_id="outcome-replay",
                target_id="sensor-001",
                execution_version="build-a1",
                event_timestamp="2026-10-30T08:05:00Z",
                baseline_ref="baseline-001",
                payload={"pressure_pa": 101411},
            )
        self.assertEqual(self.ledger.verify(), 2)

    def test_exact_idempotent_replay_is_skipped_with_trace(self) -> None:
        self.assertEqual(self.append_baseline(), "appended")
        with self.assertLogs("chronological_ledger", level="INFO") as captured:
            self.assertEqual(self.append_baseline(), "already_exists")
        self.assertTrue(
            any("Idempotent replay skipped" in message for message in captured.output)
        )
        self.assertEqual(self.ledger.verify(), 1)
        self.assertEqual(len(self.ledger_path.read_text().splitlines()), 1)

    def test_outcome_target_must_match_baseline(self) -> None:
        self.append_baseline()
        with self.assertRaises(InvalidRecordError):
            self.ledger.append_outcome(
                record_id="outcome-wrong-target",
                target_id="sensor-OTHER",
                execution_version="build-a1",
                event_timestamp="2026-10-30T08:05:00Z",
                baseline_ref="baseline-001",
                payload={"pressure_pa": 101400},
            )
        self.assertEqual(self.ledger.verify(), 1)

    def test_orphan_outcome_is_rejected(self) -> None:
        with self.assertRaises(InvalidRecordError):
            self.ledger.append_outcome(
                record_id="outcome-orphan",
                target_id="sensor-001",
                execution_version="build-a1",
                event_timestamp="2026-10-30T08:05:00Z",
                baseline_ref="missing-baseline",
                payload={"pressure_pa": 101400},
            )
        self.assertFalse(self.ledger_path.exists())

    def test_historical_payload_tampering_is_detected(self) -> None:
        self.append_baseline()
        original = self.ledger_path.read_text(encoding="utf-8")
        tampered = original.replace("101325", "101326")
        self.ledger_path.write_text(tampered, encoding="utf-8")
        with self.assertRaises(IntegrityError):
            self.ledger.verify()

    def test_wrong_hmac_secret_is_rejected(self) -> None:
        self.append_baseline()
        wrong_key_ledger = ChronologicalLedgerManager(
            self.ledger_path,
            hmac_secret=b"different-test-secret-material-32-bytes",
        )
        with self.assertRaises(IntegrityError):
            wrong_key_ledger.verify()

    def test_deeply_nested_duplicate_json_keys_are_rejected(self) -> None:
        malformed_line = (
            b'{"record":{"payload":{"outer":{"middle":{"inner":'
            b'{"measurement":1,"measurement":2}}}}}}\n'
        )
        self.ledger_path.write_bytes(malformed_line)
        with self.assertRaises(IntegrityError):
            self.ledger.verify()


if __name__ == "__main__":
    unittest.main()
