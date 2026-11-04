from __future__ import annotations

import hashlib
import hmac
import json
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator
from unittest.mock import patch

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


    def test_reordering_records_is_detected(self) -> None:
        self.append_baseline()
        self.ledger.append_baseline(
            record_id="baseline-002",
            target_id="sensor-002",
            execution_version="build-a1",
            event_timestamp="2026-10-30T08:01:00Z",
            payload={"pressure_pa": 100900},
        )
        lines = self.ledger_path.read_bytes().splitlines(keepends=True)
        self.ledger_path.write_bytes(lines[1] + lines[0])
        with self.assertRaises(IntegrityError):
            self.ledger.verify()

    def test_removing_an_interior_record_is_detected(self) -> None:
        self.append_baseline()
        self.ledger.append_baseline(
            record_id="baseline-002",
            target_id="sensor-002",
            execution_version="build-a1",
            event_timestamp="2026-10-30T08:01:00Z",
            payload={"pressure_pa": 100900},
        )
        self.ledger.append_baseline(
            record_id="baseline-003",
            target_id="sensor-003",
            execution_version="build-a1",
            event_timestamp="2026-10-30T08:02:00Z",
            payload={"pressure_pa": 100800},
        )
        lines = self.ledger_path.read_bytes().splitlines(keepends=True)
        self.ledger_path.write_bytes(lines[0] + lines[2])
        with self.assertRaises(IntegrityError):
            self.ledger.verify()

    def test_incomplete_final_jsonl_line_is_rejected(self) -> None:
        self.append_baseline()
        with self.ledger_path.open("ab") as stream:
            stream.write(b'{"record":')
        with self.assertRaises(IntegrityError):
            self.ledger.verify()

    def test_record_id_cannot_be_reused_for_another_composite_key(self) -> None:
        self.append_baseline()
        with self.assertRaises(DuplicateConflictError):
            self.ledger.append_baseline(
                record_id="baseline-001",
                target_id="sensor-002",
                execution_version="build-a1",
                event_timestamp="2026-10-30T08:01:00Z",
                payload={"pressure_pa": 100900},
            )
        self.assertEqual(self.ledger.verify(), 1)

    def test_concurrent_append_prevention(self) -> None:
        original_lock = self.ledger._writer_lock

        @contextmanager
        def mutate_after_lock() -> Iterator[None]:
            with original_lock():
                self.ledger_path.write_bytes(b'{"out_of_band":true}\n')
                yield

        with patch.object(self.ledger, "_writer_lock", mutate_after_lock):
            with self.assertRaises(IntegrityError):
                self.ledger.append_baseline(
                    record_id="baseline-raced",
                    target_id="sensor-raced",
                    execution_version="build-a1",
                    event_timestamp="2026-10-30T08:00:00Z",
                    payload={"pressure_pa": 101325},
                )

    def test_tamper_detection_via_detached_checkpoint(self) -> None:
        self.append_baseline()
        checkpoint_path = (
            self.ledger_path.parent / "reports" / "ledger_checkpoint.sha256"
        )
        original_checkpoint = checkpoint_path.read_text(encoding="ascii").strip()
        envelope = self._load_json_object(
            self.ledger_path.read_text(encoding="utf-8").strip()
        )
        record = self._load_json_object(json.dumps(envelope["record"]))
        payload = self._load_json_object(json.dumps(record["payload"]))
        payload["pressure_pa"] = 999999
        record["payload"] = payload

        canonical_record = json.dumps(
            record,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        record_hash = hashlib.sha256(canonical_record).hexdigest()
        chain_hash = hashlib.sha256(
            f"{GENESIS_HASH}:{record_hash}".encode("ascii")
        ).hexdigest()
        signature = hmac.new(
            self.secret, chain_hash.encode("ascii"), hashlib.sha256
        ).hexdigest()
        rewritten_envelope = {
            "record": record,
            "record_hash": record_hash,
            "previous_hash": GENESIS_HASH,
            "chain_hash": chain_hash,
            "signature": signature,
        }
        rewritten_line = json.dumps(
            rewritten_envelope,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        self.ledger_path.write_text(rewritten_line + "\n", encoding="utf-8")

        self.assertNotEqual(chain_hash, original_checkpoint)

        # Simulate an actor with write access to the complete local workspace:
        # rewrite both the ledger and its colocated checkpoint to agree with
        # the forged chain. The remote expected head remains unchanged.
        checkpoint_path.write_text(chain_hash + "\n", encoding="ascii")
        self.assertEqual(
            checkpoint_path.read_text(encoding="ascii").strip(),
            chain_hash,
        )
        with self.assertRaises(IntegrityError):
            self.ledger.verify(expected_head_hash=original_checkpoint)

    def test_verification_via_explicit_head_hash(self) -> None:
        self.append_baseline()
        envelope = self._load_json_object(
            self.ledger_path.read_text(encoding="utf-8").strip()
        )
        expected_head = envelope.get("chain_hash")
        if not isinstance(expected_head, str):
            self.fail("Expected a string chain hash in the ledger envelope.")
        self.assertEqual(
            self.ledger.verify(expected_head_hash=expected_head),
            1,
        )
        with self.assertRaises(IntegrityError):
            self.ledger.verify(expected_head_hash=GENESIS_HASH)


if __name__ == "__main__":
    unittest.main()
