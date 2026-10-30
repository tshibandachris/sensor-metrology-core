import json
import math
import tempfile
import unittest
from pathlib import Path

from sensor_integrity_auditor import (
    DuplicateKeyError,
    atomic_write_json,
    audit_jsonl,
    reject_duplicate_keys,
    validate_record,
)


class SensorValidationTests(unittest.TestCase):
    def test_valid_record(self):
        self.assertEqual(
            validate_record(
                {"sensor_id": "PRESSURE-001", "pressure_pa": 101325}
            ),
            [],
        )

    def test_empty_sensor_id(self):
        errors = validate_record({"sensor_id": "  ", "pressure_pa": 101325})
        self.assertTrue(any("sensor_id" in error for error in errors))

    def test_boolean_pressure_is_rejected(self):
        errors = validate_record({"sensor_id": "S1", "pressure_pa": True})
        self.assertTrue(any("number" in error for error in errors))

    def test_string_pressure_is_rejected(self):
        errors = validate_record({"sensor_id": "S1", "pressure_pa": "101325"})
        self.assertTrue(any("number" in error for error in errors))

    def test_negative_pressure_is_rejected(self):
        errors = validate_record({"sensor_id": "S1", "pressure_pa": -1})
        self.assertTrue(any("non-negative" in error for error in errors))

    def test_non_finite_pressure_is_rejected(self):
        for value in (math.nan, math.inf, -math.inf):
            with self.subTest(value=value):
                errors = validate_record({"sensor_id": "S1", "pressure_pa": value})
                self.assertTrue(any("finite" in error for error in errors))

    def test_non_object_record_is_rejected(self):
        self.assertTrue(validate_record(["not", "an", "object"]))


class JsonIntegrityTests(unittest.TestCase):
    def test_duplicate_key_is_rejected(self):
        with self.assertRaises(DuplicateKeyError):
            json.loads(
                '{"sensor_id":"S1","pressure_pa":10,"pressure_pa":20}',
                object_pairs_hook=reject_duplicate_keys,
            )

    def test_nested_duplicate_key_is_rejected(self):
        with self.assertRaises(DuplicateKeyError):
            json.loads(
                '{"outer":{"value":1,"value":2}}',
                object_pairs_hook=reject_duplicate_keys,
            )

    def test_blank_lines_are_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "readings.jsonl"
            source.write_text(
                '\n{"sensor_id":"S1","pressure_pa":100}\n\n',
                encoding="utf-8",
            )
            report = audit_jsonl(source)
            self.assertEqual(report["records_accepted"], 1)
            self.assertEqual(report["records_rejected"], 0)

    def test_invalid_json_is_counted_as_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "readings.jsonl"
            source.write_text('{"sensor_id":\n', encoding="utf-8")
            report = audit_jsonl(source)
            self.assertEqual(report["records_rejected"], 1)
            self.assertEqual(report["rejections"][0]["line"], 1)

    def test_duplicate_json_key_is_counted_as_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "readings.jsonl"
            source.write_text(
                '{"sensor_id":"S1","pressure_pa":10,'
                '"pressure_pa":20}\n',
                encoding="utf-8",
            )
            report = audit_jsonl(source)
            self.assertEqual(report["records_rejected"], 1)

    def test_nonstandard_json_constant_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "readings.jsonl"
            source.write_text(
                '{"sensor_id":"S1","pressure_pa":NaN}\n',
                encoding="utf-8",
            )
            report = audit_jsonl(source)
            self.assertEqual(report["records_rejected"], 1)


class AtomicWriteTests(unittest.TestCase):
    def test_atomic_write_creates_valid_json(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "report.json"
            payload = {"records_accepted": 3}
            atomic_write_json(destination, payload)
            self.assertEqual(
                json.loads(destination.read_text(encoding="utf-8")),
                payload,
            )

    def test_existing_file_is_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "report.json"
            destination.write_text('{"old": true}', encoding="utf-8")
            atomic_write_json(destination, {"new": True})
            self.assertEqual(
                json.loads(destination.read_text(encoding="utf-8")),
                {"new": True},
            )

    def test_non_serializable_payload_preserves_old_file(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "report.json"
            destination.write_text('{"stable": true}', encoding="utf-8")

            with self.assertRaises(TypeError):
                atomic_write_json(destination, {"bad": object()})

            self.assertEqual(
                json.loads(destination.read_text(encoding="utf-8")),
                {"stable": True},
            )
            self.assertEqual(
                list(destination.parent.glob("*.tmp")),
                [],
            )

    def test_non_finite_json_payload_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "report.json"
            with self.assertRaises(ValueError):
                atomic_write_json(destination, {"value": math.nan})
            self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
