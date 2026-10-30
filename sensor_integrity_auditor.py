#!/usr/bin/env python3
"""Validate JSONL physical pressure readings and atomically write a report."""

from __future__ import annotations

import argparse
import json
import math
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class DuplicateKeyError(ValueError):
    """Raised when a JSON object contains a duplicate key."""


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate keys instead of silently keeping the last value."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_nonstandard_constant(value: str) -> None:
    """Reject NaN and Infinity tokens, which are not standard JSON numbers."""
    raise ValueError(f"Non-standard JSON numeric constant: {value}")


def validate_record(record: Any) -> list[str]:
    """Return validation errors for one physical sensor reading."""
    if not isinstance(record, dict):
        return ["Record must be a JSON object"]

    errors: list[str] = []
    sensor_id = record.get("sensor_id")
    if not isinstance(sensor_id, str) or not sensor_id.strip():
        errors.append("sensor_id must be a non-empty string")

    pressure = record.get("pressure_pa")
    if isinstance(pressure, bool) or not isinstance(pressure, (int, float)):
        errors.append("pressure_pa must be a number")
    elif not math.isfinite(pressure):
        errors.append("pressure_pa must be finite")
    elif pressure < 0:
        errors.append("pressure_pa must be non-negative")

    return errors


def audit_jsonl(input_path: Path) -> dict[str, Any]:
    """Audit a JSON Lines file and return a report."""
    accepted = 0
    rejected = 0
    rejection_details: list[dict[str, Any]] = []

    with input_path.open("r", encoding="utf-8") as source:
        for line_number, raw_line in enumerate(source, start=1):
            if not raw_line.strip():
                continue

            try:
                record = json.loads(
                    raw_line,
                    object_pairs_hook=reject_duplicate_keys,
                    parse_constant=reject_nonstandard_constant,
                )
                errors = validate_record(record)
            except (json.JSONDecodeError, DuplicateKeyError, ValueError) as exc:
                errors = [f"Invalid JSON record: {exc}"]

            if errors:
                rejected += 1
                rejection_details.append(
                    {"line": line_number, "errors": errors}
                )
            else:
                accepted += 1

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_file": str(input_path),
        "records_accepted": accepted,
        "records_rejected": rejected,
        "records_processed": accepted + rejected,
        "rejections": rejection_details,
    }


def atomic_write_json(destination: Path, payload: dict[str, Any]) -> None:
    """Persist JSON using a same-directory temporary file and atomic replace."""
    destination = destination.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None

    try:
        fd, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=destination.parent,
        )
        temporary_path = Path(temporary_name)

        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(
                payload,
                stream,
                ensure_ascii=False,
                indent=2,
                allow_nan=False,
            )
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())

        os.replace(temporary_path, destination)
        temporary_path = None

        # Persist the directory entry where directory fsync is supported.
        if os.name == "posix":
            directory_fd = os.open(destination.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit JSONL physical pressure sensor readings."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("data/sensor_readings.jsonl"),
        help="Input JSONL file.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("reports/sensor_integrity_report.json"),
        help="Output JSON report.",
    )
    args = parser.parse_args()

    try:
        report = audit_jsonl(args.input)
        atomic_write_json(args.output, report)
    except (OSError, TypeError, ValueError) as exc:
        parser.exit(1, f"Audit failed: {exc}\n")

    print(
        f"Audit complete: {report['records_accepted']} accepted, "
        f"{report['records_rejected']} rejected."
    )
    print(f"Report: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
