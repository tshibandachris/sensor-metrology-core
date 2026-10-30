#!/usr/bin/env python3
"""Append-only, single-writer chronological JSONL ledger.

The ledger is a tamper-evident stream, not a transactional database. Appends
are serialized with an advisory operating-system process lock.
Keep HMAC keys outside the repository and ledger directory.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Literal, TypeAlias


JsonValue: TypeAlias = (
    str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
)
JsonObject: TypeAlias = dict[str, JsonValue]
RecordKind: TypeAlias = Literal["baseline", "outcome"]

GENESIS_HASH = "0" * 64
SCHEMA_VERSION = 1
BASELINE_INDEX = "b_target_version_timestamp"
OUTCOME_INDEX = "o_baselineref_version_timestamp"


class LedgerError(Exception):
    """Base exception for chronological ledger failures."""


class InvalidRecordError(LedgerError):
    """A proposed record violates the ledger contract."""


class IntegrityError(LedgerError):
    """An existing ledger record or chain failed verification."""


class DuplicateConflictError(LedgerError):
    """A unique key or record identifier conflicts with existing content."""


class DuplicateJsonKeyError(ValueError):
    """A JSON object contains a repeated key."""


def _reject_duplicate_json_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    """Reject duplicate keys at every JSON object depth."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKeyError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    """Reject NaN and Infinity, which are not valid JSON numbers."""
    raise ValueError(f"Non-standard JSON numeric constant: {value}")


def _validate_json_value(value: Any, location: str = "payload") -> None:
    """Validate strict JSON-compatible values without coercing Python objects."""
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise InvalidRecordError(
                f"{location} contains a non-finite floating-point value."
            )
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_value(item, f"{location}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise InvalidRecordError(
                    f"{location} contains a non-string object key."
                )
            _validate_json_value(item, f"{location}.{key}")
        return
    raise InvalidRecordError(
        f"{location} contains unsupported type {type(value).__name__}."
    )


def _canonical_json(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON bytes."""
    try:
        text = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise InvalidRecordError(f"Value is not canonical JSON: {exc}") from exc
    return text.encode("utf-8")


def _parse_utc_timestamp(value: str) -> datetime:
    """Parse a strict UTC ISO-8601 timestamp ending in Z."""
    if not isinstance(value, str) or not value.endswith("Z"):
        raise InvalidRecordError(
            "event_timestamp must be an ISO-8601 UTC string ending in Z."
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise InvalidRecordError(
            f"Invalid ISO-8601 event_timestamp: {value}"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise InvalidRecordError("event_timestamp must represent UTC.")
    return parsed.astimezone(timezone.utc)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class ChronologicalLedgerManager:
    """Manage a verifiable append-only JSONL ledger with one active writer.

    Baseline uniqueness:
        (target_id, execution_version, event_timestamp)

    Outcome uniqueness:
        (baseline_ref, execution_version, event_timestamp)

    A replay with the same composite key and same business payload is skipped.
    Reusing a composite key with different business payload raises
    DuplicateConflictError. Record identifiers are globally unique.

    The class deliberately does not claim multi-process locking. The caller
    must guarantee that only one process writes to a given ledger at a time.
    """

    def __init__(
        self,
        ledger_path: Path,
        hmac_secret: bytes | None = None,
    ) -> None:
        if hmac_secret is not None and len(hmac_secret) < 32:
            raise ValueError("hmac_secret must contain at least 32 bytes.")
        self.ledger_path = ledger_path
        self._hmac_secret = hmac_secret

    @staticmethod
    def _record_hash(record: JsonObject) -> str:
        return _sha256_hex(_canonical_json(record))

    @staticmethod
    def _chain_hash(previous_hash: str, record_hash: str) -> str:
        material = f"{previous_hash}:{record_hash}".encode("ascii")
        return _sha256_hex(material)

    def _signature(self, chain_hash: str) -> str | None:
        if self._hmac_secret is None:
            return None
        return hmac.new(
            self._hmac_secret,
            chain_hash.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def _composite_index(
        record: dict[str, Any],
    ) -> tuple[str, tuple[str, str, str]]:
        kind = record["record_type"]
        version = record["execution_version"]
        timestamp = record["event_timestamp"]
        if kind == "baseline":
            return (
                BASELINE_INDEX,
                (record["target_id"], version, timestamp),
            )
        return (
            OUTCOME_INDEX,
            (record["baseline_ref"], version, timestamp),
        )

    @staticmethod
    def _validate_non_empty_string(value: Any, field: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise InvalidRecordError(f"{field} must be a non-empty string.")
        return value

    def _load_verified(
        self,
    ) -> tuple[
        list[dict[str, Any]],
        dict[tuple[str, tuple[str, str, str]], dict[str, Any]],
        dict[str, dict[str, Any]],
        datetime | None,
        str,
    ]:
        records: list[dict[str, Any]] = []
        composite_index: dict[
            tuple[str, tuple[str, str, str]], dict[str, Any]
        ] = {}
        baselines: dict[str, dict[str, Any]] = {}
        record_ids: set[str] = set()
        previous_hash = GENESIS_HASH
        last_timestamp: datetime | None = None

        if not self.ledger_path.exists():
            return records, composite_index, baselines, last_timestamp, previous_hash

        try:
            stream = self.ledger_path.open("rb")
        except OSError:
            raise

        with stream:
            for line_number, raw_line in enumerate(stream, start=1):
                if not raw_line.endswith(b"\n"):
                    raise IntegrityError(
                        f"Incomplete JSONL line at line {line_number}."
                    )
                try:
                    envelope = json.loads(
                        raw_line.decode("utf-8"),
                        object_pairs_hook=_reject_duplicate_json_keys,
                        parse_constant=_reject_json_constant,
                    )
                except (
                    UnicodeDecodeError,
                    json.JSONDecodeError,
                    DuplicateJsonKeyError,
                    ValueError,
                ) as exc:
                    raise IntegrityError(
                        f"Invalid JSON at line {line_number}: {exc}"
                    ) from exc

                if not isinstance(envelope, dict):
                    raise IntegrityError(
                        f"Envelope at line {line_number} is not an object."
                    )
                record = envelope.get("record")
                if not isinstance(record, dict):
                    raise IntegrityError(
                        f"Missing record object at line {line_number}."
                    )

                expected_record_hash = self._record_hash(record)
                stored_record_hash = envelope.get("record_hash")
                if not isinstance(stored_record_hash, str) or not hmac.compare_digest(
                    stored_record_hash, expected_record_hash
                ):
                    raise IntegrityError(
                        f"Record hash mismatch at line {line_number}."
                    )

                stored_previous_hash = envelope.get("previous_hash")
                if stored_previous_hash != previous_hash:
                    raise IntegrityError(
                        f"Previous hash mismatch at line {line_number}."
                    )

                expected_chain_hash = self._chain_hash(
                    previous_hash, expected_record_hash
                )
                stored_chain_hash = envelope.get("chain_hash")
                if not isinstance(stored_chain_hash, str) or not hmac.compare_digest(
                    stored_chain_hash, expected_chain_hash
                ):
                    raise IntegrityError(
                        f"Chain hash mismatch at line {line_number}."
                    )

                if self._hmac_secret is not None:
                    expected_signature = self._signature(expected_chain_hash)
                    stored_signature = envelope.get("signature")
                    if (
                        not isinstance(stored_signature, str)
                        or expected_signature is None
                        or not hmac.compare_digest(
                            stored_signature, expected_signature
                        )
                    ):
                        raise IntegrityError(
                            f"HMAC signature mismatch at line {line_number}."
                        )

                if record.get("schema_version") != SCHEMA_VERSION:
                    raise IntegrityError(
                        f"Unsupported schema version at line {line_number}."
                    )

                kind = record.get("record_type")
                if kind not in ("baseline", "outcome"):
                    raise IntegrityError(
                        f"Invalid record_type at line {line_number}."
                    )

                try:
                    record_id = self._validate_non_empty_string(
                        record.get("record_id"), "record_id"
                    )
                    target_id = self._validate_non_empty_string(
                        record.get("target_id"), "target_id"
                    )
                    version = self._validate_non_empty_string(
                        record.get("execution_version"), "execution_version"
                    )
                    timestamp_text = self._validate_non_empty_string(
                        record.get("event_timestamp"), "event_timestamp"
                    )
                    timestamp = _parse_utc_timestamp(timestamp_text)
                except InvalidRecordError as exc:
                    raise IntegrityError(
                        f"Invalid record fields at line {line_number}: {exc}"
                    ) from exc

                payload = record.get("payload")
                if not isinstance(payload, dict):
                    raise IntegrityError(
                        f"Payload must be an object at line {line_number}."
                    )
                try:
                    _validate_json_value(payload)
                except InvalidRecordError as exc:
                    raise IntegrityError(
                        f"Invalid payload at line {line_number}: {exc}"
                    ) from exc

                if last_timestamp is not None and timestamp < last_timestamp:
                    raise IntegrityError(
                        f"Retroactive timestamp in existing ledger at line {line_number}."
                    )

                if record_id in record_ids:
                    raise IntegrityError(
                        f"Duplicate record_id at line {line_number}."
                    )

                if kind == "baseline":
                    if record.get("baseline_ref") is not None:
                        raise IntegrityError(
                            f"Baseline cannot contain baseline_ref at line {line_number}."
                        )
                else:
                    baseline_ref = record.get("baseline_ref")
                    if not isinstance(baseline_ref, str) or baseline_ref not in baselines:
                        raise IntegrityError(
                            f"Orphan outcome at line {line_number}: "
                            "baseline_ref is not a previously verified baseline."
                        )
                    if baselines[baseline_ref].get("target_id") != target_id:
                        raise IntegrityError(
                            f"Outcome target does not match its baseline at line {line_number}."
                        )

                index_key = self._composite_index(record)
                if index_key in composite_index:
                    raise IntegrityError(
                        f"Duplicate composite index at line {line_number}."
                    )

                composite_index[index_key] = envelope
                if kind == "baseline":
                    baselines[record_id] = record
                record_ids.add(record_id)
                records.append(envelope)
                previous_hash = expected_chain_hash
                last_timestamp = timestamp

        return records, composite_index, baselines, last_timestamp, previous_hash


    @contextmanager
    def _writer_lock(self) -> Iterator[None]:
        """Acquire an advisory process lock for the complete append transaction."""
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.ledger_path.with_name(
            self.ledger_path.name + ".writer.lock"
        )
        with lock_path.open("a+b") as lock_stream:
            if os.name == "nt":
                import msvcrt

                lock_stream.seek(0, os.SEEK_END)
                if lock_stream.tell() == 0:
                    lock_stream.write(b"\0")
                    lock_stream.flush()
                lock_stream.seek(0)
                msvcrt.locking(lock_stream.fileno(), msvcrt.LK_LOCK, 1)
                try:
                    yield
                finally:
                    lock_stream.seek(0)
                    msvcrt.locking(lock_stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(lock_stream.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(lock_stream.fileno(), fcntl.LOCK_UN)

    def verify(self) -> int:
        """Verify every line, hash link, timestamp, index, and baseline reference."""
        records, _, _, _, _ = self._load_verified()
        return len(records)

    def append_baseline(
        self,
        *,
        record_id: str,
        target_id: str,
        execution_version: str,
        event_timestamp: str,
        payload: JsonObject,
    ) -> Literal["appended", "already_exists"]:
        """Append an immutable initial-state snapshot."""
        return self._append(
            record_type="baseline",
            record_id=record_id,
            target_id=target_id,
            execution_version=execution_version,
            event_timestamp=event_timestamp,
            payload=payload,
            baseline_ref=None,
        )

    def append_outcome(
        self,
        *,
        record_id: str,
        target_id: str,
        execution_version: str,
        event_timestamp: str,
        baseline_ref: str,
        payload: JsonObject,
    ) -> Literal["appended", "already_exists"]:
        """Append outcome metrics linked to an existing verified baseline."""
        return self._append(
            record_type="outcome",
            record_id=record_id,
            target_id=target_id,
            execution_version=execution_version,
            event_timestamp=event_timestamp,
            payload=payload,
            baseline_ref=baseline_ref,
        )

    def _append(
        self,
        *,
        record_type: RecordKind,
        record_id: str,
        target_id: str,
        execution_version: str,
        event_timestamp: str,
        payload: JsonObject,
        baseline_ref: str | None,
    ) -> Literal["appended", "already_exists"]:
        record_id = self._validate_non_empty_string(record_id, "record_id")
        target_id = self._validate_non_empty_string(target_id, "target_id")
        execution_version = self._validate_non_empty_string(
            execution_version, "execution_version"
        )
        timestamp = _parse_utc_timestamp(event_timestamp)
        _validate_json_value(payload)

        if record_type == "baseline" and baseline_ref is not None:
            raise InvalidRecordError("A baseline cannot reference another baseline.")
        if record_type == "outcome":
            baseline_ref = self._validate_non_empty_string(
                baseline_ref, "baseline_ref"
            )

        with self._writer_lock():
            (
                existing_records,
                composite_index,
                baselines,
                last_timestamp,
                previous_hash,
            ) = self._load_verified()

            if record_type == "outcome":
                if baseline_ref not in baselines:
                    raise InvalidRecordError(
                        "Outcome rejected: baseline_ref does not identify a "
                        "previously verified baseline."
                    )
                if baselines[baseline_ref].get("target_id") != target_id:
                    raise InvalidRecordError(
                        "Outcome target_id must match the referenced baseline."
                    )

            record: dict[str, Any] = {
                "schema_version": SCHEMA_VERSION,
                "record_type": record_type,
                "record_id": record_id,
                "target_id": target_id,
                "execution_version": execution_version,
                "event_timestamp": event_timestamp,
                "baseline_ref": baseline_ref,
                "payload": payload,
            }
            index_key = self._composite_index(record)
            existing = composite_index.get(index_key)

            if existing is not None:
                existing_record = existing["record"]
                if existing_record.get("payload") == payload:
                    return "already_exists"
                raise DuplicateConflictError(
                    f"Composite key {index_key[0]} already exists with "
                    "different business payload."
                )

            existing_ids = {
                item["record"]["record_id"] for item in existing_records
            }
            if record_id in existing_ids:
                raise DuplicateConflictError(
                    f"record_id {record_id!r} has already been used."
                )

            if last_timestamp is not None and timestamp < last_timestamp:
                raise InvalidRecordError(
                    "Retroactive append rejected: event_timestamp is older "
                    "than the latest ledger timestamp."
                )

            record_hash = self._record_hash(record)
            chain_hash = self._chain_hash(previous_hash, record_hash)
            envelope: dict[str, Any] = {
                "record": record,
                "record_hash": record_hash,
                "previous_hash": previous_hash,
                "chain_hash": chain_hash,
                "signature": self._signature(chain_hash),
            }
            encoded_line = _canonical_json(envelope) + b"\n"

            self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
            # The advisory lock serializes cooperating writers on this host.
            with self.ledger_path.open("ab") as stream:
                stream.write(encoded_line)
                stream.flush()
                os.fsync(stream.fileno())

            return "appended"
