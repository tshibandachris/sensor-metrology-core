#!/usr/bin/env python3
"""Append-only, single-writer chronological JSONL ledger."""

from __future__ import annotations

import hashlib
import hmac
import importlib
import json
import logging
import math
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Literal, Protocol, TypeAlias, cast

JsonValue: TypeAlias = (
    str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
)
JsonObject: TypeAlias = dict[str, JsonValue]
RecordKind: TypeAlias = Literal["baseline", "outcome"]

LOGGER = logging.getLogger(__name__)
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


class WindowsLockable(Protocol):
    """Minimal interface required from the Windows msvcrt module."""

    LK_LOCK: int
    LK_UNLCK: int

    def locking(self, fd: int, mode: int, nbytes: int) -> None:
        """Lock or unlock a byte range in an open file descriptor."""


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate keys at every JSON object depth."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKeyError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    """Reject NaN and Infinity, which are not valid JSON numbers."""
    raise ValueError(f"Non-standard JSON numeric constant: {value}")


def assert_json_object(val: object) -> JsonObject:
    """Recursively validate and rebuild a strict JSON object.

    Booleans are valid JSON values, but are never accepted as integer schema
    discriminators by the ledger's record validation.
    """
    if not isinstance(val, dict):
        raise InvalidRecordError("JSON envelope or record must be an object.")

    result: JsonObject = {}
    for key in val:
        if not isinstance(key, str):
            raise InvalidRecordError("JSON objects must have string keys.")
        raw_value: object = val[key]
        result[key] = _assert_json_value(raw_value, key)
    return result


def _assert_json_value(value: object, location: str) -> JsonValue:
    """Validate one JSON value recursively and return a typed copy."""
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise InvalidRecordError(
                f"{location} contains a non-finite floating-point value."
            )
        return value
    if isinstance(value, list):
        result: list[JsonValue] = []
        for index in range(len(value)):
            item: object = value[index]
            result.append(_assert_json_value(item, f"{location}[{index}]"))
        return result
    if isinstance(value, dict):
        result_object: JsonObject = {}
        for key in value:
            if not isinstance(key, str):
                raise InvalidRecordError(
                    f"{location} contains a non-string object key."
                )
            item: object = value[key]
            result_object[key] = _assert_json_value(item, f"{location}.{key}")
        return result_object
    raise InvalidRecordError(
        f"{location} contains unsupported type {type(value).__name__}."
    )


def _canonical_json(value: JsonValue) -> bytes:
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
    if not value.endswith("Z"):
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
    """Manage a verifiable append-only JSONL ledger with one active writer."""

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
        return _sha256_hex(f"{previous_hash}:{record_hash}".encode("ascii"))

    def _signature(self, chain_hash: str) -> str | None:
        if self._hmac_secret is None:
            return None
        return hmac.new(
            self._hmac_secret, chain_hash.encode("ascii"), hashlib.sha256
        ).hexdigest()

    @staticmethod
    def _required_string(record: JsonObject, field: str) -> str:
        value = record.get(field)
        if not isinstance(value, str) or not value.strip():
            raise InvalidRecordError(f"{field} must be a non-empty string.")
        return value

    @classmethod
    def _composite_index(
        cls, record: JsonObject
    ) -> tuple[str, tuple[str, str, str]]:
        kind = record.get("record_type")
        version = cls._required_string(record, "execution_version")
        timestamp = cls._required_string(record, "event_timestamp")
        if kind == "baseline":
            target_id = cls._required_string(record, "target_id")
            return BASELINE_INDEX, (target_id, version, timestamp)
        if kind == "outcome":
            baseline_ref = cls._required_string(record, "baseline_ref")
            return OUTCOME_INDEX, (baseline_ref, version, timestamp)
        raise InvalidRecordError("record_type must be baseline or outcome.")

    def _load_verified(
        self,
    ) -> tuple[
        list[JsonObject],
        dict[tuple[str, tuple[str, str, str]], JsonObject],
        dict[str, JsonObject],
        datetime | None,
        str,
    ]:
        records: list[JsonObject] = []
        composite_index: dict[tuple[str, tuple[str, str, str]], JsonObject] = {}
        baselines: dict[str, JsonObject] = {}
        record_ids: set[str] = set()
        previous_hash = GENESIS_HASH
        last_timestamp: datetime | None = None

        if not self.ledger_path.exists():
            return records, composite_index, baselines, last_timestamp, previous_hash

        with self.ledger_path.open("rb") as stream:
            for line_number, raw_line in enumerate(stream, start=1):
                if not raw_line.endswith(b"\n"):
                    raise IntegrityError(
                        f"Incomplete JSONL line at line {line_number}."
                    )
                try:
                    decoded: object = json.loads(
                        raw_line.decode("utf-8"),
                        object_pairs_hook=_reject_duplicate_json_keys,
                        parse_constant=_reject_json_constant,
                    )
                    envelope = assert_json_object(decoded)
                except (
                    UnicodeDecodeError,
                    json.JSONDecodeError,
                    DuplicateJsonKeyError,
                    InvalidRecordError,
                    ValueError,
                ) as exc:
                    raise IntegrityError(
                        f"Invalid JSON at line {line_number}: {exc}"
                    ) from exc

                raw_record = envelope.get("record")
                try:
                    record = assert_json_object(raw_record)
                except InvalidRecordError as exc:
                    raise IntegrityError(
                        f"Missing or invalid record object at line {line_number}."
                    ) from exc

                expected_record_hash = self._record_hash(record)
                stored_record_hash = envelope.get("record_hash")
                if not isinstance(stored_record_hash, str) or not hmac.compare_digest(
                    stored_record_hash, expected_record_hash
                ):
                    raise IntegrityError(f"Record hash mismatch at line {line_number}.")

                if envelope.get("previous_hash") != previous_hash:
                    raise IntegrityError(f"Previous hash mismatch at line {line_number}.")

                expected_chain_hash = self._chain_hash(previous_hash, expected_record_hash)
                stored_chain_hash = envelope.get("chain_hash")
                if not isinstance(stored_chain_hash, str) or not hmac.compare_digest(
                    stored_chain_hash, expected_chain_hash
                ):
                    raise IntegrityError(f"Chain hash mismatch at line {line_number}.")

                if self._hmac_secret is not None:
                    expected_signature = self._signature(expected_chain_hash)
                    stored_signature = envelope.get("signature")
                    if (
                        not isinstance(stored_signature, str)
                        or expected_signature is None
                        or not hmac.compare_digest(stored_signature, expected_signature)
                    ):
                        raise IntegrityError(f"HMAC signature mismatch at line {line_number}.")

                schema_version = record.get("schema_version")
                if type(schema_version) is not int or schema_version != SCHEMA_VERSION:
                    raise IntegrityError(f"Unsupported schema version at line {line_number}.")

                kind = record.get("record_type")
                if kind not in ("baseline", "outcome"):
                    raise IntegrityError(f"Invalid record_type at line {line_number}.")

                try:
                    record_id = self._required_string(record, "record_id")
                    target_id = self._required_string(record, "target_id")
                    timestamp = _parse_utc_timestamp(
                        self._required_string(record, "event_timestamp")
                    )
                    self._required_string(record, "execution_version")
                except InvalidRecordError as exc:
                    raise IntegrityError(
                        f"Invalid record fields at line {line_number}: {exc}"
                    ) from exc

                try:
                    payload = assert_json_object(record.get("payload"))
                except InvalidRecordError as exc:
                    raise IntegrityError(
                        f"Invalid payload at line {line_number}: {exc}"
                    ) from exc

                if last_timestamp is not None and timestamp < last_timestamp:
                    raise IntegrityError(
                        f"Retroactive timestamp in existing ledger at line {line_number}."
                    )
                if record_id in record_ids:
                    raise IntegrityError(f"Duplicate record_id at line {line_number}.")

                if kind == "baseline":
                    if record.get("baseline_ref") is not None:
                        raise IntegrityError(
                            f"Baseline cannot contain baseline_ref at line {line_number}."
                        )
                else:
                    baseline_ref = record.get("baseline_ref")
                    if not isinstance(baseline_ref, str) or baseline_ref not in baselines:
                        raise IntegrityError(
                            f"Orphan outcome at line {line_number}: baseline_ref "
                            "is not a previously verified baseline."
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
        lock_path = self.ledger_path.with_name(self.ledger_path.name + ".writer.lock")
        with lock_path.open("a+b") as lock_stream:
            if os.name == "nt":
                imported_module = importlib.import_module("msvcrt")
                windows_lock = cast(WindowsLockable, imported_module)
                lock_stream.seek(0, os.SEEK_END)
                if lock_stream.tell() == 0:
                    lock_stream.write(b"\0")
                    lock_stream.flush()
                lock_stream.seek(0)
                windows_lock.locking(lock_stream.fileno(), windows_lock.LK_LOCK, 1)
                try:
                    yield
                finally:
                    lock_stream.seek(0)
                    windows_lock.locking(lock_stream.fileno(), windows_lock.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(lock_stream.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(lock_stream.fileno(), fcntl.LOCK_UN)

    def verify(self) -> int:
        """Verify a stable snapshot of every record and its chain."""
        with self._writer_lock():
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
        record_id = record_id.strip()
        target_id = target_id.strip()
        execution_version = execution_version.strip()
        if not record_id or not target_id or not execution_version:
            raise InvalidRecordError("record_id, target_id and execution_version are required.")
        timestamp = _parse_utc_timestamp(event_timestamp)
        validated_payload = assert_json_object(payload)

        if record_type == "baseline" and baseline_ref is not None:
            raise InvalidRecordError("A baseline cannot reference another baseline.")
        if record_type == "outcome":
            if baseline_ref is None or not baseline_ref.strip():
                raise InvalidRecordError("baseline_ref must be a non-empty string.")
            baseline_ref = baseline_ref.strip()

        with self._writer_lock():
            (
                existing_records,
                composite_index,
                baselines,
                last_timestamp,
                previous_hash,
            ) = self._load_verified()

            if record_type == "outcome":
                if baseline_ref is None or baseline_ref not in baselines:
                    raise InvalidRecordError(
                        "Outcome rejected: baseline_ref does not identify a "
                        "previously verified baseline."
                    )
                if baselines[baseline_ref].get("target_id") != target_id:
                    raise InvalidRecordError(
                        "Outcome target_id must match the referenced baseline."
                    )

            record: JsonObject = {
                "schema_version": SCHEMA_VERSION,
                "record_type": record_type,
                "record_id": record_id,
                "target_id": target_id,
                "execution_version": execution_version,
                "event_timestamp": event_timestamp,
                "baseline_ref": baseline_ref,
                "payload": validated_payload,
            }
            index_key = self._composite_index(record)
            existing = composite_index.get(index_key)

            if existing is not None:
                existing_record = assert_json_object(existing.get("record"))
                if existing_record.get("payload") == validated_payload:
                    LOGGER.info(
                        "Idempotent replay skipped: index=%s key=%s record_id=%s",
                        index_key[0],
                        index_key[1],
                        existing_record.get("record_id"),
                    )
                    return "already_exists"
                raise DuplicateConflictError(
                    f"Composite key {index_key[0]} already exists with "
                    "different business payload."
                )

            existing_ids: set[str] = set()
            for item in existing_records:
                existing_record = assert_json_object(item.get("record"))
                existing_id = existing_record.get("record_id")
                if isinstance(existing_id, str):
                    existing_ids.add(existing_id)
            if record_id in existing_ids:
                raise DuplicateConflictError(f"record_id {record_id!r} has already been used.")

            if last_timestamp is not None and timestamp < last_timestamp:
                raise InvalidRecordError(
                    "Retroactive append rejected: event_timestamp is older "
                    "than the latest ledger timestamp."
                )

            record_hash = self._record_hash(record)
            chain_hash = self._chain_hash(previous_hash, record_hash)
            envelope: JsonObject = {
                "record": record,
                "record_hash": record_hash,
                "previous_hash": previous_hash,
                "chain_hash": chain_hash,
                "signature": self._signature(chain_hash),
            }
            encoded_line = _canonical_json(envelope) + b"\n"

            self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
            with self.ledger_path.open("ab") as stream:
                stream.write(encoded_line)
                stream.flush()
                os.fsync(stream.fileno())

            return "appended"
