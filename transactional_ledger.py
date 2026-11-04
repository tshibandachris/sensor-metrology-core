#!/usr/bin/env python3
"""Transactional SQLite implementation of the chronological integrity ledger.

SQLite serializes cooperating writers with BEGIN IMMEDIATE and gives readers a
consistent transaction snapshot. Direct edits to the database file are outside
this API's trust boundary and must be prevented with operating-system access
controls or a dedicated service account.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Literal

from chronological_ledger import (
    GENESIS_HASH,
    SCHEMA_VERSION,
    DuplicateConflictError,
    IntegrityError,
    InvalidRecordError,
    JsonObject,
    _canonical_json,
    _parse_utc_timestamp,
    _reject_duplicate_json_keys,
    _reject_json_constant,
    _sha256_hex,
    assert_json_object,
)

AppendResult = Literal["appended", "already_exists"]


def _chain_hash(previous_hash: str, record_hash: str) -> str:
    return hashlib.sha256(
        f"{previous_hash}:{record_hash}".encode("ascii")
    ).hexdigest()


class TransactionalLedgerManager:
    """Append-only ledger whose transaction boundary is managed by SQLite."""

    def __init__(
        self,
        database_path: Path,
        hmac_secret: bytes | None = None,
        timeout_seconds: float = 30.0,
    ) -> None:
        if hmac_secret is None:
            configured = os.environ.get("METROLOGY_SIGNING_KEY")
            if configured is None:
                raise ValueError("METROLOGY_SIGNING_KEY must be configured.")
            hmac_secret = configured.encode("utf-8")
        if len(hmac_secret) < 32:
            raise ValueError("hmac_secret must contain at least 32 bytes.")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive.")

        self.database_path = database_path
        self._hmac_secret = hmac_secret
        self._timeout_seconds = timeout_seconds
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.database_path,
            timeout=self._timeout_seconds,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            f"PRAGMA busy_timeout = {int(self._timeout_seconds * 1000)}"
        )
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS ledger_meta (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    head_hash TEXT NOT NULL,
                    last_timestamp TEXT,
                    record_count INTEGER NOT NULL CHECK (record_count >= 0)
                );

                INSERT OR IGNORE INTO ledger_meta
                    (singleton, head_hash, last_timestamp, record_count)
                VALUES (1, '0000000000000000000000000000000000000000000000000000000000000000',
                        NULL, 0);

                CREATE TABLE IF NOT EXISTS ledger_records (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    record_id TEXT NOT NULL UNIQUE,
                    record_type TEXT NOT NULL CHECK (record_type IN ('baseline', 'outcome')),
                    target_id TEXT NOT NULL,
                    execution_version TEXT NOT NULL,
                    event_timestamp TEXT NOT NULL,
                    baseline_ref TEXT REFERENCES ledger_records(record_id),
                    composite_key TEXT NOT NULL UNIQUE,
                    record_json TEXT NOT NULL,
                    record_hash TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    chain_hash TEXT NOT NULL UNIQUE,
                    signature TEXT NOT NULL
                );

                CREATE TRIGGER IF NOT EXISTS ledger_records_no_update
                BEFORE UPDATE ON ledger_records
                BEGIN
                    SELECT RAISE(ABORT, 'ledger records are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS ledger_records_no_delete
                BEFORE DELETE ON ledger_records
                BEGIN
                    SELECT RAISE(ABORT, 'ledger records are append-only');
                END;
                """
            )
        finally:
            connection.close()

    @staticmethod
    def _composite_key(
        record_type: str,
        target_id: str,
        execution_version: str,
        event_timestamp: str,
        baseline_ref: str | None,
    ) -> str:
        return json.dumps(
            [
                record_type,
                target_id,
                execution_version,
                event_timestamp,
                baseline_ref,
            ],
            ensure_ascii=False,
            separators=(",", ":"),
        )

    def _signature(self, chain_hash: str) -> str:
        return hmac.new(
            self._hmac_secret,
            chain_hash.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()

    def append_baseline(
        self,
        *,
        record_id: str,
        target_id: str,
        execution_version: str,
        event_timestamp: str,
        payload: JsonObject,
    ) -> AppendResult:
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
    ) -> AppendResult:
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
        record_type: Literal["baseline", "outcome"],
        record_id: str,
        target_id: str,
        execution_version: str,
        event_timestamp: str,
        payload: JsonObject,
        baseline_ref: str | None,
    ) -> AppendResult:
        record_id = record_id.strip()
        target_id = target_id.strip()
        execution_version = execution_version.strip()
        if not record_id or not target_id or not execution_version:
            raise InvalidRecordError(
                "record_id, target_id and execution_version are required."
            )
        timestamp = _parse_utc_timestamp(event_timestamp)
        validated_payload = assert_json_object(payload)
        if record_type == "outcome":
            if baseline_ref is None or not baseline_ref.strip():
                raise InvalidRecordError("baseline_ref must be a non-empty string.")
            baseline_ref = baseline_ref.strip()
        elif baseline_ref is not None:
            raise InvalidRecordError("A baseline cannot reference another baseline.")

        composite_key = self._composite_key(
            record_type, target_id, execution_version, event_timestamp, baseline_ref
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT record_json FROM ledger_records WHERE composite_key = ?",
                (composite_key,),
            ).fetchone()
            if existing is not None:
                existing_record = json.loads(existing["record_json"])
                if existing_record.get("payload") == validated_payload:
                    connection.execute("COMMIT")
                    return "already_exists"
                raise DuplicateConflictError(
                    "Composite key already exists with different business payload."
                )

            duplicate_id = connection.execute(
                "SELECT 1 FROM ledger_records WHERE record_id = ?",
                (record_id,),
            ).fetchone()
            if duplicate_id is not None:
                raise DuplicateConflictError(f"record_id {record_id!r} was already used.")

            meta = connection.execute(
                "SELECT head_hash, last_timestamp, record_count "
                "FROM ledger_meta WHERE singleton = 1"
            ).fetchone()
            if meta is None:
                raise IntegrityError("Ledger metadata row is missing.")
            if meta["last_timestamp"] is not None:
                if timestamp < _parse_utc_timestamp(meta["last_timestamp"]):
                    raise InvalidRecordError(
                        "Retroactive append rejected: event_timestamp is older "
                        "than the latest ledger timestamp."
                    )

            if record_type == "outcome":
                baseline = connection.execute(
                    "SELECT target_id FROM ledger_records "
                    "WHERE record_id = ? AND record_type = 'baseline'",
                    (baseline_ref,),
                ).fetchone()
                if baseline is None:
                    raise InvalidRecordError(
                        "Outcome rejected: baseline_ref is not a verified baseline."
                    )
                if baseline["target_id"] != target_id:
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
            record_hash = _sha256_hex(_canonical_json(record))
            previous_hash = str(meta["head_hash"])
            chain_hash = _chain_hash(previous_hash, record_hash)
            signature = self._signature(chain_hash)
            record_json = _canonical_json(record).decode("utf-8")

            connection.execute(
                """
                INSERT INTO ledger_records (
                    record_id, record_type, target_id, execution_version,
                    event_timestamp, baseline_ref, composite_key, record_json,
                    record_hash, previous_hash, chain_hash, signature
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record_id,
                    record_type,
                    target_id,
                    execution_version,
                    event_timestamp,
                    baseline_ref,
                    composite_key,
                    record_json,
                    record_hash,
                    previous_hash,
                    chain_hash,
                    signature,
                ),
            )
            connection.execute(
                """
                UPDATE ledger_meta
                SET head_hash = ?, last_timestamp = ?, record_count = record_count + 1
                WHERE singleton = 1
                """,
                (chain_hash, event_timestamp),
            )
            connection.execute("COMMIT")
            return "appended"
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def verify(self, expected_head_hash: str | None = None) -> int:
        if expected_head_hash is not None and (
            len(expected_head_hash) != 64
            or any(char not in "0123456789abcdef" for char in expected_head_hash)
        ):
            raise IntegrityError(
                "expected_head_hash must be a 64-character lowercase SHA-256 value."
            )

        connection = self._connect()
        try:
            connection.execute("BEGIN")
            integrity_result = connection.execute("PRAGMA integrity_check").fetchone()
            if integrity_result is None or integrity_result[0] != "ok":
                raise IntegrityError("SQLite database integrity check failed.")
            rows = connection.execute(
                "SELECT * FROM ledger_records ORDER BY sequence"
            ).fetchall()
            previous_hash = GENESIS_HASH
            last_timestamp: datetime | None = None
            last_timestamp_text: str | None = None
            record_ids: set[str] = set()
            baselines: dict[str, str] = {}
            composite_keys: set[str] = set()

            for expected_sequence, row in enumerate(rows, start=1):
                if row["sequence"] != expected_sequence:
                    raise IntegrityError("Ledger sequence contains a gap or reordering.")
                if not isinstance(row["record_hash"], str) or not isinstance(
                    row["previous_hash"], str
                ) or not isinstance(row["chain_hash"], str) or not isinstance(
                    row["signature"], str
                ):
                    raise IntegrityError(
                        f"Invalid hash or signature column at sequence {row['sequence']}."
                    )
                try:
                    decoded: object = json.loads(
                        row["record_json"],
                        object_pairs_hook=_reject_duplicate_json_keys,
                        parse_constant=_reject_json_constant,
                    )
                    record = assert_json_object(decoded)
                except (ValueError, TypeError, InvalidRecordError) as exc:
                    raise IntegrityError(
                        f"Invalid stored record at sequence {row['sequence']}."
                    ) from exc

                if _sha256_hex(_canonical_json(record)) != row["record_hash"]:
                    raise IntegrityError(
                        f"Record hash mismatch at sequence {row['sequence']}."
                    )
                if row["previous_hash"] != previous_hash:
                    raise IntegrityError(
                        f"Previous hash mismatch at sequence {row['sequence']}."
                    )
                chain_hash = _chain_hash(previous_hash, row["record_hash"])
                if not hmac.compare_digest(chain_hash, row["chain_hash"]):
                    raise IntegrityError(
                        f"Chain hash mismatch at sequence {row['sequence']}."
                    )
                if not hmac.compare_digest(
                    self._signature(chain_hash), row["signature"]
                ):
                    raise IntegrityError(
                        f"HMAC signature mismatch at sequence {row['sequence']}."
                    )

                record_id = record.get("record_id")
                record_type = record.get("record_type")
                target_id = record.get("target_id")
                timestamp_text = record.get("event_timestamp")
                version = record.get("execution_version")
                if (
                    not isinstance(record_id, str)
                    or not isinstance(target_id, str)
                    or not isinstance(version, str)
                    or not isinstance(timestamp_text, str)
                    or record_type not in ("baseline", "outcome")
                    or type(record.get("schema_version")) is not int
                    or record.get("schema_version") != SCHEMA_VERSION
                ):
                    raise IntegrityError(
                        f"Invalid record fields at sequence {row['sequence']}."
                    )
                try:
                    timestamp = _parse_utc_timestamp(timestamp_text)
                except InvalidRecordError as exc:
                    raise IntegrityError(
                        f"Invalid timestamp at sequence {row['sequence']}."
                    ) from exc
                if last_timestamp is not None and timestamp < last_timestamp:
                    raise IntegrityError(
                        f"Retroactive timestamp at sequence {row['sequence']}."
                    )
                if record_id in record_ids:
                    raise IntegrityError(f"Duplicate record_id {record_id!r}.")
                try:
                    assert_json_object(record.get("payload"))
                except InvalidRecordError as exc:
                    raise IntegrityError(
                        f"Invalid payload at sequence {row['sequence']}."
                    ) from exc

                baseline_ref = record.get("baseline_ref")
                if record_type == "baseline":
                    if baseline_ref is not None:
                        raise IntegrityError("Baseline cannot contain baseline_ref.")
                    baselines[record_id] = target_id
                else:
                    if not isinstance(baseline_ref, str):
                        raise IntegrityError("Outcome must reference a baseline.")
                    if baselines.get(baseline_ref) != target_id:
                        raise IntegrityError("Outcome baseline reference is invalid.")

                key = self._composite_key(
                    str(record_type),
                    target_id,
                    version,
                    timestamp_text,
                    baseline_ref if isinstance(baseline_ref, str) else None,
                )
                if key in composite_keys:
                    raise IntegrityError("Duplicate composite key.")
                composite_keys.add(key)

                if (
                    row["record_id"] != record_id
                    or row["record_type"] != record_type
                    or row["target_id"] != target_id
                    or row["execution_version"] != version
                    or row["event_timestamp"] != timestamp_text
                    or row["baseline_ref"] != baseline_ref
                    or row["composite_key"] != key
                ):
                    raise IntegrityError(
                        f"Indexed columns disagree with record at sequence {row['sequence']}."
                    )

                record_ids.add(record_id)
                previous_hash = chain_hash
                last_timestamp = timestamp
                last_timestamp_text = timestamp_text

            meta = connection.execute(
                "SELECT head_hash, last_timestamp, record_count "
                "FROM ledger_meta WHERE singleton = 1"
            ).fetchone()
            if meta is None:
                raise IntegrityError("Ledger metadata row is missing.")
            if (
                meta["head_hash"] != previous_hash
                or meta["record_count"] != len(rows)
                or meta["last_timestamp"] != last_timestamp_text
            ):
                raise IntegrityError("Ledger metadata does not match verified records.")
            if expected_head_hash is not None and not hmac.compare_digest(
                expected_head_hash, previous_hash
            ):
                raise IntegrityError("Ledger head differs from external expected hash.")

            connection.execute("COMMIT")
            return len(rows)
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
