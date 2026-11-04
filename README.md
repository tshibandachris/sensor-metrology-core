# Sensor Metrology Core

Standalone Python toolkit for validating physical pressure sensor readings stored in JSON Lines format.

## Scope and record format

Each record contains a non-empty `sensor_id` and a numeric `pressure_pa` value expressed in pascals (Pa):

```json
{
  "sensor_id": "PRESSURE-001",
  "pressure_pa": 101325
}
```

Pressure values must be finite and non-negative. Booleans are rejected even though Python treats `bool` as a subclass of `int`. No probability normalization or sum-to-one constraint is applied to physical measurements.

## Repository layout

```text
sensor-metrology-core/
├── .github/workflows/verify-metrology.yml
├── data/
├── reports/
├── tests/test_sensor_auditor.py
├── sensor_integrity_auditor.py
├── requirements.txt
└── README.md
```

## Validation pipeline

1. Read the JSONL input one line at a time.
2. Ignore blank lines.
3. Parse each non-empty line as JSON.
4. Reject duplicate keys, including keys in nested objects.
5. Validate the sensor identifier and pressure value.
6. Count accepted and rejected records and record rejection details.
7. Serialize the resulting integrity report.

Malformed records are counted as rejected; an input-file I/O failure stops the audit rather than producing a misleading partial-success report.

## Duplicate-key protection

The JSON decoder is configured with `object_pairs_hook=reject_duplicate_keys`. The hook receives the key/value pairs of each JSON object before they are collapsed into a Python dictionary. It raises `DuplicateKeyError` when a key appears more than once, preventing ambiguous input from silently using the last occurrence. The hook is applied recursively to nested objects.

The decoder also rejects non-standard numeric tokens such as `NaN` and `Infinity`.

## Atomic report persistence

The report writer follows this sequence:

1. `tempfile.mkstemp()` creates a uniquely named temporary file in the destination directory.
2. `os.fdopen()` wraps the returned file descriptor as a text stream.
3. `json.dump()` serializes the complete report; `allow_nan=False` prevents non-standard JSON numeric values.
4. `stream.flush()` moves Python-buffered data to the operating system.
5. `os.fsync(stream.fileno())` requests that the file's data and metadata be committed to the underlying storage device.
6. `os.replace()` atomically replaces the destination with the completed temporary file.
7. On POSIX systems, the parent directory is synced on a best-effort basis so the directory-entry update is more resilient to a crash.

The temporary file is created in the destination directory so the replacement normally occurs on the same filesystem. If serialization or writing fails before replacement, the existing destination remains intact and the temporary file is removed when possible.

### Atomicity is not multi-writer isolation

Under normal same-filesystem rename semantics, a reader sees either the previous complete report or the new complete report—not a partially written destination file.

Unique temporary names prevent writers from colliding while preparing their temporary files. However, `os.replace()` is not compare-and-swap and does not provide inter-process locking. If two processes concurrently target the same destination, both replacements may succeed and the last replacement wins.

If coordinated multi-writer transactions are required, add an explicit inter-process lock or a versioned storage protocol. That coordination is not implemented in this version.

`fsync()` improves durability but cannot override every filesystem, storage hardware, virtual-machine, or operating-system guarantee. Directory syncing is platform-dependent and is attempted here only on POSIX systems.

## Local setup

Python 3.12 is recommended. The current implementation uses only the Python standard library.

```bash
python -m venv .venv
# Activate the environment, then:
python -m pip install -r requirements.txt
```

## Run tests

```bash
python -m unittest discover -s tests -p "test_sensor_auditor.py" -v
```

## Run the auditor

Put JSONL readings in `data/sensor_readings.jsonl`, then run:

```bash
python sensor_integrity_auditor.py
```

Custom paths are supported:

```bash
python sensor_integrity_auditor.py \
  --input data/sensor_readings.jsonl \
  --output reports/sensor_integrity_report.json
```

## Continuous integration

GitHub Actions runs the unit suite on an isolated Ubuntu runner with Python 3.12. It runs on pushes to `main` and `feature/hardened-io-gate`, and on pull requests targeting `main`.

To make the workflow a blocking merge gate, configure branch protection or a repository ruleset for `main` and require the check named `Python 3.12 — Integrity tests`.

## License

Add an explicit license before redistributing this repository.


## Transactional chronological ledger

The original `ChronologicalLedgerManager` stores JSONL and uses advisory file
locks. Those locks coordinate only processes that voluntarily use the same
lock protocol. A process that writes directly to the JSONL path can still race
the final fingerprint check and append; a local checkpoint is not an
independent trust anchor.

For workloads that need concurrent cooperating writers, the repository also
provides `TransactionalLedgerManager` in `transactional_ledger.py`. It uses
SQLite transactions:

- `BEGIN IMMEDIATE` serializes writers before they read the current chain head.
- The record insert and metadata/head update commit in one database transaction.
- WAL mode gives readers a consistent snapshot while writers commit.
- A busy timeout bounds lock waiting.
- Full synchronous mode requests durable commits.
- Database triggers reject ordinary SQL UPDATE and DELETE operations on
  ledger rows; full chain and HMAC verification detects unauthorized changes.

Example:

```python
from pathlib import Path
from transactional_ledger import TransactionalLedgerManager

ledger = TransactionalLedgerManager(Path("data/metrology.sqlite3"))
ledger.append_baseline(
    record_id="baseline-001",
    target_id="sensor-001",
    execution_version="build-2026.11",
    event_timestamp="2026-11-01T08:00:00Z",
    payload={"pressure_pa": 101325},
)
assert ledger.verify() == 1
```

SQLite provides transaction isolation for clients that use SQLite correctly;
it does **not** make a database file safe against an arbitrary actor with
unrestricted filesystem access. Protect the database, WAL, and SHM files with
OS permissions, keep the HMAC secret outside the database, and expose writes
through one trusted service/API where possible. For a hostile or untrusted
writer with raw filesystem access, use a separately administered database
server or append-only remote trust service. Do not treat local triggers or
HMAC alone as a substitute for access control.
