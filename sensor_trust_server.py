"""Independent Ed25519 remote witness for sensor ledger checkpoints.

Protocol: docs/remote-checkpoint-protocol.md (v1).
The HTTP layer and durable CAS store use the Python standard library.
Ed25519 requires the project's existing 'cryptography' dependency.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import sqlite3
import ssl
import threading
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

GENESIS_HASH = "0" * 64
_HEX_256 = re.compile(r"^[0-9a-f]{64}$")
_IDEMPOTENCY = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_MAX_BODY = 8192
_KEY_ID_DEFAULT = "metrology-ed25519-2026"


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def encode_b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def load_private_key(value: str) -> Ed25519PrivateKey:
    """Accept PEM or base64url-encoded raw 32-byte Ed25519 private key."""
    if not value:
        raise ValueError("METROLOGY_PRIVATE_KEY is required.")
    if value.startswith("-----BEGIN"):
        loaded = serialization.load_pem_private_key(value.encode("utf-8"), password=None)
        if not isinstance(loaded, Ed25519PrivateKey):
            raise ValueError("METROLOGY_PRIVATE_KEY must contain an Ed25519 private key.")
        return loaded
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise ValueError("METROLOGY_PRIVATE_KEY must be PEM or base64url.") from exc
    if len(raw) != 32:
        raise ValueError("Raw Ed25519 private keys must contain exactly 32 bytes.")
    return Ed25519PrivateKey.from_private_bytes(raw)


class CheckpointStore:
    """SQLite-backed append-only checkpoint state with atomic CAS and replay."""

    def __init__(self, database_path: str | Path) -> None:
        self.database_path = str(database_path)
        if self.database_path != ":memory:":
            Path(self.database_path).parent.mkdir(parents=True, exist_ok=True)
        self._initialize_lock = threading.Lock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=15.0, isolation_level=None)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 15000")
        # synchronous is connection-local; set FULL on every writer connection.
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _initialize(self) -> None:
        with self._initialize_lock:
            connection = self._connect()
            try:
                if self.database_path != ":memory:":
                    connection.execute("PRAGMA journal_mode = WAL")
                    connection.execute("PRAGMA synchronous = FULL")
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS checkpoint_heads (
                        target_id TEXT PRIMARY KEY,
                        sequence INTEGER NOT NULL CHECK(sequence >= 0),
                        chain_hash TEXT NOT NULL,
                        checkpoint_id TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS checkpoint_idempotency (
                        target_id TEXT NOT NULL,
                        idempotency_key TEXT NOT NULL,
                        request_sha256 TEXT NOT NULL,
                        signed_response TEXT NOT NULL,
                        PRIMARY KEY(target_id, idempotency_key)
                    );
                    CREATE TABLE IF NOT EXISTS checkpoint_records (
                        target_id TEXT NOT NULL,
                        sequence INTEGER NOT NULL,
                        previous_hash TEXT NOT NULL,
                        record_hash TEXT NOT NULL,
                        chain_hash TEXT NOT NULL,
                        checkpoint_id TEXT NOT NULL,
                        issued_at TEXT NOT NULL,
                        PRIMARY KEY(target_id, sequence)
                    );
                    """
                )
            finally:
                connection.close()

    def read_head(self, target_id: str) -> dict[str, object]:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT sequence, chain_hash, checkpoint_id FROM checkpoint_heads WHERE target_id = ?",
                (target_id,),
            ).fetchone()
            if row is None:
                return {"sequence": 0, "chain_hash": GENESIS_HASH, "checkpoint_id": "genesis"}
            return {"sequence": int(row[0]), "chain_hash": str(row[1]), "checkpoint_id": str(row[2])}
        finally:
            connection.close()

    def append(
        self,
        target_id: str,
        request: dict[str, object],
        request_bytes: bytes,
        sign_payload: Any,
    ) -> tuple[str, bool]:
        """Atomically compare head, append record, and persist original signed receipt."""
        sequence = request["sequence"]
        previous_hash = request["previous_hash"]
        record_hash = request["record_hash"]
        chain_hash = request["chain_hash"]
        idempotency_key = request["idempotency_key"]
        if type(sequence) is not int or not isinstance(previous_hash, str) or not isinstance(record_hash, str):
            raise ValueError("invalid_fields")
        if not isinstance(chain_hash, str) or not isinstance(idempotency_key, str):
            raise ValueError("invalid_fields")
        request_digest = hashlib.sha256(request_bytes).hexdigest()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            replay = connection.execute(
                """SELECT request_sha256, signed_response
                   FROM checkpoint_idempotency WHERE target_id = ? AND idempotency_key = ?""",
                (target_id, idempotency_key),
            ).fetchone()
            if replay is not None:
                if not hmac.compare_digest(str(replay[0]), request_digest):
                    connection.rollback()
                    raise ValueError("idempotency_conflict")
                response = str(replay[1])
                connection.commit()
                return response, True

            row = connection.execute(
                "SELECT sequence, chain_hash FROM checkpoint_heads WHERE target_id = ?",
                (target_id,),
            ).fetchone()
            current_sequence = 0 if row is None else int(row[0])
            current_hash = GENESIS_HASH if row is None else str(row[1])
            if sequence != current_sequence + 1 or previous_hash != current_hash:
                connection.rollback()
                raise ValueError("stale_head")

            expected_hash = hashlib.sha256(
                f"{previous_hash}:{record_hash}".encode("ascii")
            ).hexdigest()
            if not hmac.compare_digest(chain_hash, expected_hash):
                connection.rollback()
                raise ValueError("chain_hash_mismatch")

            checkpoint_id = str(uuid.uuid4())
            issued_at = datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
            payload: dict[str, object] = {
                "protocol_version": 1,
                "target_id": target_id,
                "sequence": sequence,
                "chain_hash": chain_hash,
                "checkpoint_id": checkpoint_id,
                "issued_at": issued_at,
                "previous_hash": previous_hash,
                "record_hash": record_hash,
            }
            signed_response = canonical_json(sign_payload(payload)).decode("utf-8")
            connection.execute(
                """INSERT INTO checkpoint_records
                   (target_id, sequence, previous_hash, record_hash, chain_hash, checkpoint_id, issued_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (target_id, sequence, previous_hash, record_hash, chain_hash, checkpoint_id, issued_at),
            )
            connection.execute(
                """INSERT INTO checkpoint_heads(target_id, sequence, chain_hash, checkpoint_id)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(target_id) DO UPDATE SET
                     sequence=excluded.sequence,
                     chain_hash=excluded.chain_hash,
                     checkpoint_id=excluded.checkpoint_id""",
                (target_id, sequence, chain_hash, checkpoint_id),
            )
            connection.execute(
                """INSERT INTO checkpoint_idempotency
                   (target_id, idempotency_key, request_sha256, signed_response)
                   VALUES (?, ?, ?, ?)""",
                (target_id, idempotency_key, request_digest, signed_response),
            )
            connection.commit()
            return signed_response, False
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()


class RemoteTrustHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        store: CheckpointStore,
        auth_token: str,
        private_key: Ed25519PrivateKey,
        key_id: str = _KEY_ID_DEFAULT,
    ) -> None:
        if not auth_token or len(auth_token) > 4096:
            raise ValueError("A non-empty SERVER_AUTH_TOKEN is required.")
        if not key_id or len(key_id) > 128:
            raise ValueError("key_id must contain 1 to 128 characters.")
        self.store = store
        self.auth_token = auth_token
        self.private_key = private_key
        self.key_id = key_id
        super().__init__(server_address, RemoteTrustRequestHandler)

    def signed_envelope(self, payload: dict[str, object]) -> dict[str, str]:
        payload_bytes = canonical_json(payload)
        return {
            "key_id": self.key_id,
            "payload": encode_b64url(payload_bytes),
            "signature": encode_b64url(self.private_key.sign(payload_bytes)),
        }


class RemoteTrustRequestHandler(BaseHTTPRequestHandler):
    server: RemoteTrustHTTPServer
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        # Never log Authorization headers, request bodies, or bearer credentials.
        return

    def _send(self, status: int, value: object) -> None:
        body = canonical_json(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        supplied = self.headers.get("Authorization", "")
        expected = f"Bearer {self.server.auth_token}"
        return hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8"))

    def _target_from_path(self) -> tuple[str | None, str | None]:
        parts = [unquote(part) for part in urlsplit(self.path).path.split("/")]
        if len(parts) != 6 or parts[:3] != ["", "v1", "targets"]:
            return None, None
        if not parts[3] or len(parts[3]) > 256 or "/" in parts[3]:
            return None, None
        return parts[3], parts[4] if parts[5] == "" else None

    def _route(self) -> tuple[str | None, str | None]:
        parts = [unquote(part) for part in urlsplit(self.path).path.split("/")]
        if len(parts) != 5 or parts[:3] != ["", "v1", "targets"]:
            return None, None
        target_id = parts[3]
        if not target_id or len(target_id) > 256 or "/" in target_id:
            return None, None
        return target_id, parts[4]

    def _read_json(self) -> tuple[dict[str, object] | None, bytes | None]:
        raw_length = self.headers.get("Content-Length", "")
        try:
            length = int(raw_length)
        except ValueError:
            self._send(400, {"error": "invalid_content_length"})
            return None, None
        if length < 1:
            self._send(400, {"error": "empty_body"})
            return None, None
        if length > _MAX_BODY:
            self._send(413, {"error": "body_too_large"})
            return None, None
        raw = self.rfile.read(length)
        try:
            decoded: object = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=reject_duplicate_keys,
                parse_constant=lambda value: (_ for _ in ()).throw(ValueError("invalid_json_constant")),
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            self._send(400, {"error": "invalid_json"})
            return None, None
        if not isinstance(decoded, dict):
            self._send(400, {"error": "invalid_schema"})
            return None, None
        return decoded, raw

    def do_GET(self) -> None:
        if not self._authorized():
            self._send(401, {"error": "unauthorized"})
            return
        target_id, action = self._route()
        if target_id is None or action != "head" or urlsplit(self.path).query:
            self._send(404, {"error": "not_found"})
            return
        head = self.server.store.read_head(target_id)
        payload: dict[str, object] = {
            "protocol_version": 1,
            "target_id": target_id,
            "sequence": head["sequence"],
            "chain_hash": head["chain_hash"],
            "checkpoint_id": head["checkpoint_id"],
            "issued_at": datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z"),
        }
        self._send(200, self.server.signed_envelope(payload))

    def do_POST(self) -> None:
        if not self._authorized():
            self._send(401, {"error": "unauthorized"})
            return
        target_id, action = self._route()
        if target_id is None or action != "checkpoints" or urlsplit(self.path).query:
            self._send(404, {"error": "not_found"})
            return
        request, raw = self._read_json()
        if request is None or raw is None:
            return
        expected_fields = {
            "protocol_version", "target_id", "sequence", "previous_hash",
            "record_hash", "chain_hash", "idempotency_key",
        }
        if set(request) != expected_fields:
            self._send(400, {"error": "invalid_schema"})
            return
        request_sequence = request.get("sequence")
        if (
            type(request.get("protocol_version")) is not int
            or request["protocol_version"] != 1
            or request.get("target_id") != target_id
            or type(request_sequence) is not int
            or request_sequence < 1
        ):
            self._send(400, {"error": "invalid_fields"})
            return
        digests = (request.get("previous_hash"), request.get("record_hash"), request.get("chain_hash"))
        if any(not isinstance(item, str) or not _HEX_256.fullmatch(item) for item in digests):
            self._send(400, {"error": "invalid_digest"})
            return
        idempotency_key = request.get("idempotency_key")
        if not isinstance(idempotency_key, str) or not _IDEMPOTENCY.fullmatch(idempotency_key):
            self._send(400, {"error": "invalid_idempotency_key"})
            return
        try:
            response, replayed = self.server.store.append(
                target_id, request, canonical_json(request), self.server.signed_envelope
            )
        except ValueError as exc:
            reason = str(exc)
            status = 409 if reason in {"stale_head", "idempotency_conflict", "chain_hash_mismatch"} else 400
            self._send(status, {"error": reason})
            return
        except sqlite3.Error:
            self._send(503, {"error": "storage_unavailable"})
            return
        self.send_response(200 if replayed else 201)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(response.encode("utf-8"))))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Idempotent-Replay", "true" if replayed else "false")
        self.end_headers()
        self.wfile.write(response.encode("utf-8"))


def build_server(
    database_path: str | Path | None = None,
    host: str | None = None,
    port: int | None = None,
    auth_token: str | None = None,
    private_key_value: str | None = None,
    key_id: str | None = None,
    certfile_path: str | None = None,
    keyfile_path: str | None = None,
) -> RemoteTrustHTTPServer:
    """Build the witness server, optionally wrapping its listener in TLS.

    TLS remains disabled when neither certificate path is configured. When
    enabled, both the certificate chain and matching private key are required.
    """
    resolved_token = auth_token if auth_token is not None else os.environ.get("SERVER_AUTH_TOKEN", "")
    resolved_key = private_key_value if private_key_value is not None else os.environ.get("METROLOGY_PRIVATE_KEY", "")
    resolved_db = database_path if database_path is not None else os.environ.get(
        "METROLOGY_DATABASE", "sensor-trust.sqlite3"
    )
    resolved_host = host if host is not None else os.environ.get("SERVER_HOST", "127.0.0.1")
    resolved_port = port if port is not None else int(os.environ.get("SERVER_PORT", "8443"))
    resolved_key_id = key_id if key_id is not None else os.environ.get("METROLOGY_KEY_ID", _KEY_ID_DEFAULT)
    resolved_certfile = certfile_path if certfile_path is not None else os.environ.get("METROLOGY_TLS_CERT")
    resolved_keyfile = keyfile_path if keyfile_path is not None else os.environ.get("METROLOGY_TLS_KEY")
    if bool(resolved_certfile) != bool(resolved_keyfile):
        raise ValueError("METROLOGY_TLS_CERT and METROLOGY_TLS_KEY must be configured together.")
    tls_enabled = resolved_certfile is not None and resolved_keyfile is not None
    try:
        bind_ip = ipaddress.ip_address(resolved_host)
        loopback_only = bind_ip.is_loopback
    except ValueError:
        loopback_only = resolved_host.lower() == "localhost"
    if not tls_enabled and not loopback_only:
        raise ValueError("TLS is required when binding to a non-loopback address.")
    if not resolved_token:
        raise ValueError("SERVER_AUTH_TOKEN is required.")
    tls_context: ssl.SSLContext | None = None
    if tls_enabled:
        assert resolved_certfile is not None
        assert resolved_keyfile is not None
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
        tls_context.load_cert_chain(certfile=resolved_certfile, keyfile=resolved_keyfile)
    private_key = load_private_key(resolved_key)
    server = RemoteTrustHTTPServer(
        (resolved_host, resolved_port),
        CheckpointStore(resolved_db),
        resolved_token,
        private_key,
        resolved_key_id,
    )
    if tls_context is not None:
        try:
            server.socket = tls_context.wrap_socket(server.socket, server_side=True)
        except Exception:
            server.server_close()
            raise
    return server


def main() -> None:
    server = build_server()
    host, port = server.server_address[:2]
    if not isinstance(host, str) or type(port) is not int:
        raise RuntimeError("HTTP server returned an invalid bind address.")
    print(f"Remote trust witness listening on {host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
