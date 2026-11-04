"""In-process HTTP witness fixture for remote trust protocol tests only."""

from __future__ import annotations

import base64
import hashlib
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import unquote, urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

GENESIS_HASH = "0" * 64
KEY_ID = "test-ed25519-key"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


class RemoteTrustStub:
    """Threaded local HTTP server with atomic head and idempotency behavior.

    This fixture deliberately binds only to loopback. It is not a production
    service and must never be exposed on a public interface.
    """

    def __init__(self, target_id: str = "sensor-001", token: str = "test-token") -> None:
        self.target_id = target_id
        self.token = token
        self._private_key = Ed25519PrivateKey.generate()
        self._head: dict[str, object] = {
            "sequence": 0,
            "chain_hash": GENESIS_HASH,
            "checkpoint_id": "genesis",
        }
        self._idempotency: dict[str, tuple[bytes, dict[str, str]]] = {}
        self._lock = threading.Lock()
        self.drop_next_post_response = False
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                return

            def _send(self, status: int, value: object) -> None:
                body = _canonical(value)
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _authorized(self) -> bool:
                return self.headers.get("Authorization") == f"Bearer {fixture.token}"

            def _target_from_path(self) -> str | None:
                parts = [unquote(part) for part in urlsplit(self.path).path.split("/")]
                if len(parts) < 5 or parts[1:3] != ["v1", "targets"]:
                    return None
                return parts[3]

            def _signed(self, payload: dict[str, object]) -> dict[str, str]:
                payload_bytes = _canonical(payload)
                signature = fixture._private_key.sign(payload_bytes)
                public_payload = base64.urlsafe_b64encode(payload_bytes).rstrip(b"=").decode("ascii")
                encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
                return {
                    "key_id": KEY_ID,
                    "payload": public_payload,
                    "signature": encoded_signature,
                }

            def do_GET(self) -> None:
                if not self._authorized():
                    self._send(401, {"error": "unauthorized"})
                    return
                target = self._target_from_path()
                if target != fixture.target_id or not self.path.endswith("/head"):
                    self._send(404, {"error": "not_found"})
                    return
                with fixture._lock:
                    head = dict(fixture._head)
                payload: dict[str, object] = {
                    "protocol_version": 1,
                    "target_id": target,
                    "sequence": head["sequence"],
                    "chain_hash": head["chain_hash"],
                    "checkpoint_id": head["checkpoint_id"],
                    "issued_at": "2026-11-04T12:00:00Z",
                }
                self._send(200, self._signed(payload))

            def do_POST(self) -> None:
                if not self._authorized():
                    self._send(401, {"error": "unauthorized"})
                    return
                target = self._target_from_path()
                if target != fixture.target_id or not self.path.endswith("/checkpoints"):
                    self._send(404, {"error": "not_found"})
                    return
                raw_length = self.headers.get("Content-Length", "")
                try:
                    length = int(raw_length)
                except ValueError:
                    self._send(400, {"error": "invalid_content_length"})
                    return
                if length < 1 or length > 8192:
                    self._send(413, {"error": "invalid_body_size"})
                    return
                body = self.rfile.read(length)
                try:
                    request: object = json.loads(body.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    self._send(400, {"error": "invalid_json"})
                    return
                if not isinstance(request, dict) or set(request) != {
                    "protocol_version", "target_id", "sequence", "previous_hash",
                    "record_hash", "chain_hash", "idempotency_key",
                }:
                    self._send(400, {"error": "invalid_schema"})
                    return
                sequence = request.get("sequence")
                previous_hash = request.get("previous_hash")
                record_hash = request.get("record_hash")
                chain_hash = request.get("chain_hash")
                key = request.get("idempotency_key")
                if (
                    request.get("protocol_version") != 1
                    or request.get("target_id") != target
                    or type(sequence) is not int
                    or sequence < 1
                    or not isinstance(previous_hash, str)
                    or not isinstance(record_hash, str)
                    or not isinstance(chain_hash, str)
                    or not isinstance(key, str)
                    or len(key) < 1
                    or len(key) > 128
                ):
                    self._send(400, {"error": "invalid_fields"})
                    return
                if any(
                    len(digest) != 64
                    or any(char not in "0123456789abcdef" for char in digest)
                    for digest in (previous_hash, record_hash, chain_hash)
                ):
                    self._send(400, {"error": "invalid_digest"})
                    return
                expected = hashlib.sha256(
                    f"{previous_hash}:{record_hash}".encode("ascii")
                ).hexdigest()
                if chain_hash != expected:
                    self._send(409, {"error": "chain_hash_mismatch"})
                    return

                with fixture._lock:
                    replay = fixture._idempotency.get(key)
                    if replay is not None:
                        if replay[0] != body:
                            self._send(409, {"error": "idempotency_conflict"})
                            return
                        response = replay[1]
                    else:
                        current_sequence = fixture._head["sequence"]
                        current_hash = fixture._head["chain_hash"]
                        if sequence != current_sequence + 1 or previous_hash != current_hash:
                            self._send(409, {"error": "stale_head"})
                            return
                        checkpoint_id = f"checkpoint-{sequence}"
                        payload: dict[str, object] = {
                            "protocol_version": 1,
                            "target_id": target,
                            "sequence": sequence,
                            "chain_hash": chain_hash,
                            "checkpoint_id": checkpoint_id,
                            "issued_at": "2026-11-04T12:00:00Z",
                            "previous_hash": previous_hash,
                            "record_hash": record_hash,
                        }
                        response = self._signed(payload)
                        fixture._head = {
                            "sequence": sequence,
                            "chain_hash": chain_hash,
                            "checkpoint_id": checkpoint_id,
                        }
                        fixture._idempotency[key] = (body, response)
                    should_drop = fixture.drop_next_post_response
                    fixture.drop_next_post_response = False

                if should_drop:
                    try:
                        self.connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    self.connection.close()
                    return
                self._send(200, response)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def base_url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    @property
    def public_key_bytes(self) -> bytes:
        return self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @property
    def public_keys(self) -> dict[str, bytes]:
        return {KEY_ID: self.public_key_bytes}

    @property
    def sequence(self) -> int:
        with self._lock:
            return int(self._head["sequence"])

    @property
    def chain_hash(self) -> str:
        with self._lock:
            value = self._head["chain_hash"]
        if not isinstance(value, str):
            raise RuntimeError("Stub head hash is not a string.")
        return value

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

    def __enter__(self) -> RemoteTrustStub:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object,
    ) -> None:
        self.close()
