"""Fail-closed client for the remote checkpoint witness protocol v1."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from typing import Mapping
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_HEX_256 = re.compile(r"^[0-9a-f]{64}$")
_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_IDEMPOTENCY = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_MAX_RESPONSE = 65_536
_MAX_REQUEST = 8_192


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Prevent authenticated requests from being forwarded to another host."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        return None


@dataclass(frozen=True, slots=True)
class VerifiedChainHead:
    """A remote head whose Ed25519 signature and schema were verified."""

    key_id: str
    target_id: str
    sequence: int
    chain_hash: str
    checkpoint_id: str
    issued_at: str
    previous_hash: str | None = None
    record_hash: str | None = None


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _decode_b64url(value: object, field: str) -> bytes:
    if not isinstance(value, str) or not _B64URL.fullmatch(value):
        raise RuntimeError(f"Invalid base64url value in {field}.")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise RuntimeError(f"Invalid base64url value in {field}.") from exc


def _validate_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or not _HEX_256.fullmatch(value):
        raise RuntimeError(f"{field} must be a lowercase SHA-256 digest.")
    return value


class RemoteTrustBridge:
    """Communicate with a remote witness and verify every signed response.

    Public keys are raw 32-byte Ed25519 keys indexed by the server's key_id.
    Production deployments should inject these pinned keys from trusted
    configuration, not accept keys supplied by the remote response.
    """

    def __init__(
        self,
        base_url: str | None = None,
        token: str | None = None,
        target_id: str | None = None,
        trusted_public_keys: Mapping[str, bytes] | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        self.base_url = (base_url or os.environ.get("REMOTE_TRUST_BASE_URL", "")).rstrip("/")
        self.token = token or os.environ.get("REMOTE_TRUST_TOKEN", "")
        self.target_id = target_id or os.environ.get("REMOTE_TRUST_TARGET_ID", "")
        self.timeout_seconds = timeout_seconds
        if not self.base_url or not self.token or not self.target_id:
            raise ValueError(
                "REMOTE_TRUST_BASE_URL, REMOTE_TRUST_TOKEN and "
                "REMOTE_TRUST_TARGET_ID are required."
            )
        if len(self.token) > 4096 or any(ord(char) < 33 for char in self.token):
            raise ValueError("Remote trust token has an invalid format.")
        if not self.target_id.strip() or len(self.target_id) > 256:
            raise ValueError("target_id must contain 1 to 256 characters.")
        if timeout_seconds <= 0 or timeout_seconds > 120:
            raise ValueError("timeout_seconds must be greater than 0 and at most 120.")
        parsed = urllib.parse.urlsplit(self.base_url)
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("Credentials must not be embedded in base_url.")
        if parsed.query or parsed.fragment or not parsed.hostname:
            raise ValueError("base_url must be an absolute URL without query or fragment.")
        is_loopback_http = (
            parsed.scheme == "http"
            and parsed.hostname in ("127.0.0.1", "localhost", "::1")
        )
        if parsed.scheme != "https" and not is_loopback_http:
            raise ValueError("HTTPS is required except for a local loopback test server.")
        if parsed.scheme == "https" and parsed.port not in (None, 443):
            # Non-standard HTTPS ports are allowed for controlled deployments.
            pass

        if trusted_public_keys is None:
            raw_keys = os.environ.get("REMOTE_TRUST_PUBLIC_KEYS", "")
            if not raw_keys:
                raise ValueError("REMOTE_TRUST_PUBLIC_KEYS must contain pinned public keys.")
            try:
                decoded_keys: object = json.loads(
                    raw_keys, object_pairs_hook=_reject_duplicate_keys
                )
            except (json.JSONDecodeError, ValueError) as exc:
                raise ValueError("REMOTE_TRUST_PUBLIC_KEYS is invalid JSON.") from exc
            if not isinstance(decoded_keys, dict):
                raise ValueError("REMOTE_TRUST_PUBLIC_KEYS must be a JSON object.")
            parsed_keys: dict[str, bytes] = {}
            for key_id, encoded_key in decoded_keys.items():
                parsed_keys[key_id] = _decode_b64url(encoded_key, "public key")
            trusted_public_keys = parsed_keys

        if not trusted_public_keys:
            raise ValueError("At least one pinned Ed25519 public key is required.")
        self._public_keys: dict[str, Ed25519PublicKey] = {}
        for key_id, raw_key in trusted_public_keys.items():
            if not key_id or len(key_id) > 128 or len(raw_key) != 32:
                raise ValueError("Each trusted key needs a key_id and 32 raw bytes.")
            self._public_keys[key_id] = Ed25519PublicKey.from_public_bytes(raw_key)

        self._opener = urllib.request.build_opener(_NoRedirect())

    def _request(self, method: str, endpoint: str, body: bytes | None = None) -> object:
        url = f"{self.base_url}{endpoint}"
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.token}",
        }
        if body is not None:
            if len(body) > _MAX_REQUEST:
                raise ValueError("Remote trust request exceeds the size limit.")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with self._opener.open(request, timeout=self.timeout_seconds) as response:
                status = response.status
                if status < 200 or status >= 300:
                    raise IOError(f"Remote trust service returned HTTP {status}.")
                raw = response.read(_MAX_RESPONSE + 1)
        except urllib.error.HTTPError as exc:
            raise IOError(f"Remote trust service returned HTTP {exc.code}.") from exc
        except urllib.error.URLError as exc:
            raise IOError(f"Remote trust network request failed: {exc.reason}") from exc
        except (TimeoutError, OSError) as exc:
            raise IOError(f"Remote trust network request failed: {exc}") from exc
        if len(raw) > _MAX_RESPONSE:
            raise RuntimeError("Remote trust response exceeds the size limit.")
        try:
            decoded: object = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=lambda value: (_ for _ in ()).throw(
                    ValueError(f"Invalid JSON constant: {value}")
                ),
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise RuntimeError("Remote trust service returned malformed JSON.") from exc
        if not isinstance(decoded, dict):
            raise RuntimeError("Remote trust response must be a JSON object.")
        return decoded

    def _verify_envelope(self, envelope: object, receipt: bool) -> VerifiedChainHead:
        if not isinstance(envelope, dict) or set(envelope) != {
            "key_id", "payload", "signature"
        }:
            raise RuntimeError("Signed response envelope has unexpected fields.")
        key_id = envelope.get("key_id")
        if not isinstance(key_id, str) or key_id not in self._public_keys:
            raise RuntimeError("Remote trust response uses an unknown signing key.")
        payload_bytes = _decode_b64url(envelope.get("payload"), "payload")
        signature = _decode_b64url(envelope.get("signature"), "signature")
        try:
            self._public_keys[key_id].verify(signature, payload_bytes)
        except (InvalidSignature, ValueError) as exc:
            raise RuntimeError("Remote trust response signature is invalid.") from exc
        try:
            payload: object = json.loads(
                payload_bytes.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=lambda value: (_ for _ in ()).throw(
                    ValueError(f"Invalid JSON constant: {value}")
                ),
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise RuntimeError("Signed checkpoint payload is malformed.") from exc
        if not isinstance(payload, dict) or _canonical_json(payload) != payload_bytes:
            raise RuntimeError("Signed checkpoint payload is not canonical JSON.")
        expected_fields = {
            "protocol_version", "target_id", "sequence", "chain_hash",
            "checkpoint_id", "issued_at",
        }
        if receipt:
            expected_fields.update({"previous_hash", "record_hash"})
        if set(payload) != expected_fields:
            raise RuntimeError("Signed checkpoint payload has unexpected fields.")
        if type(payload.get("protocol_version")) is not int or payload["protocol_version"] != 1:
            raise RuntimeError("Unsupported remote checkpoint protocol version.")
        target = payload.get("target_id")
        sequence = payload.get("sequence")
        checkpoint_id = payload.get("checkpoint_id")
        issued_at = payload.get("issued_at")
        if target != self.target_id:
            raise RuntimeError("Remote checkpoint target_id does not match.")
        if type(sequence) is not int or sequence < 0 or (receipt and sequence == 0):
            raise RuntimeError("Remote checkpoint sequence is invalid.")
        chain_hash = _validate_digest(payload.get("chain_hash"), "chain_hash")
        if not isinstance(checkpoint_id, str) or not checkpoint_id or len(checkpoint_id) > 256:
            raise RuntimeError("checkpoint_id is invalid.")
        if not isinstance(issued_at, str) or not issued_at.endswith("Z"):
            raise RuntimeError("issued_at must be a UTC timestamp ending in Z.")
        try:
            datetime.fromisoformat(issued_at[:-1] + "+00:00")
        except ValueError as exc:
            raise RuntimeError("issued_at is not a valid ISO-8601 timestamp.") from exc
        previous_hash: str | None = None
        record_hash: str | None = None
        if receipt:
            previous_hash = _validate_digest(payload.get("previous_hash"), "previous_hash")
            record_hash = _validate_digest(payload.get("record_hash"), "record_hash")
        return VerifiedChainHead(
            key_id=key_id,
            target_id=target,
            sequence=sequence,
            chain_hash=chain_hash,
            checkpoint_id=checkpoint_id,
            issued_at=issued_at,
            previous_hash=previous_hash,
            record_hash=record_hash,
        )

    def fetch_expected_chain_head(self) -> VerifiedChainHead:
        """Fetch and cryptographically verify the current remote chain head."""
        target = urllib.parse.quote(self.target_id, safe="")
        envelope = self._request("GET", f"/v1/targets/{target}/head")
        return self._verify_envelope(envelope, receipt=False)

    def post_new_chain_head(
        self,
        *,
        sequence: int,
        previous_hash: str,
        record_hash: str,
        chain_hash: str,
        idempotency_key: str,
    ) -> VerifiedChainHead:
        """Submit one checkpoint and verify the signed receipt.

        The caller must durably persist the exact request and idempotency key
        before calling this method. A timeout is ambiguous; retry the exact
        same arguments and key rather than constructing a new request.
        """
        if type(sequence) is not int or sequence < 1:
            raise ValueError("sequence must be a positive integer.")
        previous = _validate_digest(previous_hash, "previous_hash")
        record = _validate_digest(record_hash, "record_hash")
        supplied_chain = _validate_digest(chain_hash, "chain_hash")
        expected_chain = hashlib.sha256(
            f"{previous}:{record}".encode("ascii")
        ).hexdigest()
        if supplied_chain != expected_chain:
            raise ValueError("chain_hash does not match previous_hash and record_hash.")
        if not isinstance(idempotency_key, str) or not _IDEMPOTENCY.fullmatch(idempotency_key):
            raise ValueError("idempotency_key has an invalid format.")
        payload = {
            "protocol_version": 1,
            "target_id": self.target_id,
            "sequence": sequence,
            "previous_hash": previous,
            "record_hash": record,
            "chain_hash": supplied_chain,
            "idempotency_key": idempotency_key,
        }
        body = _canonical_json(payload)
        target = urllib.parse.quote(self.target_id, safe="")
        envelope = self._request(
            "POST", f"/v1/targets/{target}/checkpoints", body=body
        )
        receipt = self._verify_envelope(envelope, receipt=True)
        if (
            receipt.sequence != sequence
            or receipt.previous_hash != previous
            or receipt.record_hash != record
            or receipt.chain_hash != supplied_chain
        ):
            raise RuntimeError("Signed checkpoint receipt does not match the request.")
        return receipt
