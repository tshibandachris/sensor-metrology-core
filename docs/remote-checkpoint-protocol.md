# Remote checkpoint protocol (v1)

## Purpose and trust boundary

The remote checkpoint service is an independently administered witness for a
local ledger head. It detects divergence from the last remotely accepted
checkpoint. It does not, by itself, prove that a client-generated record is
truthful or that a compromised client process is trustworthy.

The service MUST NOT trust a client-supplied sequence or chain head without
checking it against the stored head in one atomic transaction. It MUST NOT
allow a client to overwrite or delete an accepted checkpoint.

A bearer credential authorizes the client to request checkpoints. It is not a
protection against compromise of that client: a process administrator may be
able to read runtime credentials. Credentials therefore MUST be target-scoped,
least-privilege, revocable, rate-limited, and excluded from logs. Deployments
requiring resistance to a compromised client need a separate device identity
or signed record attestation backed by a protected key.

## Transport and endpoints

- HTTPS only; redirects MUST NOT be followed for authenticated requests.
- API version: `/v1`.
- Authentication: `Authorization: Bearer <scoped-token>`.
- JSON encoding: UTF-8, no duplicate keys, no unknown fields, bounded request
  and response sizes.
- Target identifiers are path segments and MUST be percent-encoded.
- The service MUST return explicit non-2xx errors; clients MUST fail closed.

### Read current head

`GET /v1/targets/{target_id}/head`

A successful response is a signed envelope:

```json
{
  "key_id": "checkpoint-signing-2026-01",
  "payload": "BASE64URL_OF_CANONICAL_UTF8_JSON",
  "signature": "BASE64URL_ED25519_SIGNATURE"
}
```

The decoded canonical payload has exactly these fields:

```json
{
  "protocol_version": 1,
  "target_id": "sensor-001",
  "sequence": 12,
  "chain_hash": "64 lowercase hexadecimal characters",
  "checkpoint_id": "opaque-server-id",
  "issued_at": "2026-11-04T12:00:00Z"
}
```

For a target with no accepted checkpoints, sequence is `0` and chain_hash
is 64 zeroes. The client verifies the Ed25519 signature using a public key
pinned by key_id, then validates every field and the requested target. The
signature covers the exact decoded payload bytes. Unknown key IDs, malformed
base64url, invalid signatures, unexpected fields, wrong target IDs, and
invalid sequence/hash values are integrity failures.

GET is strictly read-only. It MUST NOT create targets, advance a head, refresh
a checkpoint, or mutate audit state other than ordinary access telemetry.

### Append a checkpoint

`POST /v1/targets/{target_id}/checkpoints`

Request body:

```json
{
  "protocol_version": 1,
  "target_id": "sensor-001",
  "sequence": 13,
  "previous_hash": "64 lowercase hexadecimal characters",
  "record_hash": "64 lowercase hexadecimal characters",
  "chain_hash": "64 lowercase hexadecimal characters",
  "idempotency_key": "opaque unique request identifier"
}
```

The client computes:

`chain_hash = SHA256(ASCII(previous_hash + ":" + record_hash))`

The service MUST independently recompute that value. In a single database
transaction it MUST:

1. Authenticate and authorize the credential for this target.
2. Validate the complete schema and all digest formats.
3. Check the idempotency key. An exact replay returns the original receipt;
   reuse with a different request body returns HTTP 409.
4. Lock or compare-and-swap the target head.
5. Require `sequence == stored_sequence + 1` and
   `previous_hash == stored_chain_hash`.
6. Persist the checkpoint, idempotency mapping, and new head atomically.
7. Return a signed receipt only after commit.

A stale head, sequence gap, conflicting idempotency key, or incorrect chain
hash returns HTTP 409 (or another documented 4xx error) without changing
state. Concurrent append attempts for one target must serialize so only one
request can advance a given head.

A successful response uses the same signed-envelope format as GET. Its
canonical payload contains the GET head fields plus `previous_hash` and
`record_hash`. The client verifies the receipt signature and confirms that
its target, sequence, previous hash, and chain hash exactly match the request.

## Retry and distributed-commit semantics

A network timeout does not reveal whether the server committed. The client
MUST retain the exact request and idempotency key and retry that exact request;
it MUST NOT generate a new key for an uncertain attempt. The service returns
the original signed receipt for an exact replay.

Local ledger storage and a remote HTTP service cannot participate in one
ordinary atomic transaction. The integration MUST therefore use a durable
pending-checkpoint/outbox state and explicit reconciliation:

- A local append is not reported as remotely anchored until a signed receipt
  has been verified.
- While an append is pending or its outcome is unknown, later appends are
  blocked for that target.
- On restart, the client retries the same pending request, then verifies the
  signed remote head against the local ledger.
- If the remote head is ahead, behind, or otherwise inconsistent with the
  local chain, the client fails closed and requires an explicit recovery
  procedure. It must not silently reset either side.

The pending request and idempotency key must be durable before the network
request is sent. This is required to recover safely from a process crash after
remote commit but before the client receives or stores the receipt.

## Security and operational requirements

- Ed25519 signing keys are held by the remote service in a KMS/HSM or
  equivalently protected signing boundary; private signing keys are never
  distributed to clients.
- Clients pin trusted public keys and support a documented key-rotation
  process with overlapping key IDs.
- Credentials are target-scoped, revocable, rotated, rate-limited, and never
  logged. A client-side environment variable is injection, not protection
  from a local administrator.
- The service enforces retention/append-only policy, tenant isolation,
  audit logging, backups, monitoring, and operator access controls.
- HTTPS certificate validation remains enabled. The client rejects redirects
  and unexpected hosts.
- The mock server used in tests is a protocol fixture only; it is not a
  production trust service and provides no deployment security guarantees.

## Scope of this repository change

This repository includes the protocol document, a loopback-only test fixture,
an Ed25519-verifying client, and an opt-in SQLite transactional outbox with
reconciliation. The outbox persists the exact checkpoint request and
idempotency key in the same local transaction as each ledger append, blocks
later appends while a checkpoint is pending, and marks delivery only after a
verified signed receipt.

The production remote service remains external and is not implemented by this
repository. The local outbox cannot provide remote availability or protect
against an administrator who can directly rewrite the SQLite database and its
files. Production use still requires an independently operated witness with
atomic compare-and-swap, protected signing keys, target-scoped credentials,
monitoring, backups, and a documented recovery procedure.
