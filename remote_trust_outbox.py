"""Durable SQLite outbox reconciliation for remote ledger checkpoints."""

from __future__ import annotations

from typing import Literal

from chronological_ledger import IntegrityError
from remote_trust_bridge import RemoteTrustBridge
from transactional_ledger import TransactionalLedgerManager

SyncResult = Literal["delivered", "reconciled", "in_sync"]


class RemoteTrustSynchronizer:
    """Synchronize one ledger's durable outbox with its remote witness.

    A pending local append blocks later local appends. This synchronizer sends
    the exact persisted request and idempotency key, and only marks it delivered
    after verifying the server's Ed25519-signed receipt.
    """

    def __init__(
        self,
        ledger: TransactionalLedgerManager,
        bridge: RemoteTrustBridge,
    ) -> None:
        self.ledger = ledger
        self.bridge = bridge

    def _synchronize_one(self) -> SyncResult:
        """Deliver or reconcile the earliest pending checkpoint.

        A signed remote head that is exactly one sequence ahead is not enough
        to mark the row delivered: the exact original POST is replayed so the
        witness returns its original signed idempotent receipt.
        """
        for _ in range(3):
            before = self.ledger.get_remote_checkpoint_state()
            remote = self.bridge.fetch_expected_chain_head()
            after = self.ledger.get_remote_checkpoint_state()
            if before != after:
                continue

            local_sequence, local_hash, pending = after
            if pending is None:
                if (
                    remote.sequence != local_sequence
                    or remote.chain_hash != local_hash
                ):
                    raise IntegrityError(
                        "Remote checkpoint head differs from the verified local ledger."
                    )
                return "in_sync"

            if (
                remote.sequence == pending.sequence
                and remote.chain_hash == pending.chain_hash
            ):
                result: SyncResult = "reconciled"
            elif (
                remote.sequence == pending.sequence - 1
                and remote.chain_hash == pending.previous_hash
            ):
                result = "delivered"
            else:
                raise IntegrityError(
                    "Remote checkpoint head is inconsistent with the pending local outbox."
                )

            try:
                receipt = self.bridge.post_new_chain_head(
                    sequence=pending.sequence,
                    previous_hash=pending.previous_hash,
                    record_hash=pending.record_hash,
                    chain_hash=pending.chain_hash,
                    idempotency_key=pending.idempotency_key,
                )
            except Exception as exc:
                self.ledger.record_remote_checkpoint_failure(
                    pending.sequence, type(exc).__name__
                )
                raise

            self.ledger.mark_remote_checkpoint_delivered(
                receipt.sequence, receipt.checkpoint_id
            )
            return result

        raise RuntimeError(
            "Local outbox changed during remote reconciliation; retry synchronization."
        )

    def synchronize_one(self) -> SyncResult:
        """Verify the complete local ledger, then process one checkpoint."""
        self.ledger.verify()
        return self._synchronize_one()

    def synchronize(self, max_checkpoints: int = 100) -> int:
        """Drain up to max_checkpoints in order and return processed count."""
        if type(max_checkpoints) is not int or not 1 <= max_checkpoints <= 10_000:
            raise ValueError("max_checkpoints must be an integer from 1 to 10000.")
        self.ledger.verify()
        processed = 0
        while processed < max_checkpoints:
            result = self._synchronize_one()
            if result == "in_sync":
                break
            processed += 1
        return processed
