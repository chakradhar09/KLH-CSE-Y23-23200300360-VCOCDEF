"""Append-only, hash-linked, ECDSA-signed custody log.

Each entry's ``entry_hash`` covers its own payload plus the previous entry's
hash, so any change to an earlier entry (or to its position) changes every
subsequent hash — the same tamper-evidence property a blockchain gets from
its consensus layer, but here enforced purely by verification, since there
is only one custodian and no distributed agreement to reach.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from ecdsa import SigningKey, VerifyingKey

from .ecdsa_signer import sign_message, verify_signature
from .hashing import hash_bytes
from .models import CustodyEvent

GENESIS_HASH = "0" * 64


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class HashChain:
    """In-memory append-only custody log with load/save to JSON."""

    def __init__(self, entries: list[CustodyEvent] | None = None):
        self.entries: list[CustodyEvent] = entries or []

    @property
    def last_hash(self) -> str:
        return self.entries[-1].entry_hash if self.entries else GENESIS_HASH

    def add_event(
        self,
        evidence_id: str,
        actor: str,
        action: str,
        signing_key: SigningKey,
        timestamp: str | None = None,
    ) -> CustodyEvent:
        """Create, hash, sign, and append a new custody event."""
        entry = CustodyEvent(
            index=len(self.entries),
            evidence_id=evidence_id,
            actor=actor,
            action=action,
            timestamp=timestamp or utc_now_iso(),
            prev_hash=self.last_hash,
        )
        entry.entry_hash = hash_bytes(entry.canonical_payload().encode("utf-8"))
        entry.signature = sign_message(signing_key, entry.entry_hash.encode("utf-8"))
        self.entries.append(entry)
        return entry

    def verify(self, verifying_key: VerifyingKey) -> tuple[bool, int | None, str]:
        """Recompute hashes/signatures for every entry from scratch.

        Returns ``(ok, break_index, reason)``. ``break_index`` is the index
        of the first entry that fails verification, or ``None`` if the
        whole chain is valid.
        """
        expected_prev = GENESIS_HASH
        for entry in self.entries:
            if entry.prev_hash != expected_prev:
                return False, entry.index, "prev_hash does not match preceding entry"

            recomputed_hash = hash_bytes(entry.canonical_payload().encode("utf-8"))
            if recomputed_hash != entry.entry_hash:
                return False, entry.index, "entry_hash does not match recomputed payload hash"

            if not verify_signature(verifying_key, entry.entry_hash.encode("utf-8"), entry.signature):
                return False, entry.index, "signature verification failed"

            expected_prev = entry.entry_hash

        return True, None, "chain verified"

    def to_json(self) -> str:
        return json.dumps([e.to_dict() for e in self.entries], indent=2)

    def save(self, path: str | Path) -> None:
        Path(path).write_text(self.to_json(), encoding="utf-8")

    @staticmethod
    def load(path: str | Path) -> "HashChain":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        return HashChain([CustodyEvent.from_dict(d) for d in raw])
