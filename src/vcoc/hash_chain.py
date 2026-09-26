"""Append-only, hash-linked, ECDSA-signed custody log.

Each entry's ``entry_hash`` covers its own payload plus the previous entry's
hash, so any change to an earlier entry (or to its position) changes every
subsequent hash — the same tamper-evidence property a blockchain gets from
its consensus layer, but here enforced purely by verification, since there
is only one custodian and no distributed agreement to reach.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from ecdsa import SigningKey, VerifyingKey

from .ecdsa_signer import sign_message, verify_signature
from .hashing import hash_bytes
from .models import CustodyEvent

GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class EntryVerification:
    """Per-entry verification result -- see HashChain.verify_each()."""

    index: int
    ok: bool
    reason: str


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
        actor: str,
        action: str,
        signing_key: SigningKey,
        evidence_id: str | None = None,
        evidence_ids: list[str] | None = None,
        case_number: str | None = None,
        tag: str | None = None,
        notes: str | None = None,
        timestamp: str | None = None,
    ) -> CustodyEvent:
        """Create, hash, sign, and append a new custody event.

        Exactly one of ``evidence_id`` (legacy, single) or ``evidence_ids``
        (new, one-or-more) must be given -- see CustodyEvent's docstring for
        why the two shapes are mutually exclusive and permanent per entry.
        """
        if (evidence_id is None) == (evidence_ids is None):
            raise ValueError("add_event requires exactly one of evidence_id or evidence_ids")

        if evidence_ids is not None:
            entry = CustodyEvent(
                index=len(self.entries),
                evidence_id="",
                evidence_ids=evidence_ids,
                actor=actor,
                action=action,
                timestamp=timestamp or utc_now_iso(),
                prev_hash=self.last_hash,
                case_number=case_number,
                tag=tag,
                notes=notes,
            )
        else:
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

    def verify_each(self, verifying_key: VerifyingKey) -> list[EntryVerification]:
        """Independently verify every entry, without stopping at the first
        break -- additive to verify()'s existing (ok, break_index, reason)
        contract, which every other caller keeps using unchanged.

        An entry downstream of a broken one is also reported not-ok: once an
        entry's own recomputed hash doesn't match what it claims, nothing
        chaining from it can be trusted either, even if that later entry's
        own payload/signature would otherwise check out.
        """
        results: list[EntryVerification] = []
        expected_prev = GENESIS_HASH
        upstream_broken = False
        for entry in self.entries:
            reasons = []
            if entry.prev_hash != expected_prev:
                reasons.append("prev_hash does not match preceding entry")

            recomputed_hash = hash_bytes(entry.canonical_payload().encode("utf-8"))
            if recomputed_hash != entry.entry_hash:
                reasons.append("entry_hash does not match recomputed payload hash")

            if not verify_signature(verifying_key, entry.entry_hash.encode("utf-8"), entry.signature):
                reasons.append("signature verification failed")

            if upstream_broken:
                reasons.append("upstream entry failed verification")

            ok = not reasons
            results.append(EntryVerification(index=entry.index, ok=ok, reason="; ".join(reasons) or "ok"))

            if not ok:
                upstream_broken = True
            expected_prev = entry.entry_hash

        return results

    def to_json(self) -> str:
        return json.dumps([e.to_dict() for e in self.entries], indent=2)

    def save(self, path: str | Path) -> None:
        Path(path).write_text(self.to_json(), encoding="utf-8")

    @staticmethod
    def load(path: str | Path) -> "HashChain":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        return HashChain([CustodyEvent.from_dict(d) for d in raw])
