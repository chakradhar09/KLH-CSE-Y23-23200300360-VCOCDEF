"""Shared data structures for evidence records and custody-log entries."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Evidence:
    """A single piece of digital evidence tracked by the system."""

    evidence_id: str
    original_filename: str
    sha256: str
    size_bytes: int
    added_at: str  # ISO 8601 UTC timestamp
    source_path: str = field(default="")  # resolved path at collection time
    folder_id: str | None = field(default=None)  # set when registered as part of a folder batch


@dataclass
class CustodyEvent:
    """One append-only, hash-linked, ECDSA-signed custody log entry."""

    index: int
    evidence_id: str
    actor: str
    action: str
    timestamp: str  # ISO 8601 UTC
    prev_hash: str
    entry_hash: str = field(default="")
    signature: str = field(default="")

    def canonical_payload(self) -> str:
        """Deterministic string representation used for hashing/signing.

        Field order and separators are fixed so the same logical entry
        always produces the same bytes, independent of dict/JSON key
        ordering.
        """
        return "|".join(
            [
                str(self.index),
                self.evidence_id,
                self.actor,
                self.action,
                self.timestamp,
                self.prev_hash,
            ]
        )

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "evidence_id": self.evidence_id,
            "actor": self.actor,
            "action": self.action,
            "timestamp": self.timestamp,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
            "signature": self.signature,
        }

    @staticmethod
    def from_dict(data: dict) -> "CustodyEvent":
        return CustodyEvent(
            index=data["index"],
            evidence_id=data["evidence_id"],
            actor=data["actor"],
            action=data["action"],
            timestamp=data["timestamp"],
            prev_hash=data["prev_hash"],
            entry_hash=data.get("entry_hash", ""),
            signature=data.get("signature", ""),
        )
