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
    """One append-only, hash-linked, ECDSA-signed custody log entry.

    Two mutually-exclusive shapes, disambiguated by which field is set:
    legacy entries carry a single ``evidence_id`` string (today's format,
    already signed in real custody logs); new entries carry
    ``evidence_ids`` (a list, one-or-more) plus optional
    ``case_number``/``tag``/``notes``. A ``CustodyEvent`` never changes
    shape after creation (the log is append-only), so which field is
    populated is a permanent, sufficient marker -- no version field needed.
    ``canonical_payload()`` branches on shape so legacy entries keep
    hashing to their already-recorded, already-signed ``entry_hash``
    forever.
    """

    index: int
    evidence_id: str
    actor: str
    action: str
    timestamp: str  # ISO 8601 UTC
    prev_hash: str
    evidence_ids: list[str] | None = field(default=None)
    case_number: str | None = field(default=None)
    tag: str | None = field(default=None)
    notes: str | None = field(default=None)
    entry_hash: str = field(default="")
    signature: str = field(default="")

    def canonical_payload(self) -> str:
        """Deterministic string representation used for hashing/signing.

        Field order and separators are fixed so the same logical entry
        always produces the same bytes, independent of dict/JSON key
        ordering.
        """
        if self.evidence_ids is None:
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
        return "|".join(
            [
                str(self.index),
                ",".join(self.evidence_ids),
                self.actor,
                self.action,
                self.timestamp,
                self.prev_hash,
                self.case_number or "",
                self.tag or "",
                self.notes or "",
            ]
        )

    def to_dict(self) -> dict:
        data = {
            "index": self.index,
            "actor": self.actor,
            "action": self.action,
            "timestamp": self.timestamp,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
            "signature": self.signature,
        }
        if self.evidence_ids is None:
            data["evidence_id"] = self.evidence_id
        else:
            data["evidence_ids"] = self.evidence_ids
            if self.case_number is not None:
                data["case_number"] = self.case_number
            if self.tag is not None:
                data["tag"] = self.tag
            if self.notes is not None:
                data["notes"] = self.notes
        return data

    @staticmethod
    def from_dict(data: dict) -> "CustodyEvent":
        if "evidence_ids" in data:
            return CustodyEvent(
                index=data["index"],
                evidence_id="",
                evidence_ids=data["evidence_ids"],
                actor=data["actor"],
                action=data["action"],
                timestamp=data["timestamp"],
                prev_hash=data["prev_hash"],
                case_number=data.get("case_number"),
                tag=data.get("tag"),
                notes=data.get("notes"),
                entry_hash=data.get("entry_hash", ""),
                signature=data.get("signature", ""),
            )
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
