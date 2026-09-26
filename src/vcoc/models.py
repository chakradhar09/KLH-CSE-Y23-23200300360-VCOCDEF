
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Evidence:

    evidence_id: str
    original_filename: str
    sha256: str
    size_bytes: int
    added_at: str
    source_path: str = field(default="")
    folder_id: str | None = field(default=None)


@dataclass
class CustodyEvent:

    index: int
    evidence_id: str
    actor: str
    action: str
    timestamp: str
    prev_hash: str
    evidence_ids: list[str] | None = field(default=None)
    case_number: str | None = field(default=None)
    tag: str | None = field(default=None)
    notes: str | None = field(default=None)
    entry_hash: str = field(default="")
    signature: str = field(default="")

    def canonical_payload(self) -> str:
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
