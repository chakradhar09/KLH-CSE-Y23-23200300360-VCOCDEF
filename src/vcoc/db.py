from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .models import CustodyEvent, Evidence

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS custody_log (
    idx          INTEGER PRIMARY KEY,
    evidence_id  TEXT,
    evidence_ids TEXT,
    actor        TEXT NOT NULL,
    action       TEXT NOT NULL,
    timestamp    TEXT NOT NULL,
    prev_hash    TEXT NOT NULL,
    case_number  TEXT,
    tag          TEXT,
    notes        TEXT,
    entry_hash   TEXT NOT NULL,
    signature    TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS custody_log_no_update BEFORE UPDATE ON custody_log
BEGIN SELECT RAISE(ABORT, 'custody_log is append-only'); END;

CREATE TRIGGER IF NOT EXISTS custody_log_no_delete BEFORE DELETE ON custody_log
BEGIN SELECT RAISE(ABORT, 'custody_log is append-only'); END;

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id       TEXT PRIMARY KEY,
    original_filename TEXT NOT NULL,
    sha256            TEXT NOT NULL,
    size_bytes        INTEGER NOT NULL,
    added_at          TEXT NOT NULL,
    source_path       TEXT NOT NULL DEFAULT '',
    folder_id         TEXT
);

CREATE TABLE IF NOT EXISTS folders (
    folder_id  TEXT PRIMARY KEY,
    root       TEXT NOT NULL,
    member_ids TEXT NOT NULL
);
"""


def connect(path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    conn.commit()
    return conn


def event_to_row(entry: CustodyEvent) -> tuple:
    return (
        entry.index,
        entry.evidence_id if entry.evidence_ids is None else None,
        None if entry.evidence_ids is None else json.dumps(entry.evidence_ids),
        entry.actor,
        entry.action,
        entry.timestamp,
        entry.prev_hash,
        entry.case_number,
        entry.tag,
        entry.notes,
        entry.entry_hash,
        entry.signature,
    )


def row_to_event(row: sqlite3.Row) -> CustodyEvent:
    data = {
        "index": row["idx"],
        "actor": row["actor"],
        "action": row["action"],
        "timestamp": row["timestamp"],
        "prev_hash": row["prev_hash"],
        "entry_hash": row["entry_hash"],
        "signature": row["signature"],
    }
    if row["evidence_ids"] is None:
        data["evidence_id"] = row["evidence_id"]
    else:
        data["evidence_ids"] = json.loads(row["evidence_ids"])
        for key in ("case_number", "tag", "notes"):
            if row[key] is not None:
                data[key] = row[key]
    return CustodyEvent.from_dict(data)


def insert_events(conn: sqlite3.Connection, entries: list[CustodyEvent]) -> None:
    with conn:
        conn.executemany(
            "INSERT INTO custody_log (idx, evidence_id, evidence_ids, actor, action, timestamp, prev_hash,"
            " case_number, tag, notes, entry_hash, signature) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            [event_to_row(e) for e in entries],
        )


def load_events(conn: sqlite3.Connection) -> list[CustodyEvent]:
    return [row_to_event(r) for r in conn.execute("SELECT * FROM custody_log ORDER BY idx")]


_EVIDENCE_SQL = (
    "INSERT OR REPLACE INTO evidence (evidence_id, original_filename, sha256, size_bytes, added_at,"
    " source_path, folder_id) VALUES (?,?,?,?,?,?,?)"
)


def _evidence_row(e: Evidence) -> tuple:
    return (e.evidence_id, e.original_filename, e.sha256, e.size_bytes, e.added_at, e.source_path, e.folder_id)


def put_evidence(conn: sqlite3.Connection, evidence: Evidence) -> None:
    with conn:
        conn.execute(_EVIDENCE_SQL, _evidence_row(evidence))


def load_evidence_index(conn: sqlite3.Connection) -> dict:
    return {r["evidence_id"]: Evidence(**dict(r)).__dict__ for r in conn.execute("SELECT * FROM evidence")}


def put_folder(
    conn: sqlite3.Connection, folder_id: str, root: str, member_ids: list[str], members: list[Evidence] = ()
) -> None:
    with conn:
        conn.executemany(_EVIDENCE_SQL, [_evidence_row(m) for m in members])
        conn.execute(
            "INSERT OR REPLACE INTO folders (folder_id, root, member_ids) VALUES (?,?,?)",
            (folder_id, root, json.dumps(member_ids)),
        )


def load_folder_index(conn: sqlite3.Connection) -> dict:
    return {
        r["folder_id"]: {"root": r["root"], "member_ids": json.loads(r["member_ids"])}
        for r in conn.execute("SELECT * FROM folders")
    }
