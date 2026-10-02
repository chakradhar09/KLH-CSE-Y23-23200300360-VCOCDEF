from __future__ import annotations

import codecs
import itertools
import json
import sqlite3
from pathlib import Path

from .models import CustodyEvent, Evidence

SCHEMA_VERSION = 1

_HAS_BLOBOPEN = hasattr(sqlite3.Connection, "blobopen")  # Python 3.11+: incremental BLOB/TEXT reads

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
    if conn.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
        # Only a new/old database is stamped: an unconditional write here made every plain read wait for (and block) others
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


def get_evidence(conn: sqlite3.Connection, evidence_id: str) -> dict | None:
    row = conn.execute("SELECT * FROM evidence WHERE evidence_id = ?", (evidence_id,)).fetchone()
    return None if row is None else dict(row)


def get_folder(conn: sqlite3.Connection, folder_id: str) -> dict | None:
    row = conn.execute("SELECT * FROM folders WHERE folder_id = ?", (folder_id,)).fetchone()
    return None if row is None else {"root": row["root"], "member_ids": json.loads(row["member_ids"])}


def member_hashes(conn: sqlite3.Connection, folder_id: str) -> dict[str, str]:
    cur = conn.cursor()
    cur.row_factory = None  # plain tuples: a big folder has ~90k rows and sqlite3.Row objects cost ~15% more
    return dict(cur.execute("SELECT evidence_id, sha256 FROM evidence WHERE folder_id = ?", (folder_id,)))


def _group_sql(counts: bool) -> str:
    count_sql = "CASE WHEN f.folder_id IS NULL THEN NULL ELSE json_array_length(f.member_ids) END" if counts else "NULL"
    return (
        "WITH groups AS (SELECT COALESCE(NULLIF(folder_id, ''), evidence_id) AS gid FROM evidence GROUP BY 1)"
        f" SELECT g.gid, COALESCE(f.root, e.sha256), {count_sql}"
        " FROM groups g LEFT JOIN folders f ON f.folder_id = g.gid LEFT JOIN evidence e ON e.evidence_id = g.gid"
        " ORDER BY g.gid"
    )


def iter_group_leaves(conn: sqlite3.Connection):
    """(group id, leaf hash) per top-level group in id order, streamed from a cursor (no list of every group)."""
    cur = conn.cursor()
    cur.row_factory = None  # plain tuples
    for gid, leaf, _ in cur.execute(_group_sql(False)):
        if leaf is None:
            raise KeyError(gid)  # a folder id with neither a folders row nor an evidence row (corrupt data)
        yield gid, leaf


def iter_json_strings(chunks):
    """The strings of a JSON array of strings, read from an iterable of UTF-8 byte chunks.

    Holds one chunk plus the string being read, never the whole array: the member_ids of a 416,000-file folder are
    ~40 MB of JSON. Chunks may split a multi-byte character or an escape anywhere. Raises ValueError on anything else.
    """
    decode = json.JSONDecoder().raw_decode
    utf8 = codecs.getincrementaldecoder("utf-8")()
    chunks = iter(chunks)
    buf, pos, eof = "", 0, False

    def refill() -> bool:
        nonlocal buf, pos, eof
        if eof:
            return False
        try:
            text = utf8.decode(next(chunks))
        except StopIteration:
            eof, text = True, utf8.decode(b"", final=True)
        buf, pos = buf[pos:] + text, 0
        return True

    def skip_space() -> bool:
        nonlocal pos
        while True:
            while pos < len(buf) and buf[pos] in " \t\r\n":
                pos += 1
            if pos < len(buf):
                return True
            if not refill():
                return False

    if not skip_space() or buf[pos] != "[":
        raise ValueError("not a JSON array")
    pos += 1
    first = True
    while True:
        if not skip_space():
            raise ValueError("unterminated JSON array")
        if buf[pos] == "]":
            return
        if not first:
            if buf[pos] != ",":
                raise ValueError("expected , or ] in the JSON array")
            pos += 1
            if not skip_space():
                raise ValueError("unterminated JSON array")
        if buf[pos] != '"':
            raise ValueError("a JSON array of strings was expected")
        while True:
            try:
                value, end = decode(buf, pos)
                break
            except json.JSONDecodeError:
                if not refill():  # the string may just continue in the next chunk
                    raise ValueError("unterminated JSON string") from None
        pos, first = end, False
        yield value


def _member_id_chunks(conn: sqlite3.Connection, folder_id: str, chunk_size: int):
    row = conn.execute("SELECT rowid FROM folders WHERE folder_id = ?", (folder_id,)).fetchone()
    if row is None:
        raise KeyError(folder_id)
    if _HAS_BLOBOPEN:
        with conn.blobopen("folders", "member_ids", row[0], readonly=True) as blob:
            while chunk := blob.read(chunk_size):
                yield chunk
    else:  # no incremental reads before Python 3.11: the whole text at once
        yield conn.execute("SELECT member_ids FROM folders WHERE rowid = ?", (row[0],)).fetchone()[0].encode("utf-8")


def iter_member_leaves(conn: sqlite3.Connection, folder_id: str, chunk_size: int = 1 << 20):
    """(member id, sha256) for every member of a folder, in the stored member order, in constant memory.

    The ids are streamed out of the stored JSON and merged with one ordered scan of the evidence table (the members are
    stored in id order). Rows that are not members (left over from an earlier registration) are skipped, and a member
    the scan does not meet in order is looked up by its primary key. Raises KeyError for an unknown folder or a member
    without an evidence row.
    """
    ids = iter_json_strings(_member_id_chunks(conn, folder_id, chunk_size))
    first = next(ids, None)
    if first is None:
        return
    cur = conn.cursor()
    cur.row_factory = None
    cur.execute("SELECT evidence_id, sha256 FROM evidence WHERE evidence_id >= ? ORDER BY evidence_id", (first,))
    row = cur.fetchone()
    for member in itertools.chain([first], ids):
        while row is not None and row[0] < member:
            row = cur.fetchone()
        if row is not None and row[0] == member:
            yield member, row[1]
            continue
        found = conn.execute("SELECT sha256 FROM evidence WHERE evidence_id = ?", (member,)).fetchone()
        if found is None:
            raise KeyError(member)
        yield member, found[0]


def group_leaves(conn: sqlite3.Connection, counts: bool = True) -> list[tuple[str, str, int | None]]:
    """(group id, leaf hash, member count) per top-level group, sorted by id, without loading every evidence row.

    A folder is one group whose leaf is its Merkle root (count = its member_ids length); a standalone file is its own
    group whose leaf is its sha256 (count = None). Same grouping as `cli._build_main_tree`.
    `counts=False` leaves every count None and never parses `member_ids`: json_array_length parses the whole JSON text
    of each folder (a 215 MiB peak at 832,000 members), so callers that only need the leaves should not pay for it.
    """
    rows = conn.execute(_group_sql(counts)).fetchall()
    for gid, leaf, _ in rows:
        if leaf is None:
            raise KeyError(gid)  # a folder id with neither a folders row nor an evidence row (corrupt data)
    return [(gid, leaf, count) for gid, leaf, count in rows]


def begin_folder(conn: sqlite3.Connection) -> None:
    """Start a streamed folder write: nothing is committed until `finish_folder`; closing or rolling back discards it all."""
    conn.execute("DROP TABLE IF EXISTS temp._folder_run")
    conn.execute("CREATE TEMP TABLE _folder_run (evidence_id TEXT PRIMARY KEY) WITHOUT ROWID")


def add_folder_members(conn: sqlite3.Connection, members: list[Evidence]) -> None:
    """Insert one batch inside the still-open transaction (no commit)."""
    conn.executemany(_EVIDENCE_SQL, [_evidence_row(m) for m in members])
    conn.executemany("INSERT INTO temp._folder_run (evidence_id) VALUES (?)", [(m.evidence_id,) for m in members])


def finish_folder(conn: sqlite3.Connection, folder_id: str, root: str) -> None:
    """Write the folders row (member_ids built by SQLite from this run's members, in id order) and commit everything."""
    conn.execute(
        "INSERT OR REPLACE INTO folders (folder_id, root, member_ids)"
        " SELECT ?, ?, json_group_array(evidence_id) FROM (SELECT evidence_id FROM temp._folder_run ORDER BY evidence_id)",
        (folder_id, root),
    )
    conn.commit()
    conn.execute("DROP TABLE temp._folder_run")


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
