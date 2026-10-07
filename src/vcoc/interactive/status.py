"""What the main menu's header says: the evidence database and the *last known* result of a chain verification.

It never verifies anything. The result comes from `shell_config.json` (written when a chain check finishes) and is
compared with cheap read-only counts, so adding evidence or logging an event after a verification shows as stale
instead of leaving an old "clean" on screen. The database is only opened read-only and is never created here.
"""

from __future__ import annotations

import os
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import config

_WIDTH = 78  # columns inside a frame on an 80-column terminal
_SEP = "  │  "


@dataclass(frozen=True)
class Counts:
    items: int  # evidence rows
    events: int  # custody events
    evidence_max: int  # highest evidence rowid: grows whenever evidence is added
    first_hash: str = field(default="", compare=False)  # entry_hash of custody event #0 ("" if none): tells one log from another


@dataclass(frozen=True)
class ChainStatus:
    state: str  # clean | stale | tamper | shortened | unverified | nodb | unavailable
    db_name: str
    items: int
    verified_at: float | None
    new: int  # evidence rows and custody events added since the verification
    bad_event: int | None
    removed: int = 0  # custody events gone from the end of the log since the most that were ever verified (state "shortened")
    # The last evidence check (files re-hashed against their recorded sha256), separate from the chain's verdict:
    files: str = "none"  # none | unchecked | clean | stale | tamper | issues
    files_n: int = 0  # files behind the verdict (tampered, not logged or unverifiable), or rows added since a stale check
    files_kind: str = ""  # TAMPERED | NOT LOGGED | UNVERIFIABLE
    files_at: float | None = None

    @property
    def frame_state(self) -> str:
        """What the menu frame shows: the worse of the chain and the files, "tamper" over "stale", else nothing."""
        states = (self.state, self.files)
        return "tamper" if "tamper" in states or "shortened" in states else "stale" if "stale" in states else ""


_items_cache: dict[str, tuple[int, int]] = {}  # db path -> (highest evidence rowid, row count) at the last full count


def _count_items(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]


def read_counts(db_path: str) -> Counts | None:
    """Row counts through a read-only connection; None if the file is missing, locked or not a vcoc database.

    Counting 92,879 evidence rows takes 1.7 ms, the header's only real cost, so the count is reused while the highest
    evidence rowid (which grows whenever evidence is added) is unchanged. Custody events are append-only with indexes
    0..n-1, so their count is the highest index plus one: no scan.
    """
    if not os.path.exists(db_path):
        return None
    try:
        conn = sqlite3.connect(Path(db_path).resolve().as_uri() + "?mode=ro", uri=True, timeout=0.2)
        try:
            evidence_max = conn.execute("SELECT COALESCE(MAX(rowid), 0) FROM evidence").fetchone()[0]
            events = conn.execute("SELECT COALESCE(MAX(idx) + 1, 0) FROM custody_log").fetchone()[0]
            first = conn.execute("SELECT entry_hash FROM custody_log WHERE idx = 0").fetchone()  # a primary-key lookup
            cached = _items_cache.get(db_path)
            if cached is not None and cached[0] == evidence_max:
                items = cached[1]
            else:
                items = _count_items(conn)
                _items_cache[db_path] = (evidence_max, items)
        finally:
            conn.close()
    except sqlite3.Error:
        return None
    return Counts(items, events, evidence_max, first[0] if first else "")


def removed_events(record: dict, counts: Counts) -> int:
    """Custody events gone from the end of the log since the most that were ever verified.

    The log only grows, so a shorter one means its newest events were deleted; the events that remain still verify, which is
    why a chain check alone cannot see it. Not counted: a different log (its first event differs: the database was started
    over) and an empty database (a new one)."""
    first = record.get("first_hash")
    if first and counts.first_hash and first != counts.first_hash:
        return 0
    if counts.events == 0 and counts.items == 0:
        return 0
    return max(0, record.get("high_water", record["events"]) - counts.events)


def _files_status(shell_config: dict, db_path: str, counts: Counts) -> dict:
    """The ChainStatus fields for the last evidence check; worst first, and a tamper verdict outlives anything added later."""
    record = config.last_evidence_check(shell_config, db_path)
    if record is None:
        return {"files": "unchecked" if counts.items else "none"}
    at = record["at"]
    if record["tampered"]:
        return {"files": "tamper", "files_n": record["tampered"], "files_kind": "TAMPERED", "files_at": at}
    new = max(0, counts.events - record["events"]) + max(0, counts.evidence_max - record["evidence_max"])
    if new:  # a new event can log a file that was not logged, so the counts below may no longer hold
        return {"files": "stale", "files_n": new, "files_at": at}
    for key, kind in (("not_logged", "NOT LOGGED"), ("unverifiable", "UNVERIFIABLE")):
        if record[key]:
            return {"files": "issues", "files_n": record[key], "files_kind": kind, "files_at": at}
    return {"files": "clean", "files_at": at}


def current_status(shell_config: dict, db_path: str) -> ChainStatus:
    name = os.path.basename(db_path)
    if not os.path.exists(db_path):
        return ChainStatus("nodb", name, 0, None, 0, None)
    counts = read_counts(db_path)
    if counts is None:
        return ChainStatus("unavailable", name, 0, None, 0, None)
    files = _files_status(shell_config, db_path, counts)
    record = config.last_verify(shell_config, db_path)
    if record is None:
        return ChainStatus("unverified", name, counts.items, None, 0, None, **files)
    new = max(0, counts.events - record["events"]) + max(0, counts.evidence_max - record["evidence_max"])
    removed = removed_events(record, counts)
    state = "tamper" if not record["ok"] else "shortened" if removed else "stale" if new else "clean"  # tamper outlives anything added later
    return ChainStatus(state, name, counts.items, record["at"], new, record["bad_event"], removed, **files)


def record_chain_check(shell_config, db_path: str, oks: list[bool], indexes: list[int], now: float | None = None, config_path: str | None = None) -> None:
    """Remember a finished chain verification: whether every event checked out, and what the database held at the time."""
    counts = read_counts(db_path)
    if shell_config is None or counts is None:
        return
    bad = next((index for ok, index in zip(oks, indexes) if not ok), None)
    before = config.last_verify(shell_config, db_path)  # this database's earlier verification, if any
    if before and before.get("first_hash") and counts.first_hash and before["first_hash"] != counts.first_hash:
        before = None  # a different log (the database was started over): its mark starts from nothing
    record = {
        "at": time.time() if now is None else now,
        "ok": bad is None,
        "events": len(oks),
        "bad_event": bad,
        "evidence_max": counts.evidence_max,
        "db": db_path,
        # the most events ever verified: it never drops, so cutting the log short stays visible after checking the rest
        "high_water": max(len(oks), before.get("high_water", before["events"]) if before else 0),
        "first_hash": counts.first_hash,
    }
    config.record_last_verify(shell_config, record, config_path)


def record_evidence_check(
    shell_config, db_path: str, counts: Counts | None, total: int, tampered: int, not_logged: int, unverifiable: int,
    now: float | None = None, config_path: str | None = None,
) -> None:
    """Remember a finished evidence check. `counts` is what the database held when the check BEGAN, so evidence added while
    the files were re-hashing shows as new afterwards instead of being counted as checked."""
    if shell_config is None or counts is None:
        return
    record = {
        "at": time.time() if now is None else now,
        "db": db_path,
        "total": total,
        "tampered": tampered,
        "not_logged": not_logged,
        "unverifiable": unverifiable,
        "events": counts.events,
        "evidence_max": counts.evidence_max,
    }
    config.record_evidence_check(shell_config, record, config_path)


def _clock(at: float, now: float | None) -> str:
    then, today = time.localtime(at), time.localtime(time.time() if now is None else now)
    return time.strftime("%H:%M" if then[:3] == today[:3] else "%m-%d %H:%M", then)


def _files_text(status: ChainStatus) -> str | None:
    n, kind = f"{status.files_n:,}", status.files_kind
    return {
        "clean": "files ● ALL GREEN",
        "stale": f"files ◐ STALE · {n} new",
        "tamper": f"files ✖ {n} {kind}",  # only the worst kind: the Evidence screen has the full breakdown
        "issues": f"files ◐ {n} {kind}",
        "unchecked": "files ○ unchecked",
    }.get(status.files)


def header_text(status: ChainStatus, now: float | None = None) -> str:
    """One line for the top of the menu, at most 78 columns; a long database name is shortened to make room.

    With a files segment the chain text is shortened first ("verified" and the "since" clock go), then the item count is
    dropped, and only then the database name; without one the line is exactly the chain's."""
    if status.state == "nodb":
        variants = [["not created yet"]]
    elif status.state == "unavailable":
        variants = [["status unavailable"]]
    else:
        when = _clock(status.verified_at, now) if status.verified_at is not None else ""
        items, files = f"{status.items:,} items", _files_text(status)
        verbose = {
            "clean": f"chain ● CLEAN · verified {when}",
            "stale": f"chain ◐ STALE · {status.new:,} new since {when}",
            "tamper": f"chain ✖ TAMPER · " + (f"event #{status.bad_event} · " if status.bad_event is not None else "") + when,
            "shortened": f"chain ✖ SHORTENED · {status.removed:,} event{'s' * (status.removed != 1)} gone since {when}",
            "unverified": "chain ○ not verified yet",
        }[status.state]
        variants = [[items, verbose]]
        if files is not None:
            compact = {
                "clean": f"chain ● CLEAN {when}",
                "stale": f"chain ◐ STALE · {status.new:,} new",
                "tamper": "chain ✖ TAMPER" + (f" · event #{status.bad_event}" if status.bad_event is not None else ""),
                "shortened": f"chain ✖ SHORTENED · {status.removed:,} gone",
                "unverified": "chain ○ unverified",
            }[status.state]
            variants = [[items, verbose, files], [items, compact, files], [compact, files]]
    for rest in variants:
        tail = "".join(_SEP + part for part in rest)
        if len(" DB ") + len(status.db_name) + len(tail) <= _WIDTH:
            return f" DB {status.db_name}{tail}"
    room = _WIDTH - len(" DB ") - len(tail)  # the last, shortest variant: the name gives way
    return f" DB {status.db_name[: max(room - 1, 1)]}…{tail}"
