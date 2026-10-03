"""What the main menu's header says: the evidence database and the *last known* result of a chain verification.

It never verifies anything. The result comes from `shell_config.json` (written when a chain check finishes) and is
compared with cheap read-only counts, so adding evidence or logging an event after a verification shows as stale
instead of leaving an old "clean" on screen. The database is only opened read-only and is never created here.
"""

from __future__ import annotations

import os
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from . import config

_WIDTH = 78  # columns inside a frame on an 80-column terminal
_SEP = "  │  "


@dataclass(frozen=True)
class Counts:
    items: int  # evidence rows
    events: int  # custody events
    evidence_max: int  # highest evidence rowid: grows whenever evidence is added


@dataclass(frozen=True)
class ChainStatus:
    state: str  # clean | stale | tamper | unverified | nodb | unavailable
    db_name: str
    items: int
    verified_at: float | None
    new: int  # evidence rows and custody events added since the verification
    bad_event: int | None


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
    return Counts(items, events, evidence_max)


def current_status(shell_config: dict, db_path: str) -> ChainStatus:
    name = os.path.basename(db_path)
    if not os.path.exists(db_path):
        return ChainStatus("nodb", name, 0, None, 0, None)
    counts = read_counts(db_path)
    if counts is None:
        return ChainStatus("unavailable", name, 0, None, 0, None)
    record = config.last_verify(shell_config, db_path)
    if record is None:
        return ChainStatus("unverified", name, counts.items, None, 0, None)
    new = max(0, counts.events - record["events"]) + max(0, counts.evidence_max - record["evidence_max"])
    state = "tamper" if not record["ok"] else "stale" if new else "clean"  # a tamper verdict outlives anything added later
    return ChainStatus(state, name, counts.items, record["at"], new, record["bad_event"])


def record_chain_check(shell_config, db_path: str, oks: list[bool], indexes: list[int], now: float | None = None, config_path: str | None = None) -> None:
    """Remember a finished chain verification: whether every event checked out, and what the database held at the time."""
    counts = read_counts(db_path)
    if shell_config is None or counts is None:
        return
    bad = next((index for ok, index in zip(oks, indexes) if not ok), None)
    record = {
        "at": time.time() if now is None else now,
        "ok": bad is None,
        "events": len(oks),
        "bad_event": bad,
        "evidence_max": counts.evidence_max,
        "db": db_path,
    }
    config.record_last_verify(shell_config, record, config_path)


def _clock(at: float, now: float | None) -> str:
    then, today = time.localtime(at), time.localtime(time.time() if now is None else now)
    return time.strftime("%H:%M" if then[:3] == today[:3] else "%m-%d %H:%M", then)


def header_text(status: ChainStatus, now: float | None = None) -> str:
    """One line for the top of the menu, at most 78 columns; a long database name is shortened to make room."""
    if status.state == "nodb":
        rest = ["not created yet"]
    elif status.state == "unavailable":
        rest = ["status unavailable"]
    else:
        when = _clock(status.verified_at, now) if status.verified_at is not None else ""
        chain = {
            "clean": f"chain ● CLEAN · verified {when}",
            "stale": f"chain ◐ STALE · {status.new:,} new since {when}",
            "tamper": f"chain ✖ TAMPER · " + (f"event #{status.bad_event} · " if status.bad_event is not None else "") + when,
            "unverified": "chain ○ not verified yet",
        }[status.state]
        rest = [f"{status.items:,} items", chain]
    tail = "".join(_SEP + part for part in rest)
    room = _WIDTH - len(" DB ") - len(tail)
    name = status.db_name if len(status.db_name) <= room else status.db_name[: max(room - 1, 1)] + "…"
    return f" DB {name}{tail}"
