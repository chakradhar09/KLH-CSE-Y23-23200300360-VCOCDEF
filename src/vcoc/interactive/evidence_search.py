
from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

from prompt_toolkit import Application
from prompt_toolkit.application import get_app
from prompt_toolkit.buffer import Buffer
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import HSplit, Layout, Window
from prompt_toolkit.layout.controls import BufferControl, FormattedTextControl
from prompt_toolkit.layout.dimension import D
from prompt_toolkit.widgets import Frame

from vcoc import db


def search(index: dict, query: str) -> list[dict]:
    q = query.lower()
    results = [
        {
            "evidence_id": eid,
            "original_filename": rec.get("original_filename", ""),
            "sha256": rec.get("sha256", ""),
        }
        for eid, rec in index.items()
    ]
    if q:
        results = [r for r in results if q in r["evidence_id"].lower() or q in r["original_filename"].lower()]
    results.sort(key=lambda r: r["evidence_id"])
    return results


def _format_result(entry: dict, selected: bool) -> str:
    marker = "▸" if selected else " "
    eid = entry["evidence_id"].ljust(10)
    fname = entry["original_filename"][:28].ljust(28)
    return f"{marker} {eid} {fname} {entry['sha256'][:8]}..."


def _format_result_multi(entry: dict, selected: bool, checked: bool) -> str:
    marker = "▸" if selected else " "
    box = "[x]" if checked else "[ ]"
    eid = entry["evidence_id"].ljust(10)
    fname = entry["original_filename"][:28].ljust(28)
    return f"{marker} {box} {eid} {fname} {entry['sha256'][:8]}..."


_CHROME_ROWS = 9  # frame borders + query label/box + help line + position line around the results


def _visible_height() -> int:
    try:
        rows = get_app().output.get_size().rows
    except Exception:
        rows = 40
    return max(5, rows - _CHROME_ROWS)


def scroll_top(top: int, selected: int, height: int, total: int) -> int:
    """First visible row: the smallest scroll that keeps `selected` on screen, never past the end."""
    top = min(top, max(total - height, 0))
    if selected < top:
        top = selected
    elif selected >= top + height:
        top = selected - height + 1
    return max(top, 0)


def window_text(
    results: list, format_row, selected: int, top: list[int], height: int, footer: bool = True
) -> str:
    """Render only the visible rows (cost is O(height), not O(len(results))) plus a `from-to of total` line."""
    total = len(results)
    if not total:
        return "  (no matches)"
    top[0] = scroll_top(top[0], selected, height, total)
    end = min(top[0] + height, total)
    lines = [format_row(results[i], i) for i in range(top[0], end)]
    if footer:
        lines.append(f"  {top[0] + 1:,}-{end:,} of {total:,}")
    return "\n".join(lines)


def _add_jump_keys(kb: KeyBindings, selected: list[int], total) -> None:
    """PgUp/PgDn move by a screenful; Home/End jump to the first/last row (arrows alone cannot cross 92k rows)."""

    @kb.add("pageup")
    def _(event):
        if total():
            selected[0] = max(0, selected[0] - _visible_height())

    @kb.add("pagedown")
    def _(event):
        if total():
            selected[0] = min(total() - 1, selected[0] + _visible_height())

    @kb.add("home")
    def _(event):
        selected[0] = 0

    @kb.add("end")
    def _(event):
        if total():
            selected[0] = total() - 1


def _like_escape(text: str) -> str:
    return text.replace("!", "!!").replace("%", "!%").replace("_", "!_")


class EvidenceSource:
    """Reads the evidence table a page at a time: SQL `LIKE ... LIMIT` with keyset paging (never OFFSET), nothing cached.

    For ASCII queries the rows and their order equal `search()` (substring of id or file name, case-insensitive, sorted by
    id). A query with non-ASCII characters goes through a Python lower() so it matches exactly like `search()` too (slower).
    No schema change and no index beyond the primary key: a query that matches almost nothing scans the table.
    """

    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn
        conn.create_function("vcoc_lower", 1, lambda v: v.lower() if isinstance(v, str) else v, deterministic=True)

    def _match(self, query: str) -> tuple[str, list]:
        if not query:
            return "", []
        if query.isascii():
            pattern = f"%{_like_escape(query)}%"
            return "(evidence_id LIKE ? ESCAPE '!' OR original_filename LIKE ? ESCAPE '!')", [pattern, pattern]
        lowered = query.lower()
        return "(instr(vcoc_lower(evidence_id), ?) > 0 OR instr(vcoc_lower(original_filename), ?) > 0)", [lowered, lowered]

    def _rows(self, query: str, key, op: str, order: str, limit: int) -> list[dict]:
        where, params = self._match(query)
        conds = [where] if where else []
        if key is not None:
            conds.append(f"evidence_id {op} ?")
            params.append(key)
        sql = "SELECT evidence_id, original_filename, sha256 FROM evidence"
        if conds:
            sql += " WHERE " + " AND ".join(conds)
        sql += f" ORDER BY evidence_id {order} LIMIT ?"
        params.append(limit)
        return [
            {"evidence_id": r[0], "original_filename": r[1], "sha256": r[2]} for r in self._conn.execute(sql, params)
        ]

    def forward(self, query: str, key: str | None, inclusive: bool, limit: int) -> list[dict]:
        """Up to `limit` matching rows from `key` on (ascending); key=None starts at the first row."""
        return self._rows(query, key, ">=" if inclusive else ">", "ASC", limit)

    def backward(self, query: str, key: str | None, inclusive: bool, limit: int) -> list[dict]:
        """Up to `limit` matching rows up to `key` (returned ascending); key=None ends at the last row."""
        return self._rows(query, key, "<=" if inclusive else "<", "DESC", limit)[::-1]

    def narrow(self, query: str, ids) -> list[dict]:
        """Of the rows with these ids, the ones matching `query`, in id order: a few primary-key lookups, never a scan."""
        ids = sorted(ids)
        where, match_params = self._match(query)
        rows: list[dict] = []
        for start in range(0, len(ids), 500):
            chunk = ids[start : start + 500]
            sql = (
                "SELECT evidence_id, original_filename, sha256 FROM evidence"
                f" WHERE evidence_id IN ({','.join('?' * len(chunk))})"
            )
            if where:
                sql += f" AND {where}"
            rows += [
                {"evidence_id": r[0], "original_filename": r[1], "sha256": r[2]}
                for r in self._conn.execute(sql, [*chunk, *match_params])
            ]
        return sorted(rows, key=lambda r: r["evidence_id"])

    def matching_ids(self, query: str, ids) -> list[str]:
        """The ids (sorted) that also match `query`: what is still visible of a multi-selection after filtering."""
        return [r["evidence_id"] for r in self.narrow(query, ids)]

    def interrupt(self) -> None:
        self._conn.interrupt()  # callable from another thread: aborts the statement running on this connection

    def close(self) -> None:
        self._conn.close()


class Pager:
    """One window of the result and a selection inside it, moved with keyset queries.

    Behaves like absolute selection over the full sorted result with minimal scrolling (a random-walk test pins that),
    but holds at most one window of rows, so a 800,000-row table costs a few KB and opens instantly.
    `exhausted_before/after` record that no matching row exists beyond the window: once a rare query has been fully read,
    moving to its ends costs nothing (it used to scan the rest of the table every time).
    """

    def __init__(self, source: EvidenceSource):
        self.source = source
        self.query = ""
        self.rows: list[dict] = []
        self.sel = 0
        self.exhausted_before = True
        self.exhausted_after = True

    def window_ids(self) -> list[str]:
        return [r["evidence_id"] for r in self.rows]

    def current(self) -> dict | None:
        return self.rows[self.sel] if self.rows else None

    @property
    def complete(self) -> bool:
        """True when the window holds EVERY row matching the query."""
        return self.exhausted_before and self.exhausted_after

    def apply(self, query: str, rows: list[dict], h: int, complete: bool = False) -> None:
        """Show `rows` (the first window of `query`'s result) with the first row selected."""
        self.query, self.rows, self.sel = query, rows, 0
        self.exhausted_before, self.exhausted_after = True, complete or len(rows) < h

    def reset(self, query: str, h: int) -> None:
        self.apply(query, self.source.forward(query, None, True, h), h)

    def home(self, h: int) -> None:
        self.reset(self.query, h)

    def end(self, h: int) -> None:
        self.rows = self.source.backward(self.query, None, True, h)
        self.sel = max(len(self.rows) - 1, 0)
        self.exhausted_before, self.exhausted_after = len(self.rows) < h, True

    def down(self, h: int) -> None:
        if not self.rows:
            return
        if self.sel < len(self.rows) - 1:
            self.sel += 1
            return
        if self.exhausted_after:
            return
        more = self.source.forward(self.query, self.rows[-1]["evidence_id"], False, 1)
        if not more:
            self.exhausted_after = True
            return
        self.rows = (self.rows[1:] if len(self.rows) >= h else self.rows) + more
        self.sel = len(self.rows) - 1
        self.exhausted_before = False

    def up(self, h: int) -> None:
        if not self.rows:
            return
        if self.sel > 0:
            self.sel -= 1
            return
        if self.exhausted_before:
            return
        before = self.source.backward(self.query, self.rows[0]["evidence_id"], False, 1)
        if not before:
            self.exhausted_before = True
            return
        self.rows = before + (self.rows[:-1] if len(self.rows) >= h else self.rows)
        self.sel = 0
        self.exhausted_after = False

    def page_down(self, h: int) -> None:
        if not self.rows:
            return
        if self.exhausted_after:  # everything after the selection is already in the window
            self.sel = min(len(self.rows) - 1, self.sel + h)
            return
        after = self.source.forward(self.query, self.rows[self.sel]["evidence_id"], False, h)
        if not after:
            self.exhausted_after = True
            return
        # the row h places further on (or the last row): the new window ends on it
        self.rows = self.source.backward(self.query, after[-1]["evidence_id"], True, h)
        self.sel = len(self.rows) - 1
        self.exhausted_before, self.exhausted_after = len(self.rows) < h, len(after) < h

    def page_up(self, h: int) -> None:
        if not self.rows:
            return
        if self.exhausted_before:
            self.sel = max(0, self.sel - h)
            return
        before = self.source.backward(self.query, self.rows[self.sel]["evidence_id"], False, h)
        if not before:
            self.exhausted_before = True
            return
        # the row h places back (or the first row): the new window starts on it
        rows = self.source.forward(self.query, before[0]["evidence_id"], True, h)
        extra = self.source.backward(self.query, rows[0]["evidence_id"], False, h - len(rows)) if len(rows) < h else []
        self.rows, self.sel = extra + rows, len(extra)
        self.exhausted_before, self.exhausted_after = len(before) < h, len(rows) < h


class _Searcher:
    """Runs scans on a worker thread so the screen never waits for one.

    Only the newest request matters: a new request interrupts the scan in progress (sqlite3 `interrupt`) and replaces
    anything still waiting, and a result that is no longer the newest is never handed out.
    """

    def __init__(self, source, on_update):
        self._src = source
        self._on_update = on_update
        self._cv = threading.Condition()
        self._pending = None  # (query, h) waiting for the worker
        self._running = None  # (query, h) the worker is scanning
        self._done = None  # (query, rows, error) of the newest finished scan, until taken
        self._closed = False
        self._thread = threading.Thread(target=self._loop, daemon=True, name="vcoc-search")
        self._thread.start()

    def request(self, query: str, h: int) -> None:
        with self._cv:
            self._pending, self._done = (query, h), None
            if self._running is not None:
                self._src.interrupt()
            self._cv.notify_all()

    def take(self):
        with self._cv:
            done, self._done = self._done, None
            return done

    def wait_idle(self, timeout: float = 60.0) -> None:
        with self._cv:
            self._cv.wait_for(lambda: self._pending is None and self._running is None, timeout)

    def close(self) -> None:
        with self._cv:
            self._closed = True
            self._pending = None
            if self._running is not None:
                self._src.interrupt()
            self._cv.notify_all()
        self._thread.join(10)
        self._src.close()

    def _loop(self) -> None:
        while True:
            with self._cv:
                self._cv.wait_for(lambda: self._pending is not None or self._closed)
                if self._closed:
                    return
                request, self._pending = self._pending, None
                self._running = request
            query, h = request
            rows, error = [], None
            try:
                rows = self._src.forward(query, None, True, h)
            except sqlite3.OperationalError as exc:
                if "interrupt" in str(exc).lower():
                    with self._cv:
                        self._running = None
                        if self._pending is None and not self._closed:
                            self._pending = request  # a stray interrupt hit the newest request: run it again
                        self._cv.notify_all()
                    continue
                error = str(exc)
            except Exception as exc:  # a broken scan must not leave the screen waiting for ever
                error = str(exc)
            with self._cv:
                self._running = None
                if self._pending is None:  # still the newest
                    self._done = (query, rows, error)
                self._cv.notify_all()
            self._on_update()


class SearchState:
    """What the search screen shows for what is typed, without ever blocking on a table scan while typing.

    * Typing only records the wanted text (`set_text`); `ensure` brings the window up to date and never waits.
    * A longer query over a result that is already complete (every match is in the window) can only narrow it: answered
      from those few rows with primary-key lookups, no scan. That covers every key after the matches fit on one screen.
    * Anything else is scanned on a worker thread (`worker_source`, its own connection); until the answer arrives the
      old rows stay on screen and `busy` is True. Without a worker the scan runs in `ensure` (small in-memory tables).
    * `settle` waits for the answer: Enter and the movement keys use it, so they always act on what was typed.
    """

    def __init__(self, source: EvidenceSource, worker_source=None, on_update=None, clock=time.monotonic, delay: float = 0.3):
        self.pager = Pager(source)
        self.error: str | None = None
        self._source = source
        self._on_update = on_update
        self._clock = clock
        self._delay = delay  # the screen says "searching" only after this long without a keystroke and without an answer
        self._changed_at: float | None = None
        self._timer: threading.Timer | None = None
        self._wanted = ""
        self._shown: str | None = None  # the query the pager's rows answer
        self._asked: str | None = None  # the query last handed to the worker
        self._searcher = _Searcher(worker_source, on_update or (lambda: None)) if worker_source is not None else None

    @property
    def busy(self) -> bool:
        return self._shown != self._wanted

    def set_text(self, text: str) -> None:
        if text != self._wanted:
            self._wanted = text
            self._touched()

    def refresh(self) -> None:
        """Run the current query again (Ctrl-R), even though it is what is shown."""
        self._shown = self._asked = None
        self._touched()

    def _touched(self) -> None:
        """A keystroke: restart the quiet period after which "searching" may be shown, and ask for the redraw that will
        show it (nothing else redraws a screen that is just waiting)."""
        self._changed_at = self._clock()
        if self._timer is not None:
            self._timer.cancel()
        if self._on_update is not None:
            self._timer = threading.Timer(self._delay, self._on_update)
            self._timer.daemon = True
            self._timer.start()

    def show_searching(self) -> bool:
        """Whether to SAY it is searching: only when the typing has paused for the delay and the answer is still not in,
        so quick scans (and a burst of typing whose answers are arriving) never flash the status."""
        return self.busy and self._changed_at is not None and self._clock() - self._changed_at >= self._delay

    def ensure(self, h: int) -> None:
        self._sync(h)

    def _sync(self, h: int) -> None:
        if self._searcher is not None:
            done = self._searcher.take()
            if done is not None and done[0] == self._wanted:
                query, rows, error = done
                self.error = error
                self.pager.apply(query, rows, h)
                self._shown = query
        if self._shown == self._wanted:
            return
        wanted = self._wanted
        if self._shown is not None and wanted.startswith(self._shown) and self.pager.complete and self.error is None:
            narrowed = self._source.narrow(wanted, [r["evidence_id"] for r in self.pager.rows])
            self.pager.apply(wanted, narrowed, h, complete=True)
            self._shown = wanted
        elif self._searcher is None or wanted == "":  # no worker, or the empty query: one tiny index read
            self.error = None
            self.pager.reset(wanted, h)
            self._shown = wanted
        elif self._asked != wanted:
            self._searcher.request(wanted, h)
            self._asked = wanted

    def settle(self, h: int) -> None:
        self.ensure(h)
        if self.busy and self._searcher is not None:
            self._searcher.wait_idle()
            self.ensure(h)

    def close(self) -> None:
        if self._timer is not None:
            self._timer.cancel()
        if self._searcher is not None:
            self._searcher.close()


def _open_source(db_path: str | None, with_worker: bool = False):
    """(source, connection, worker_source): the evidence table of `db_path`. A missing file is an empty table and is not
    created. `worker_source` (only for a real file, when asked) has its own connection for scans on a worker thread."""
    if db_path and Path(db_path).exists():
        conn = db.connect(db_path)
        worker = None
        if with_worker:
            worker = EvidenceSource(sqlite3.connect(db_path, check_same_thread=False))
        return EvidenceSource(conn), conn, worker
    conn = sqlite3.connect(":memory:")
    conn.executescript(db.SCHEMA)
    return EvidenceSource(conn), conn, None


def _index_source(index: dict):
    """An in-memory table of an already loaded index dict (the original API of the two screens)."""
    source, conn, _ = _open_source(None)
    with conn:
        conn.executemany(
            "INSERT INTO evidence (evidence_id, original_filename, sha256, size_bytes, added_at) VALUES (?,?,?,0,'')",
            [(eid, rec.get("original_filename", ""), rec.get("sha256", "")) for eid, rec in index.items()],
        )
    return source, conn, None


def _run_search(source: EvidenceSource, multi: bool, worker_source=None):
    query_buf = Buffer(multiline=False)
    holder: list[Application] = []
    state = SearchState(source, worker_source, on_update=lambda: holder and holder[0].invalidate())
    pager = state.pager
    checked: set[str] = set()

    def get_results_text():
        state.ensure(_visible_height())
        h = _visible_height()
        rows = pager.rows
        if state.error:
            return f"  Search failed: {state.error}"
        if not rows:
            if state.busy:
                return "  (searching...)" if state.show_searching() else ""
            return "  (no matches)"
        first = scroll_top(0, pager.sel, h, len(rows))
        lines = []
        for i in range(first, min(first + h, len(rows))):
            entry = rows[i]
            if multi:
                lines.append(_format_result_multi(entry, i == pager.sel, entry["evidence_id"] in checked))
            else:
                lines.append(_format_result(entry, i == pager.sel))
        return "\n".join(lines)

    def get_query_label():
        # Drawn BEFORE the results, so it must bring the state up to date itself: otherwise a redraw caused by the worker
        # finishing (or by clearing the box) drew the stale "(searching...)" and nothing redrew it until the next key.
        state.ensure(_visible_height())
        return " Query:   (searching...)" if state.show_searching() else " Query:"

    query_buf.on_text_changed += lambda _=None: state.set_text(query_buf.text)

    kb = KeyBindings()

    def move(method):
        def handler(event):
            state.settle(_visible_height())
            method(pager, _visible_height())

        return handler

    kb.add("up")(move(Pager.up))
    kb.add("down")(move(Pager.down))
    kb.add("pageup")(move(Pager.page_up))
    kb.add("pagedown")(move(Pager.page_down))
    kb.add("home")(move(Pager.home))
    kb.add("end")(move(Pager.end))

    if multi:

        @kb.add(" ")
        def _(event):
            state.settle(_visible_height())
            row = pager.current()
            if row is not None:
                checked.symmetric_difference_update({row["evidence_id"]})

    @kb.add("enter")
    def _(event):
        state.settle(_visible_height())
        row = pager.current()
        if multi:
            if checked:  # the checked ids that the current filter still shows, in list order
                event.app.exit(result=source.matching_ids(pager.query, checked))
            else:
                event.app.exit(result=[row["evidence_id"]] if row else None)
        else:
            event.app.exit(result=row["evidence_id"] if row else None)

    @kb.add("c-r")
    @kb.add("f5")
    def _(event):
        state.refresh()

    @kb.add("escape")
    @kb.add("c-c")
    def _(event):
        event.app.exit(result=None)

    if multi:
        help_text = " ↑/↓ select   PgUp/PgDn/Home/End jump   Space toggle   Enter confirm   Esc cancel"
        title = "Search / Browse Evidence (multi-select)"
    else:
        help_text = " ↑/↓ select   PgUp/PgDn/Home/End jump   Enter choose   Ctrl-R/F5 refresh   Esc cancel"
        title = "Search / Browse Evidence"
    body = HSplit(
        [
            Window(FormattedTextControl(get_query_label), height=1),
            Frame(Window(BufferControl(buffer=query_buf)), height=D(min=3, max=3)),
            Window(FormattedTextControl(get_results_text)),
            Window(FormattedTextControl(lambda: help_text), height=1),
        ]
    )
    app = Application(layout=Layout(Frame(body, title=title)), key_bindings=kb, full_screen=True)
    holder.append(app)
    try:
        return app.run()
    finally:
        state.close()


def _search_screen(opened, multi: bool):
    source, conn, worker_source = opened
    try:
        return _run_search(source, multi, worker_source)
    finally:
        conn.close()


def search_evidence_db(db_path: str | None):
    """Single-select search over the evidence table of `db_path` (read a page at a time); the chosen id, or None."""
    return _search_screen(_open_source(db_path, with_worker=True), multi=False)


def search_evidence_multi_db(db_path: str | None):
    """Multi-select search over the evidence table of `db_path`; the confirmed ids, or None."""
    return _search_screen(_open_source(db_path, with_worker=True), multi=True)


def search_evidence(index: dict) -> str | None:
    return _search_screen(_index_source(index), multi=False)


def search_evidence_multi(index: dict) -> list[str] | None:
    return _search_screen(_index_source(index), multi=True)
