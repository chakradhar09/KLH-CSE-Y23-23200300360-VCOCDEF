"""Task M3: the search screens read the evidence table with SQL (LIKE ... LIMIT, keyset paging) instead of holding the
whole index as dicts and re-filtering it in Python on every keystroke.

Measured on the real 832,299-row database: opening the list 0.1 ms (was a full index load), a common query 0.2-16 ms,
and a query that matches almost nothing ~0.4 s (a full scan; the in-memory search was ~250 ms per keystroke there too, and
held ~270 MB). `search()` stays as the reference: for ASCII queries the SQL result must be the same ids in the same order.
"""

from __future__ import annotations

import random
import sqlite3
import sys
import tracemalloc
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from prompt_toolkit.application import create_app_session
from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput

from vcoc import db
from vcoc.interactive import evidence_search
from vcoc.interactive.evidence_search import EvidenceSource, Pager, scroll_top, search

PGDN, PGUP, HOME, END, DOWN, UP, ENTER, ESC = "\x1b[6~", "\x1b[5~", "\x1b[H", "\x1b[F", "\x1b[B", "\x1b[A", "\r", "\x1b"

NASTY = {
    "EV001": ("Report.PDF", "a"),
    "EV002": ("report_final.pdf", "b"),
    "EV003": ("100%_done.txt", "c"),
    "EV004": ("back\\slash.bin", "d"),
    "EV005": ("bang!.bin", "e"),
    "EV006": ("naive.txt", "f"),
    "EV007": ("naïve café.txt", "g"),
    "EV008": ("CAFÉ.TXT", "h"),
    "ev009": ("lowercase id", "i"),
    "F1/sub/deep.bin": ("deep.bin", "j"),
}
NASTY_INDEX = {k: {"original_filename": f, "sha256": s * 64} for k, (f, s) in NASTY.items()}


def _db_from(index: dict, path: Path) -> sqlite3.Connection:
    conn = db.connect(path)
    with conn:
        conn.executemany(
            "INSERT INTO evidence (evidence_id, original_filename, sha256, size_bytes, added_at, source_path, folder_id)"
            " VALUES (?,?,?,?,?,?,?)",
            [(k, v["original_filename"], v["sha256"], 1, "t", "", None) for k, v in index.items()],
        )
    return conn


def _ids(rows) -> list[str]:
    return [r["evidence_id"] for r in rows]


def _all_pages(source: EvidenceSource, query: str, size: int = 3) -> list[dict]:
    """Walk the whole result with keyset pages only."""
    rows, key = [], None
    while True:
        page = source.forward(query, key, False, size)
        if not page:
            return rows
        rows += page
        key = page[-1]["evidence_id"]


@pytest.mark.parametrize(
    "query",
    ["", "ev", "EV0", "report", "REPORT", "%", "_", "!", "\\", "100%", "e_f", "back\\", "bang!", "ev00", "sub/", "naive",
     "zzz-none", " ", "."],
)
def test_ascii_queries_return_the_same_ids_in_the_same_order_as_search(tmp_path, query):
    conn = _db_from(NASTY_INDEX, tmp_path / "e.db")
    source = EvidenceSource(conn)

    want = _ids(search(NASTY_INDEX, query))

    assert _ids(source.forward(query, None, True, 1000)) == want
    assert _ids(_all_pages(source, query)) == want  # and page by page via keysets
    backwards = source.backward(query, None, True, 1000)
    assert _ids(backwards) == want  # backward pages come back in ascending order too


@pytest.mark.parametrize("query", ["é", "É", "café", "CAFÉ", "ï"])
def test_non_ascii_queries_still_match_like_search_does(tmp_path, query):
    conn = _db_from(NASTY_INDEX, tmp_path / "e.db")

    assert _ids(EvidenceSource(conn).forward(query, None, True, 1000)) == _ids(search(NASTY_INDEX, query))


def test_percent_and_underscore_in_a_query_are_literal_not_wildcards(tmp_path):
    conn = _db_from(NASTY_INDEX, tmp_path / "e.db")
    source = EvidenceSource(conn)

    assert _ids(source.forward("%", None, True, 100)) == ["EV003"]  # only "100%_done.txt"
    assert _ids(source.forward("_", None, True, 100)) == ["EV002", "EV003"]  # report_final, 100%_done


def test_matching_ids_keeps_only_the_checked_ids_that_match_the_query(tmp_path):
    conn = _db_from(NASTY_INDEX, tmp_path / "e.db")
    source = EvidenceSource(conn)

    assert source.matching_ids("report", {"EV001", "EV002", "EV003", "nope"}) == ["EV001", "EV002"]
    assert source.matching_ids("", {"EV003", "EV001"}) == ["EV001", "EV003"]  # sorted like the result list


# --- the pager keeps the old absolute-position behavior while only ever holding one window -----------------------


class _Reference:
    """What the screens did with the full result list in memory: absolute selection, minimal scrolling."""

    def __init__(self, results: list[dict], h: int):
        self.results, self.h, self.sel, self.top = results, h, 0, 0

    def apply(self, op: str) -> None:
        n, h = len(self.results), self.h
        if n:
            self.sel = {
                "down": min(n - 1, self.sel + 1),
                "up": max(0, self.sel - 1),
                "pgdn": min(n - 1, self.sel + h),
                "pgup": max(0, self.sel - h),
                "home": 0,
                "end": n - 1,
            }[op]
        self.top = scroll_top(self.top, self.sel, h, n)

    def window(self) -> list[str]:
        return _ids(self.results[self.top : self.top + self.h])


OPS = {"down": Pager.down, "up": Pager.up, "pgdn": Pager.page_down, "pgup": Pager.page_up, "home": Pager.home, "end": Pager.end}


@pytest.mark.parametrize("n, h", [(100, 7), (13, 7), (7, 7), (5, 7), (1, 7), (60, 30), (0, 7)])
def test_pager_selection_and_window_match_the_in_memory_behavior_over_a_random_walk(tmp_path, n, h):
    index = {f"EV{i:04d}": {"original_filename": f"f{i}.bin", "sha256": f"{i:064x}"} for i in range(n)}
    conn = _db_from(index, tmp_path / "e.db")
    pager = Pager(EvidenceSource(conn))
    pager.reset("", h)
    ref = _Reference(search(index, ""), h)
    rng = random.Random(n * 100 + h)

    for step in range(400):
        op = rng.choice(list(OPS))
        OPS[op](pager, h)
        ref.apply(op)
        assert (pager.current() or {}).get("evidence_id") == (ref.results[ref.sel]["evidence_id"] if n else None), (step, op)
        assert pager.window_ids() == ref.window(), (step, op)


def test_pager_resets_to_the_first_match_when_the_query_changes(tmp_path):
    conn = _db_from(NASTY_INDEX, tmp_path / "e.db")
    pager = Pager(EvidenceSource(conn))
    pager.reset("", 5)
    pager.end(5)

    pager.reset("report", 5)

    assert pager.window_ids() == ["EV001", "EV002"] and pager.current()["evidence_id"] == "EV001"


def test_navigation_never_uses_offset_and_holds_only_one_window(tmp_path):
    index = {f"EV{i:05d}": {"original_filename": f"f{i}.bin", "sha256": f"{i:064x}"} for i in range(3000)}
    conn = _db_from(index, tmp_path / "e.db")
    statements = []
    conn.set_trace_callback(statements.append)
    pager = Pager(EvidenceSource(conn))

    pager.reset("f1", 30)
    for op in (Pager.page_down, Pager.page_down, Pager.end, Pager.page_up, Pager.home, Pager.down, Pager.up):
        op(pager, 30)

    assert statements and not any("OFFSET" in s.upper() for s in statements)
    assert len(pager.rows) <= 30


def test_opening_the_pager_is_one_tiny_query_and_a_few_kilobytes(tmp_path):
    index = {f"EV{i:05d}": {"original_filename": f"file_{i}.bin", "sha256": f"{i:064x}"} for i in range(30_000)}
    conn = _db_from(index, tmp_path / "e.db")
    statements = []
    conn.set_trace_callback(statements.append)

    tracemalloc.start()
    try:
        pager = Pager(EvidenceSource(conn))
        pager.reset("", 30)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()

    assert len([s for s in statements if "FROM evidence" in s]) == 1
    assert peak < 256 * 1024  # the in-memory index held ~686 bytes per row: 20 MB here
    assert pager.window_ids()[0] == "EV00000" and len(pager.rows) == 30


# --- the screens -------------------------------------------------------------------------------------------------


def _run(fn, arg, keys: str):
    with create_pipe_input() as pipe_input:
        pipe_input.send_text(keys)
        with create_app_session(input=pipe_input, output=DummyOutput()):
            return fn(arg)


def test_db_screen_enter_returns_the_highlighted_record_and_a_typed_filter_narrows_it(tmp_path):
    conn = _db_from(NASTY_INDEX, tmp_path / "e.db")
    conn.close()
    path = str(tmp_path / "e.db")

    assert _run(evidence_search.search_evidence_db, path, ENTER) == "EV001"
    assert _run(evidence_search.search_evidence_db, path, "report" + DOWN + ENTER) == "EV002"
    assert _run(evidence_search.search_evidence_db, path, "deep" + ENTER) == "F1/sub/deep.bin"
    assert _run(evidence_search.search_evidence_db, path, "zzz-none" + ENTER) is None
    assert _run(evidence_search.search_evidence_db, path, ESC) is None


def test_db_screen_with_no_database_file_shows_nothing_and_creates_nothing(tmp_path):
    missing = tmp_path / "nope.db"

    assert _run(evidence_search.search_evidence_db, str(missing), ENTER) is None
    assert not missing.exists()


def test_db_multi_screen_checks_survive_filtering_and_only_visible_checked_ids_are_returned(tmp_path):
    conn = _db_from(NASTY_INDEX, tmp_path / "e.db")
    conn.close()
    path = str(tmp_path / "e.db")

    # check EV001, filter to "deep" and check that one, confirm: EV001 no longer matches the filter -> only the deep one
    assert _run(evidence_search.search_evidence_multi_db, path, " " + "deep" + " " + ENTER) == ["F1/sub/deep.bin"]
    # with the filter cleared again both are returned, in list order
    keys = " " + "deep" + " " + "\x7f" * 4 + ENTER
    assert _run(evidence_search.search_evidence_multi_db, path, keys) == ["EV001", "F1/sub/deep.bin"]


def test_db_screen_pages_through_a_big_table_and_enter_returns_the_true_record(tmp_path):
    index = {f"EV{i:05d}": {"original_filename": f"file{i}.bin", "sha256": f"{i:064x}"} for i in range(500)}
    _db_from(index, tmp_path / "e.db").close()
    path = str(tmp_path / "e.db")
    h = _run(lambda _: evidence_search._visible_height(), None, "")

    assert _run(evidence_search.search_evidence_db, path, PGDN + PGDN + ENTER) == f"EV{2 * h:05d}"
    assert _run(evidence_search.search_evidence_db, path, END + ENTER) == "EV00499"
    assert _run(evidence_search.search_evidence_db, path, END + PGUP + ENTER) == f"EV{499 - h:05d}"
    assert _run(evidence_search.search_evidence_db, path, END + HOME + ENTER) == "EV00000"
    assert _run(evidence_search.search_evidence_multi_db, path, PGDN + " " + END + " " + ENTER) == [f"EV{h:05d}", "EV00499"]


def test_the_in_memory_wrappers_still_work_for_an_index_dict():
    assert _run(evidence_search.search_evidence, NASTY_INDEX, DOWN + ENTER) == "EV002"
    assert _run(evidence_search.search_evidence_multi, NASTY_INDEX, " " + DOWN + " " + ENTER) == ["EV001", "EV002"]


def test_a_burst_of_typed_characters_runs_one_search_not_one_per_key(tmp_path, monkeypatch):
    """A query that matches almost nothing scans the whole table (~0.4 s at 832k rows). Keys typed while the screen is busy
    arrive together, so the search runs once for the whole burst instead of once per character."""
    _db_from(NASTY_INDEX, tmp_path / "e.db").close()
    queries = []
    real = EvidenceSource._rows
    monkeypatch.setattr(EvidenceSource, "_rows", lambda self, q, *a, **k: queries.append(q) or real(self, q, *a, **k))

    assert _run(evidence_search.search_evidence_db, str(tmp_path / "e.db"), "report" + ENTER) == "EV001"

    assert set(queries) <= {"", "report"}
    assert "r" not in queries and "rep" not in queries


def test_navigation_and_enter_act_on_the_query_that_was_just_typed(tmp_path):
    _db_from(NASTY_INDEX, tmp_path / "e.db").close()
    path = str(tmp_path / "e.db")

    # the filter is applied before Down / Enter are handled, even though the search itself runs once per burst
    assert _run(evidence_search.search_evidence_db, path, "report" + DOWN + ENTER) == "EV002"
    assert _run(evidence_search.search_evidence_db, path, "naive" + ENTER) == "EV006"
    assert _run(evidence_search.search_evidence_db, path, "caf" + END + ENTER) == "EV008"


# --- the screen stays responsive while typing: narrowing without scans, and scans on a worker thread ----------------
# Reported: "rendering of search is laggy after more than 3-4 characters". After 3-4 characters a query matches few rows,
# and a query that matches few rows scans the whole table (0.2-1.5 s at 832k rows) -- on the UI thread, on every key.

import threading
import time

from vcoc.interactive.evidence_search import SearchState


def _recording(monkeypatch):
    calls = []
    real = EvidenceSource.forward
    monkeypatch.setattr(
        EvidenceSource, "forward", lambda self, q, key, inclusive, limit: calls.append((q, key)) or real(self, q, key, inclusive, limit)
    )
    return calls


def test_narrow_returns_only_the_given_ids_that_match_in_id_order(tmp_path):
    source = EvidenceSource(_db_from(NASTY_INDEX, tmp_path / "e.db"))

    rows = source.narrow("report", ["EV003", "EV002", "EV001", "ev009"])

    assert _ids(rows) == ["EV001", "EV002"] and rows[0]["original_filename"] == "Report.PDF"
    assert source.narrow("", []) == []


def test_pager_does_not_query_again_at_the_end_of_a_result_it_already_holds_completely(tmp_path):
    conn = _db_from(NASTY_INDEX, tmp_path / "e.db")
    pager = Pager(EvidenceSource(conn))
    pager.reset("report", 30)  # 2 matches: the whole result is in the window
    statements = []
    conn.set_trace_callback(statements.append)

    for op in (Pager.down, Pager.down, Pager.down, Pager.page_down, Pager.page_down, Pager.up, Pager.up, Pager.page_up, Pager.page_up):
        op(pager, 30)

    assert [s for s in statements if "FROM evidence" in s] == []  # on a rare query each of these used to scan the table


def test_extending_a_complete_result_narrows_it_without_a_scan(tmp_path, monkeypatch):
    conn = _db_from(NASTY_INDEX, tmp_path / "e.db")
    state = SearchState(EvidenceSource(conn))
    state.ensure(30)  # the empty query: 10 rows < 30, so the window holds the complete result
    calls = _recording(monkeypatch)

    for text in ("r", "re", "rep", "repo", "report"):
        state.set_text(text)
        state.ensure(30)
        assert not state.busy

    assert calls == []  # every step was answered from the rows already shown (an id lookup), never a scan
    assert state.pager.window_ids() == ["EV001", "EV002"]


def test_narrowing_agrees_with_search_for_every_prefix_of_every_query(tmp_path):
    state = SearchState(EvidenceSource(_db_from(NASTY_INDEX, tmp_path / "e.db")))
    state.ensure(30)

    for word in ("report_final", "100%", "deep.bin", "bang!", "back\\s"):
        for end in range(1, len(word) + 1):
            state.set_text(word[:end])
            state.ensure(30)
            assert state.pager.window_ids() == _ids(search(NASTY_INDEX, word[:end])), word[:end]


def test_a_longer_query_over_an_incomplete_result_still_scans(tmp_path, monkeypatch):
    index = {f"EV{i:04d}": {"original_filename": f"f{i}.bin", "sha256": f"{i:064x}"} for i in range(200)}
    state = SearchState(EvidenceSource(_db_from(index, tmp_path / "e.db")))
    state.set_text("EV00")
    state.ensure(5)  # 100 matches, window of 5: NOT complete
    calls = _recording(monkeypatch)

    state.set_text("EV001")
    state.ensure(5)

    assert [q for q, _ in calls] == ["EV001"]
    assert state.pager.window_ids() == [f"EV001{d}" for d in range(5)]


def test_deleting_characters_widens_the_query_and_scans_again(tmp_path, monkeypatch):
    state = SearchState(EvidenceSource(_db_from(NASTY_INDEX, tmp_path / "e.db")))
    state.set_text("report")
    state.ensure(30)
    calls = _recording(monkeypatch)

    state.set_text("rep")
    state.ensure(30)

    assert [q for q, _ in calls] == ["rep"]


class _SlowSource:
    """A scan that blocks until released and raises like sqlite when interrupted."""

    def __init__(self):
        self.started: list[str] = []
        self.release: dict[str, threading.Event] = {}
        self.interrupted = threading.Event()
        self._interrupt_flag: dict[str, bool] = {}

    def gate(self, query: str) -> threading.Event:
        return self.release.setdefault(query, threading.Event())

    def forward(self, query, key, inclusive, limit):
        self.started.append(query)
        gate = self.gate(query)
        while not gate.wait(0.01):
            if self.interrupted.is_set():
                self.interrupted.clear()
                raise sqlite3.OperationalError("interrupted")
        return [{"evidence_id": f"{query}-hit", "original_filename": "f", "sha256": "0" * 64}]

    def interrupt(self):
        self.interrupted.set()

    def close(self):
        pass

    def backward(self, *a):  # unused here
        return []

    def narrow(self, query, ids):
        return []


def _wait_for(cond, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.005)
    return False


def test_a_slow_scan_never_blocks_the_caller_and_a_newer_key_cancels_the_older_scan(tmp_path):
    ui_source = EvidenceSource(_db_from(NASTY_INDEX, tmp_path / "e.db"))
    slow = _SlowSource()
    updates = []
    state = SearchState(ui_source, worker_source=slow, on_update=lambda: updates.append(1))
    try:
        state.set_text("abcd")
        started = time.perf_counter()
        state.ensure(30)  # hands the scan to the worker and returns at once
        assert time.perf_counter() - started < 0.2
        assert state.busy
        assert _wait_for(lambda: slow.started == ["abcd"])

        state.set_text("abcde")  # the next key arrives while "abcd" is still scanning
        state.ensure(30)
        assert _wait_for(lambda: slow.started == ["abcd", "abcde"])  # the first scan was interrupted, the new one began

        slow.gate("abcde").set()
        assert _wait_for(lambda: updates)
        state.ensure(30)

        assert not state.busy
        assert state.pager.window_ids() == ["abcde-hit"]  # nothing from the stale "abcd" scan is ever shown
    finally:
        state.close()


def test_settle_waits_for_the_scan_so_enter_acts_on_the_typed_query(tmp_path):
    ui_source = EvidenceSource(_db_from(NASTY_INDEX, tmp_path / "e.db"))
    slow = _SlowSource()
    state = SearchState(ui_source, worker_source=slow)
    try:
        state.set_text("zz")
        state.ensure(30)
        threading.Timer(0.15, slow.gate("zz").set).start()

        state.settle(30)

        assert not state.busy and state.pager.current()["evidence_id"] == "zz-hit"
    finally:
        state.close()


def test_a_real_file_database_is_searched_on_a_worker_thread_and_closed_cleanly(tmp_path):
    _db_from(NASTY_INDEX, tmp_path / "e.db").close()
    source, conn, worker_source = evidence_search._open_source(str(tmp_path / "e.db"), with_worker=True)
    state = SearchState(source, worker_source=worker_source)
    state.set_text("report")
    state.ensure(30)
    state.settle(30)

    assert state.pager.window_ids() == ["EV001", "EV002"]
    assert any(t.name == "vcoc-search" for t in threading.enumerate())

    state.close()
    conn.close()
    assert not any(t.name == "vcoc-search" for t in threading.enumerate())


def test_a_failing_scan_shows_an_error_instead_of_hanging(tmp_path):
    class Broken(_SlowSource):
        def forward(self, query, key, inclusive, limit):
            raise sqlite3.OperationalError("disk I/O error")

    state = SearchState(EvidenceSource(_db_from(NASTY_INDEX, tmp_path / "e.db")), worker_source=Broken())
    try:
        state.set_text("report")
        state.settle(30)

        assert state.pager.rows == [] and "disk I/O error" in state.error
        assert not state.busy
    finally:
        state.close()


# --- the "(searching...)" label must follow the real state by itself, not wait for the next key ---------------------
# Reported: it stayed on after the results were in and after the box was cleared, until the user navigated. The label is
# drawn BEFORE the results area, and only the results area brought the state up to date, so a redraw caused by the worker
# (or by clearing the box) drew the stale label first.


def _screen_rows(app, count: int = 14) -> list[str]:
    screen = app.renderer._last_screen
    if screen is None:  # nothing drawn yet
        return [""] * count
    out = []
    for y in range(count):
        row = screen.data_buffer.get(y, {})
        out.append("".join(row[x].char if x in row else " " for x in range(80)).rstrip())
    return out


def _wait_until(cond, timeout: float = 4.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.02)
    return False


def test_the_searching_label_disappears_by_itself_when_results_arrive_and_when_the_box_is_cleared(tmp_path, monkeypatch):
    index = {f"EV{i:04d}": {"original_filename": f"file{i}.bin", "sha256": "a" * 64} for i in range(300)}
    _db_from(index, tmp_path / "e.db").close()
    apps = []

    class Recording(evidence_search.Application):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            apps.append(self)

    monkeypatch.setattr(evidence_search, "Application", Recording)
    seen = {}

    def label_gone() -> bool:
        return bool(apps) and "searching" not in _screen_rows(apps[0])[1]

    def feeder(pipe_input):
        try:
            _wait_until(lambda: bool(apps) and "Query" in _screen_rows(apps[0])[1])
            for ch in "EV01":  # > 31 matches: a real scan on the worker thread, one per key
                pipe_input.send_text(ch)
                time.sleep(0.1)
            seen["after_typing"] = _wait_until(label_gone)  # no key pressed since: the label must go on its own
            seen["typing_rows"] = _screen_rows(apps[0])
            for _ in range(4):
                pipe_input.send_text("")  # clear the box
                time.sleep(0.1)
            seen["after_clearing"] = _wait_until(label_gone)
            seen["cleared_rows"] = _screen_rows(apps[0])
        except BaseException as exc:  # never leave the app running: report it below instead
            seen["error"] = repr(exc)
        finally:
            pipe_input.send_text(ESC)

    with create_pipe_input() as pipe_input, create_app_session(input=pipe_input, output=DummyOutput()):
        watchdog = threading.Timer(30, lambda: pipe_input.send_text(ESC))  # a test must never hang the suite
        watchdog.daemon = True
        watchdog.start()
        threading.Thread(target=feeder, args=(pipe_input,), daemon=True).start()
        evidence_search.search_evidence_db(str(tmp_path / "e.db"))
        watchdog.cancel()

    assert "error" not in seen, seen.get("error")
    assert seen["after_typing"], seen["typing_rows"]
    assert seen["after_clearing"], seen["cleared_rows"]
    assert "EV0100" in "\n".join(seen["typing_rows"])  # and the matches for EV01 are what is on screen
    assert "EV0000" in "\n".join(seen["cleared_rows"])  # and clearing the box shows the full list again


# --- the "(searching...)" label waits a moment before it shows, so fast scans never flash it ------------------------


class _Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


def test_the_searching_status_only_shows_once_a_scan_has_taken_longer_than_the_delay(tmp_path):
    clock = _Clock()
    slow = _SlowSource()
    state = SearchState(EvidenceSource(_db_from(NASTY_INDEX, tmp_path / "e.db")), worker_source=slow, clock=clock, delay=0.3)
    try:
        assert not state.show_searching()  # nothing typed yet
        state.set_text("zzzz")
        state.ensure(30)
        assert state.busy and not state.show_searching()  # just started: no flash

        clock.now += 0.29
        assert not state.show_searching()
        clock.now += 0.02
        assert state.show_searching()  # it has now taken longer than the delay

        slow.gate("zzzz").set()
        assert _wait_for(lambda: state._searcher._done is not None)
        state.ensure(30)
        assert not state.busy and not state.show_searching()
    finally:
        state.close()


def test_every_new_busy_period_starts_its_own_delay(tmp_path):
    clock = _Clock()
    slow = _SlowSource()
    state = SearchState(EvidenceSource(_db_from(NASTY_INDEX, tmp_path / "e.db")), worker_source=slow, clock=clock, delay=0.3)
    try:
        state.set_text("aaaa")
        state.ensure(30)
        clock.now += 1.0
        assert state.show_searching()

        slow.gate("aaaa").set()
        assert _wait_for(lambda: state._searcher._done is not None)
        state.ensure(30)
        state.set_text("bbbb")  # not an extension of "aaaa" (that would be narrowed instantly): a new scan, new delay
        state.ensure(30)

        assert state.busy and not state.show_searching()
    finally:
        state.close()


def test_a_redraw_is_scheduled_for_when_the_delay_runs_out(tmp_path):
    slow = _SlowSource()
    redraws = []
    state = SearchState(
        EvidenceSource(_db_from(NASTY_INDEX, tmp_path / "e.db")),
        worker_source=slow,
        on_update=lambda: redraws.append(time.monotonic()),
        delay=0.05,
    )
    try:
        state.set_text("qqqq")
        state.ensure(30)  # the scan is blocked: without a timer nothing would ever redraw the label
        assert _wait_for(lambda: redraws, timeout=1.0)
    finally:
        slow.gate("qqqq").set()
        state.close()


def _run_typing_session(tmp_path, monkeypatch, scan_seconds: float):
    """Type 'EV01' into a real headless app; return the label row sampled every few ms for the whole session."""
    index = {f"EV{i:04d}": {"original_filename": f"file{i}.bin", "sha256": "a" * 64} for i in range(300)}
    _db_from(index, tmp_path / "e.db").close()
    apps, samples, seen = [], [], {}

    class Recording(evidence_search.Application):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            apps.append(self)

    monkeypatch.setattr(evidence_search, "Application", Recording)
    real = EvidenceSource.forward

    def slow_forward(self, query, key, inclusive, limit):
        if query and scan_seconds:
            time.sleep(scan_seconds)
        return real(self, query, key, inclusive, limit)

    monkeypatch.setattr(EvidenceSource, "forward", slow_forward)

    def feeder(pipe_input):
        try:
            _wait_until(lambda: bool(apps) and "Query" in _screen_rows(apps[0])[1])
            for ch in "EV01":
                pipe_input.send_text(ch)
                time.sleep(0.05)
            end = time.monotonic() + scan_seconds * 4 + 1.0
            while time.monotonic() < end:
                samples.append(_screen_rows(apps[0])[1])
                time.sleep(0.01)
        except BaseException as exc:
            seen["error"] = repr(exc)
        finally:
            pipe_input.send_text(ESC)

    with create_pipe_input() as pipe_input, create_app_session(input=pipe_input, output=DummyOutput()):
        watchdog = threading.Timer(30, lambda: pipe_input.send_text(ESC))
        watchdog.daemon = True
        watchdog.start()
        threading.Thread(target=feeder, args=(pipe_input,), daemon=True).start()
        evidence_search.search_evidence_db(str(tmp_path / "e.db"))
        watchdog.cancel()
    assert "error" not in seen, seen.get("error")
    return samples


def test_fast_scans_never_flash_the_searching_label(tmp_path, monkeypatch):
    samples = _run_typing_session(tmp_path, monkeypatch, scan_seconds=0.1)  # quick, but long enough to be sampled

    assert samples and not any("searching" in row for row in samples)


def test_a_slow_scan_shows_the_label_after_the_delay_and_removes_it_when_done(tmp_path, monkeypatch):
    samples = _run_typing_session(tmp_path, monkeypatch, scan_seconds=0.9)  # each scan takes 0.9 s (> the 0.3 s delay)

    first = next(i for i, row in enumerate(samples) if "searching" in row)  # it does appear...
    assert "searching" not in samples[-1]  # ...and is gone at the end, with no key pressed
    assert first > 0 and "searching" not in samples[0]
