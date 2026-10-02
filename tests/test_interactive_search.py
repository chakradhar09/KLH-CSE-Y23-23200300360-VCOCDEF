"""evidence_search.search: substring filter over the evidence table."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from vcoc.interactive.evidence_search import search

INDEX = {
    "EV002": {"original_filename": "beta.bin", "sha256": "b" * 64},
    "EV001": {"original_filename": "alpha.bin", "sha256": "a" * 64},
}


def test_empty_query_returns_all_sorted_by_id():
    assert [r["evidence_id"] for r in search(INDEX, "")] == ["EV001", "EV002"]


def test_query_matches_id_or_filename_case_insensitively():
    assert len(search(INDEX, "ev00")) == 2
    assert [r["evidence_id"] for r in search(INDEX, "ALPHA")] == ["EV001"]


def test_no_match_returns_empty():
    assert search(INDEX, "nomatch") == []


def test_result_carries_sha256():
    assert search(INDEX, "beta")[0]["sha256"] == "b" * 64


# --- Task 6: the list renders only the visible window (was: one string of EVERY result per redraw) -----
# Measured on the real 92,879-row DB: 143 ms per Up/Down redraw vs 3.9 ms at 300 records. Rendering must
# cost O(rows on screen), not O(records), and PgUp/PgDn/Home/End must reach any record.

from prompt_toolkit.application import create_app_session
from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput

PGDN, PGUP, HOME, END, DOWN, ENTER = "\x1b[6~", "\x1b[5~", "\x1b[H", "\x1b[F", "\x1b[B", "\r"


def _big_index(n: int) -> dict:
    return {f"EV{i:05d}": {"original_filename": f"file{i}.bin", "sha256": f"{i:064x}"} for i in range(n)}


def _run_single(index: dict, keys: str):
    from vcoc.interactive import evidence_search

    with create_pipe_input() as pipe_input:
        pipe_input.send_text(keys)
        with create_app_session(input=pipe_input, output=DummyOutput()):
            return evidence_search.search_evidence(index)


def _height() -> int:
    from vcoc.interactive import evidence_search

    with create_pipe_input() as pipe_input, create_app_session(input=pipe_input, output=DummyOutput()):
        return evidence_search._visible_height()


def test_scroll_top_keeps_the_selection_visible_with_minimal_movement():
    from vcoc.interactive.evidence_search import scroll_top

    assert scroll_top(top=0, selected=5, height=10, total=100) == 0  # already visible: no movement
    assert scroll_top(top=0, selected=10, height=10, total=100) == 1  # one below the window: scroll by one
    assert scroll_top(top=40, selected=39, height=10, total=100) == 39  # one above the window
    assert scroll_top(top=0, selected=99, height=10, total=100) == 90  # jump to the end: last page
    assert scroll_top(top=90, selected=0, height=10, total=100) == 0  # jump to the start


def test_scroll_top_never_scrolls_past_the_end_when_results_shrink():
    from vcoc.interactive.evidence_search import scroll_top

    assert scroll_top(top=90, selected=2, height=10, total=12) == 2  # 100 results filtered down to 12
    assert scroll_top(top=50, selected=0, height=10, total=3) == 0


def test_window_text_formats_only_the_visible_rows_and_reports_position():
    from vcoc.interactive.evidence_search import window_text

    formatted = []

    def fmt(entry, i):
        formatted.append(i)
        return f"row {i}"

    results = [{"evidence_id": f"EV{i}"} for i in range(20_000)]
    top = [0]
    text = window_text(results, fmt, selected=0, top=top, height=30)

    assert len(formatted) == 30  # NOT 20,000
    assert text.splitlines()[:2] == ["row 0", "row 1"]
    assert text.splitlines()[-1].strip() == "1-30 of 20,000"

    formatted.clear()
    text = window_text(results, fmt, selected=19_999, top=top, height=30)
    assert formatted == list(range(19_970, 20_000))
    assert text.splitlines()[-1].strip() == "19,971-20,000 of 20,000"


def test_window_text_empty_results():
    from vcoc.interactive.evidence_search import window_text

    assert window_text([], lambda e, i: "x", selected=0, top=[0], height=30) == "  (no matches)"


def test_single_select_renders_only_a_window_of_a_20k_list(monkeypatch):
    from vcoc.interactive import evidence_search

    calls = []
    real = evidence_search._format_result
    monkeypatch.setattr(evidence_search, "_format_result", lambda e, s: calls.append(1) or real(e, s))

    result = _run_single(_big_index(20_000), DOWN * 3 + ENTER)

    assert result == "EV00003"
    assert len(calls) <= 50 * (_height() + 1)  # a handful of redraws x one window; before: 20,000 per redraw


def test_pagedown_pageup_home_end_reach_the_true_record_and_enter_returns_it():
    index = _big_index(500)
    h = _height()

    assert _run_single(index, PGDN + ENTER) == f"EV{h:05d}"
    assert _run_single(index, PGDN + PGDN + ENTER) == f"EV{2 * h:05d}"
    assert _run_single(index, END + ENTER) == "EV00499"
    assert _run_single(index, END + PGUP + ENTER) == f"EV{499 - h:05d}"
    assert _run_single(index, END + HOME + ENTER) == "EV00000"
    assert _run_single(index, PGUP + ENTER) == "EV00000"  # already at the top: stays


def test_pagedown_stops_at_the_last_record():
    assert _run_single(_big_index(10), PGDN + PGDN + ENTER) == "EV00009"
