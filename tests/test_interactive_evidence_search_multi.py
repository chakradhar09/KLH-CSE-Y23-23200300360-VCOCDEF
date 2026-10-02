"""Headless tests for vcoc.interactive.evidence_search.search_evidence_multi
(no real TTY) -- Space-toggle multi-select, additive to the existing
single-select search_evidence."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from prompt_toolkit.application import create_app_session
from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput

from vcoc.interactive import evidence_search

INDEX = {
    "EV001": {"original_filename": "a.bin", "sha256": "a" * 64},
    "EV002": {"original_filename": "b.bin", "sha256": "b" * 64},
    "EV003": {"original_filename": "c.bin", "sha256": "c" * 64},
}


def run_multi_select(keys: str) -> list[str] | None:
    with create_pipe_input() as pipe_input:
        pipe_input.send_text(keys)
        with create_app_session(input=pipe_input, output=DummyOutput()):
            return evidence_search.search_evidence_multi(INDEX)


def test_space_toggle_two_rows_then_enter_returns_both():
    # down to EV002, space-toggle, down to EV003, space-toggle, enter
    result = run_multi_select(" " + "\x1b[B" + " " + "\r")
    assert result == ["EV001", "EV002"]


def test_enter_with_nothing_toggled_returns_just_highlighted_row():
    result = run_multi_select("\r")
    assert result == ["EV001"]


def test_escape_cancels_and_returns_none():
    result = run_multi_select("\x1b")
    assert result is None


# --- Task 6: multi-select renders only the visible window and supports PgUp/PgDn/Home/End -----------

PGDN, PGUP, HOME, END, ENTER = "\x1b[6~", "\x1b[5~", "\x1b[H", "\x1b[F", "\r"


def _big_index(n: int) -> dict:
    return {f"EV{i:05d}": {"original_filename": f"file{i}.bin", "sha256": f"{i:064x}"} for i in range(n)}


def _run_multi(index: dict, keys: str):
    with create_pipe_input() as pipe_input:
        pipe_input.send_text(keys)
        with create_app_session(input=pipe_input, output=DummyOutput()):
            return evidence_search.search_evidence_multi(index)


def _height() -> int:
    with create_pipe_input() as pipe_input, create_app_session(input=pipe_input, output=DummyOutput()):
        return evidence_search._visible_height()


def test_multi_renders_only_a_window_of_a_20k_list(monkeypatch):
    calls = []
    real = evidence_search._format_result_multi
    monkeypatch.setattr(evidence_search, "_format_result_multi", lambda e, s, c: calls.append(1) or real(e, s, c))

    result = _run_multi(_big_index(20_000), "\x1b[B" + " " + ENTER)

    assert result == ["EV00001"]
    assert len(calls) <= 50 * (_height() + 1)


def test_multi_toggle_after_paging_checks_the_true_records():
    h = _height()
    # PgDn, toggle, End, toggle, Enter -> both records checked far apart, returned in list order
    assert _run_multi(_big_index(500), PGDN + " " + END + " " + ENTER) == [f"EV{h:05d}", "EV00499"]


def test_multi_home_end_pageup_navigation():
    h = _height()
    assert _run_multi(_big_index(500), END + PGUP + " " + HOME + " " + ENTER) == ["EV00000", f"EV{499 - h:05d}"]
