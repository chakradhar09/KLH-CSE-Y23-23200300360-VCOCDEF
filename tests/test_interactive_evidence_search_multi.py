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
            return evidence_search.search_evidence_multi(INDEX, None)


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
