"""Headless tests for vcoc.interactive.forms.prompt_path (no real TTY)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from prompt_toolkit.application import create_app_session
from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput

from vcoc.interactive import forms


def run_prompt_path(keys: str, **kwargs) -> str | None:
    with create_pipe_input() as pipe_input:
        pipe_input.send_text(keys)
        with create_app_session(input=pipe_input, output=DummyOutput()):
            return forms.prompt_path("Title", "Label:", **kwargs)


def test_typed_path_with_no_selection_submits_as_is(tmp_path):
    nonexistent = str(tmp_path / "made_up_name.txt")
    result = run_prompt_path(nonexistent + "\r")
    assert result == nonexistent


def test_tab_into_results_and_enter_selects_matching_file(tmp_path):
    (tmp_path / "sample.txt").write_text("data", encoding="utf-8")
    partial = str(tmp_path / "samp")

    result = run_prompt_path(partial + "\t\r")

    assert result == str(tmp_path / "sample.txt")


def test_selecting_directory_result_descends_instead_of_submitting(tmp_path):
    sub = tmp_path / "subdir"
    sub.mkdir()
    (sub / "inner.txt").write_text("data", encoding="utf-8")
    partial = str(tmp_path / "sub")

    # Tab+Enter selects the directory (appends separator, continues editing),
    # then typing "inner" and Tab+Enter again selects the file inside it.
    keys = partial + "\t\r" + "inner\t\r"
    result = run_prompt_path(keys)

    assert result == str(sub / "inner.txt")


def test_escape_cancels_and_returns_none(tmp_path):
    result = run_prompt_path("some text\x1b")
    assert result is None


def test_dirs_only_filters_results_to_directories(tmp_path):
    (tmp_path / "afile.txt").write_text("data", encoding="utf-8")
    (tmp_path / "adir").mkdir()
    partial = str(tmp_path / "a")

    result = run_prompt_path(partial + "\t\r", dirs_only=True)

    assert result == str(tmp_path / "adir")
