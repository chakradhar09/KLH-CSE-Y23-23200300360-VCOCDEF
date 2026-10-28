"""Phase 3: the loading screen wears the theme, folder ingest shows a block progress bar, and waits show a marquee.

The bar is delivered through the loading screen's existing `status` text, so `loading_text`, `run_with_loading`'s
signature and `_IngestProgress.text()` (all pinned by existing tests) are untouched.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from test_theme_screens import ACCENT, OK_GREEN, drive, visible
from vcoc.interactive import menu, theme
from vcoc.interactive.loading import loading_text, run_with_loading

MB = 1024 * 1024


@pytest.fixture(autouse=True)
def _reset_current_theme():
    yield
    theme.set_current(None)


def lines(text: str) -> list[str]:
    return text.split("\n")


# ---- _IngestProgress: the fraction and the screen text ---------------------------------------------------------------

def test_fraction_is_unknown_until_the_first_report_then_bytes_done_over_total():
    progress = menu._IngestProgress(clock=lambda: 100.0)
    assert progress.fraction() is None
    progress(1, 4, "a.bin", 10, 0, 100)
    assert progress.fraction() == 0.0
    progress(2, 4, "b.bin", 10, 25, 100)
    assert progress.fraction() == 0.25


def test_fraction_is_one_for_an_empty_total_and_never_more_than_one():
    progress = menu._IngestProgress(clock=lambda: 100.0)
    progress(1, 1, "empty", 0, 0, 0)
    assert progress.fraction() == 1.0
    progress(1, 1, "x", 1, 150, 100)
    assert progress.fraction() == 1.0


def test_fraction_does_not_read_the_clock():
    ticks = iter([100.0])  # a second read would raise StopIteration
    progress = menu._IngestProgress(clock=ticks.__next__)
    progress(1, 2, "a.bin", 10, 50, 100)
    assert progress.fraction() == 0.5 and progress.fraction() == 0.5


def test_screen_text_is_scanning_text_without_a_bar_before_any_report():
    progress = menu._IngestProgress()
    assert progress.screen_text() == progress.text() == "Scanning the folder..."


def test_screen_text_is_the_unchanged_status_text_then_a_blank_line_and_the_bar():
    progress = menu._IngestProgress(clock=iter([100.0, 110.0, 110.0]).__next__)
    progress(3, 10, "sub/dir/file.bin", 2048, 1 * MB, 10 * MB)
    status = progress.text()  # reads the clock once (110.0)
    shown = progress.screen_text()  # reads it once more (110.0)
    assert shown.startswith(status.split("\n")[0]) and "sub/dir/file.bin (2.0 KB)" in shown
    assert shown.split("\n")[-2:] == ["", theme.progress_bar(0.1)]
    assert theme.progress_bar(0.1).endswith("10%")


def test_screen_text_shows_a_full_bar_once_every_file_is_hashed():
    progress = menu._IngestProgress(clock=lambda: 100.0)
    progress(10, 10, "z.bin", 5, 10 * MB, 10 * MB)
    shown = progress.screen_text()
    assert "Recording to the database" in shown and shown.endswith(theme.progress_bar(1.0))
    assert "□" not in shown


def test_the_ingest_status_text_itself_is_unchanged_by_the_bar():
    progress = menu._IngestProgress(clock=lambda: 100.0)
    progress(3, 10, "sub/dir/file.bin", 2048, 1 * MB, 10 * MB)
    assert "■" not in progress.text() and "[" not in progress.text()


def test_the_shell_hands_the_ingest_screen_text_with_the_bar_to_the_loading_screen(tmp_path, monkeypatch):
    seen = {}
    real = menu.run_with_loading

    def spy(title, work, label="", status=None, cancel=None):
        seen["status"] = status
        return real(title, work, label, status=status, cancel=cancel)

    monkeypatch.setattr(menu, "run_with_loading", spy)
    from test_interactive_loading import _shell_add_folder

    _shell_add_folder(tmp_path, monkeypatch, log_event=False)
    finished = seen["status"]()  # the ingest is over: every file hashed
    assert finished.endswith(theme.progress_bar(1.0)) and "Recording to the database" in finished


# ---- the loading screen as drawn -------------------------------------------------------------------------------------

def run_loading(status=None, seconds=0.45, cancel=None):
    def work():
        time.sleep(seconds)
        return "done"

    return drive(lambda: run_with_loading("Add evidence", work, "Adding evidence...", status=status, cancel=cancel), "")


RUNNING = "Hashing file 3 of 9\n  a/b.bin (1.0 MB)\n1.0 MB of 2.0 MB (50%)\n\n" + theme.progress_bar(0.5)


def test_loading_screen_draws_the_progress_bar_in_the_accent_with_its_text_unchanged():
    theme.set_current(theme.make_theme("dark"))
    result, raw = run_loading(status=lambda: RUNNING)
    assert result == "done" and ACCENT in raw
    text = visible(raw)
    assert "Adding evidence..." in text and "Hashing file 3 of 9" in text and "50%" in text
    assert "■" * 20 + "□" * 20 in text


def test_a_finished_bar_turns_green():
    theme.set_current(theme.make_theme("dark"))
    _, raw = run_loading(status=lambda: "All 9 file(s) hashed (2.0 MB).\nRecording to the database...\n\n" + theme.progress_bar(1.0))
    assert OK_GREEN in raw


def test_without_a_status_the_loading_screen_shows_a_moving_marquee():
    theme.set_current(theme.make_theme("dark"))
    result, raw = run_loading(status=None)
    assert result == "done" and ACCENT in raw
    text = visible(raw)
    assert "■" in text and "·" in text and "Adding evidence..." in text


def test_a_status_that_is_present_replaces_the_marquee():
    theme.set_current(theme.make_theme("dark"))
    _, raw = run_loading(status=lambda: "Working on it")
    assert "·" not in visible(raw) and "Working on it" in visible(raw)


def test_the_loading_screen_in_the_ascii_fallback_is_ascii_with_a_hash_bar():
    theme.set_current(theme.make_theme("dark", unicode=False))
    _, raw = run_loading(status=lambda: RUNNING)
    text = visible(raw)
    assert text.isascii() and "#" * 20 + "." * 20 in text


def test_the_loading_screen_under_the_plain_theme_emits_no_color_codes():
    theme.set_current(theme.make_theme("plain"))
    _, raw = run_loading(status=lambda: RUNNING)
    assert "38;2;" not in raw and "48;2;" not in raw


def test_the_cancel_hint_is_still_shown_and_dim_when_cancelling_is_possible():
    theme.set_current(theme.make_theme("dark"))
    _, raw = run_loading(status=lambda: RUNNING, cancel=lambda: None)
    assert "Esc cancels" in visible(raw)


def test_loading_text_is_exactly_what_it_was():
    assert loading_text("Loading...", None, 1.234) == "\n  Loading...\n\n  1.2 s"
    assert loading_text("L", "a\nb", 65.0, "Esc cancels") == "\n  L\n\n  a\n  b\n\n  65.0 s\n\n  Esc cancels"
