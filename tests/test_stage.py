"""Task 1 (screen stage): the shell keeps one alternate screen up from start to exit.

Each screen is its own full-screen app. Without a stage every hand-off leaves the alternate screen (the user's plain
terminal shows) and enters it again. With the stage the shell enters once and leaves once, and the screens in between
only home the cursor.
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from prompt_toolkit.application import create_app_session
from prompt_toolkit.data_structures import Size
from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput
from prompt_toolkit.output.vt100 import Vt100_Output

import cli as cli_module
from vcoc.interactive import menu, theme
from vcoc.interactive.app import run_shell

ENTER_ALT, LEAVE_ALT, HOME = "\x1b[?1049h", "\x1b[?1049l", "\x1b[0;0H"


@pytest.fixture(autouse=True)
def _reset_current_theme():
    yield
    theme.set_current(None)


def run_headless(keys: str) -> str:
    """Run the whole shell on a virtual terminal; return everything it sent."""
    buffer = io.StringIO()
    output = Vt100_Output(buffer, lambda: Size(24, 80), term="xterm-256color")
    with create_pipe_input() as pipe_input:
        pipe_input.send_text(keys)
        with create_app_session(input=pipe_input, output=output):
            try:
                run_shell()
            finally:
                raw = buffer.getvalue()
    return raw


@pytest.fixture
def in_empty_dir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli_module, "cmd_merkle_root", lambda args: print("Merkle root: 00"))


def test_stage_output_swallows_the_screens_alternate_screen_calls_and_homes_the_cursor():
    from vcoc.interactive.stage import StageOutput

    class Recording(DummyOutput):
        def __init__(self):
            self.calls = []

        def enter_alternate_screen(self):
            self.calls.append("enter")

        def quit_alternate_screen(self):
            self.calls.append("quit")

        def cursor_goto(self, row=0, column=0):
            self.calls.append(("goto", row, column))

        def flush(self):
            self.calls.append("flush")

    real = Recording()
    stage = StageOutput(real)
    stage.enter_alternate_screen()
    stage.quit_alternate_screen()
    assert "enter" not in real.calls and "quit" not in real.calls
    assert ("goto", 0, 0) in real.calls
    assert stage.get_default_color_depth() == real.get_default_color_depth()  # everything else passes straight through


def test_the_stage_reports_one_row_less_so_a_closing_screen_cannot_scroll_the_one_beneath():
    """A closing app moves the cursor to the row below its layout; on a full-height frame that newline scrolls the
    screen up one row, so the previous frame would jump for an instant before the next one paints (seen on a real console)."""
    from vcoc.interactive.stage import StageOutput

    real = Vt100_Output(io.StringIO(), lambda: Size(30, 80), term="xterm-256color")
    assert StageOutput(real).get_size() == Size(29, 80)
    tiny = Vt100_Output(io.StringIO(), lambda: Size(1, 80), term="xterm-256color")
    assert StageOutput(tiny).get_size().rows == 1  # never below one row


def test_a_whole_session_enters_and_leaves_the_alternate_screen_once(in_empty_dir):
    raw = run_headless("5" "x" "q")  # Merkle root (loading screen, then output screen), dismiss, back at the menu, quit
    assert raw.count(ENTER_ALT) == 1
    assert raw.count(LEAVE_ALT) == 1
    assert raw.index(ENTER_ALT) < raw.index(LEAVE_ALT)


def test_the_cursor_is_homed_after_every_screen_so_the_next_one_starts_at_the_top(in_empty_dir):
    raw = run_headless("5" "x" "q")  # menu, loading, output, menu = four screens
    assert raw.count(HOME) >= 4


def test_an_error_in_an_action_still_leaves_the_alternate_screen_once(in_empty_dir, monkeypatch):
    def boom(shell_config):
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(menu, "ACTIONS", [boom, *menu.ACTIONS[1:]])
    buffer = io.StringIO()
    output = Vt100_Output(buffer, lambda: Size(24, 80), term="xterm-256color")
    with create_pipe_input() as pipe_input:
        pipe_input.send_text("1")
        with create_app_session(input=pipe_input, output=output):
            with pytest.raises(RuntimeError, match="disk on fire"):
                run_shell()
    raw = buffer.getvalue()
    assert raw.count(ENTER_ALT) == 1 and raw.count(LEAVE_ALT) == 1
    assert raw.rfind("\x1b[?25h") > raw.rfind("\x1b[?25l")  # the last cursor command shows it: the user gets it back
