"""The Evidence tab shows a summary line of its categories and `f` steps through them (All, All green, Tampered, ...)."""

from __future__ import annotations

import io
import re
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from prompt_toolkit.application import create_app_session
from prompt_toolkit.data_structures import Size
from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import ColorDepth
from prompt_toolkit.output.vt100 import Vt100_Output

from vcoc.interactive import theme
from vcoc.interactive import verification_screen as vs

from test_evidence_check_parallel import _mixed_rows

COUNTS = {"all": 7, "green": 1, "tampered": 1, "not_logged": 4, "unverifiable": 2, "logged": 3}
CTRL_R = "\x12"


@pytest.fixture(autouse=True)
def _theme():
    theme.set_current(theme.make_theme("dark"))
    yield
    theme.set_current(None)


# ---- the pure pieces -----------------------------------------------------------------------------------------------

def test_the_views_come_in_the_order_good_news_first():
    assert vs.VIEW_ORDER == ("all", "green", "tampered", "not_logged", "unverifiable", "logged")
    assert set(vs.VIEW_LABELS) == set(vs.VIEW_ORDER)


def test_the_summary_line_brackets_the_active_view_and_shows_every_count():
    line = vs._summary_line(COUNTS, "tampered")
    assert line.index("All 7") < line.index("All green 1") < line.index("[Tampered 1]") < line.index("Not logged 4")
    assert "Unverifiable 2" in line and "Logged 3" in line
    assert line.count("[") == 1 and len(line) <= 78


def test_the_summary_line_uses_thousands_separators_and_keeps_the_good_news_in_view():
    big = {"all": 141_992, "green": 141_980, "tampered": 3, "not_logged": 12, "unverifiable": 5, "logged": 141_988}
    line = vs._summary_line(big, "all")
    assert line[:78].count("141,992") == 1 and "All green 141,980" in line[:78] and "Tampered 3" in line[:78]


@pytest.mark.parametrize("name, following", [("all", "green"), ("green", "tampered"), ("logged", "all")])
def test_f_steps_to_the_next_view_and_wraps(name, following):
    assert vs._next_view(name) == following


def test_the_evidence_tab_has_its_own_help_line_with_the_f_key_within_the_frame():
    assert "f view" in vs.HELP_EVIDENCE and len(vs.HELP_EVIDENCE) <= 78
    assert "f view" not in vs.HELP_VERIFICATION  # the other tabs have no such key


# ---- the screen, driven with real keys -----------------------------------------------------------------------------------

ROWS, COLS = 30, 100
CSI = re.compile(r"\x1b\[([0-9;?]*)([A-Za-z])")


def replay(raw: str) -> list[str]:
    """The screen a terminal would show after `raw`: just enough of VT100 for prompt_toolkit's diff output (cursor
    moves, erase, text). The renderer only rewrites cells that changed, so the raw stream alone cannot be read as text."""
    grid = [[" "] * COLS for _ in range(ROWS)]
    row = col = i = 0
    while i < len(raw):
        ch = raw[i]
        match = CSI.match(raw, i) if ch == "\x1b" else None
        if match:
            params = [int(p) if p.isdigit() else 0 for p in match.group(1).split(";")]
            n, final = max(params[0], 1), match.group(2)
            if final == "A":
                row = max(row - n, 0)
            elif final == "B":
                row = min(row + n, ROWS - 1)
            elif final == "C":
                col = min(col + n, COLS - 1)
            elif final == "D":
                col = max(col - n, 0)
            elif final == "H":
                row, col = max(params[0] - 1, 0), max((params[1] if len(params) > 1 else 1) - 1, 0)
            elif final == "J":
                grid[row][col:] = [" "] * (COLS - col)
                grid[row + 1 :] = [[" "] * COLS for _ in grid[row + 1 :]]
            elif final == "K":
                grid[row][col:] = [" "] * (COLS - col)
            i = match.end()
            continue
        if ch == "\r":
            col = 0
        elif ch == "\n":
            row = min(row + 1, ROWS - 1)
        elif ch == "\x08":
            col = max(col - 1, 0)
        elif ch >= " " and col < COLS:
            grid[row][col] = ch
            col += 1
        i += 1
    return ["".join(line).rstrip() for line in grid]


def run_screen(tmp_path, monkeypatch, steps):
    """Open the Verification screen on a seven-file database, type each step's keys and return the screen after each one."""
    _mixed_rows(tmp_path, n=6)
    monkeypatch.chdir(tmp_path)
    buffer = io.StringIO()
    output = Vt100_Output(buffer, lambda: Size(ROWS, COLS), term="xterm-256color", default_color_depth=ColorDepth.DEPTH_24_BIT)
    ends: list[int] = []

    def idle():  # the Evidence re-hash runs on a thread: wait for it before the next key
        deadline = time.time() + 10
        while any(t.name == "vcoc-bgload" for t in threading.enumerate()) and time.time() < deadline:
            time.sleep(0.02)
        time.sleep(0.3)

    with create_pipe_input() as pipe_input:

        def typist():
            for keys in steps:
                pipe_input.send_text(keys)
                idle()
                ends.append(len(buffer.getvalue()))
            pipe_input.send_text("q")

        sender = threading.Thread(target=typist, daemon=True)
        sender.start()
        with create_app_session(input=pipe_input, output=output):
            with theme.ascii_borders(theme.current()):
                vs.run_verification_screen({})
        sender.join(5)
    raw = buffer.getvalue()
    return ["\n".join(replay(raw[:end])) for end in ends]


def test_the_evidence_tab_shows_the_summary_and_every_file_once_the_check_has_finished(tmp_path, monkeypatch):
    (screen,) = run_screen(tmp_path, monkeypatch, ["2"])
    assert "[All 7]  All green 1  Tampered 1  Not logged 4  Unverifiable 2  Logged 3" in screen
    assert all(name in screen for name in ("SOLO", "F1/m000", "F1/m001", "F1/m005", "Merkle root over all evidence"))


def test_f_steps_through_the_views_and_the_list_follows(tmp_path, monkeypatch):
    _, green, tampered = run_screen(tmp_path, monkeypatch, ["2", "f", "f"])
    assert "[All green 1]" in green and "SOLO" in green and "F1/m000" not in green and "Merkle root" not in green
    assert "[Tampered 1]" in tampered and "F1/m001" in tampered and "SOLO" not in tampered
    assert "re-hash: MISMATCH" in tampered  # its detail pane describes the file that no longer matches
    assert "f view" in tampered  # the Evidence tab's help line


def test_f_wraps_around_to_the_whole_list(tmp_path, monkeypatch):
    screens = run_screen(tmp_path, monkeypatch, ["2"] + ["f"] * 6)
    assert "[All 7]" in screens[-1] and "Merkle root over all evidence" in screens[-1]


def test_the_other_tabs_show_neither_the_summary_nor_the_f_hint(tmp_path, monkeypatch):
    chain, merkle = run_screen(tmp_path, monkeypatch, ["f", "3"])
    for screen in (chain, merkle):
        assert "All green" not in screen and "f view" not in screen


def test_ctrl_r_on_the_evidence_tab_starts_again_from_the_whole_list(tmp_path, monkeypatch):
    _, tampered, again = run_screen(tmp_path, monkeypatch, ["2", "ff", CTRL_R])
    assert "[Tampered 1]" in tampered and "[All 7]" in again
