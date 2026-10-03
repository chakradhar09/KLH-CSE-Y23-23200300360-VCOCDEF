"""Phase 2: the verification, search, form and command-output screens wear the theme.

Each test runs the real screen headlessly into a virtual terminal and reads what it would draw: the color escape codes
that reach the terminal, and the text a person would see. Screen text and key behavior are pinned by the existing tests.
"""

from __future__ import annotations

import io
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from prompt_toolkit.application import create_app_session
from prompt_toolkit.data_structures import Size
from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import ColorDepth
from prompt_toolkit.output.vt100 import Vt100_Output

from vcoc.interactive import evidence_search, forms, theme, verification_screen

# truecolor escape fragments of the dark preset
OK_GREEN = "38;2;95;184;120"  # #5fb878
TAMPER_RED = "38;2;255;107;104"  # #ff6b68
ACCENT = "38;2;217;164;65"  # #d9a441
DIM = "38;2;147;156;169"  # #939ca9
WARN = "38;2;232;148;74"  # #e8944a
TINT = "48;2;38;44;53"  # #262c35, the selected row


@pytest.fixture(autouse=True)
def _reset_current_theme():
    yield
    theme.set_current(None)


def drive(run, keys: str, rows: int = 24, depth: ColorDepth = ColorDepth.DEPTH_24_BIT, term: str = "xterm-256color"):
    """Run `run()` headlessly; return (its result, the raw terminal stream)."""
    buffer = io.StringIO()
    output = Vt100_Output(buffer, lambda: Size(rows, 80), term=term, default_color_depth=depth)
    with create_pipe_input() as pipe_input:
        pipe_input.send_text(keys)
        with create_app_session(input=pipe_input, output=output):
            with theme.ascii_borders(theme.current()):
                result = run()
    return result, buffer.getvalue()


def sequences(raw: str) -> list[str]:
    return re.findall(r"\x1b\[([0-9;]*)m", raw)


def visible(raw: str) -> str:
    screen = raw.replace("\x1b[?1049l", "\x1b[?1049h").split("\x1b[?1049h")
    text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", screen[1] if len(screen) > 1 else raw)
    return re.sub(r"\r(?!\n)", "", text)  # the renderer returns the cursor before writing a row's last column


ROWS = ["OK  #0 register on EV001", "TAMPER  #1 analyze on EV002", "--  Merkle root over all evidence"]
DETAILS = [["status: OK", "signature: VALID"], ["hash link: TAMPER, chain breaks at #1", "status: TAMPER DETECTED"], ["root: abc"]]


def sidebar_screen(**kwargs):
    return verification_screen._run_sidebar_detail_app("Verify Chain", lambda: (ROWS, DETAILS), **kwargs)


# ---- T4: Verify chain / Verification -------------------------------------------------------------------------------

def test_sidebar_screen_colors_verdicts_in_the_list_and_the_detail_pane():
    theme.set_current(theme.make_theme("dark"))
    _, raw = drive(sidebar_screen, "q")
    assert OK_GREEN in raw and TAMPER_RED in raw  # list rows and the detail pane's "status: OK"
    assert DIM in raw  # labels and the help line


def test_the_selected_sidebar_row_has_the_tint_and_keeps_its_verdict_color():
    theme.set_current(theme.make_theme("dark"))
    _, raw = drive(sidebar_screen, "\x1b[Bq")  # down to the TAMPER row, then quit
    assert any("255;107;104" in s and "38;44;53" in s for s in sequences(raw))


def test_sidebar_screen_tab_bar_accents_the_active_section():
    theme.set_current(theme.make_theme("dark"))
    bar = lambda: "  Chain  [ Evidence ]  Merkle  "
    _, raw = drive(lambda: sidebar_screen(top_bar=bar), "q")
    assert ACCENT in raw and "[ Evidence ]" in visible(raw)


def test_sidebar_screen_text_is_unchanged_by_the_theme():
    theme.set_current(theme.make_theme("dark"))
    _, raw = drive(sidebar_screen, "q")
    text = visible(raw)
    for row in ROWS:
        assert row in text
    assert "status: TAMPER DETECTED" not in text  # the detail pane shows the selected row (#0) only
    assert "↑/↓ select" in text


def test_sidebar_screen_in_the_ascii_fallback_has_no_non_ascii_character_and_ascii_separators():
    theme.set_current(theme.make_theme("dark", unicode=False))
    _, raw = drive(sidebar_screen, "q")
    text = visible(raw)
    assert text.isascii() and "^/v select" in text
    assert "|" + "-" * 78 + "|" in text  # the rule above the help line, inside the frame
    assert any(line.count("|") >= 3 for line in text.split("\r\n") if "OK  #0" in line)  # frame, column divider, frame


def test_sidebar_screen_under_the_plain_theme_emits_no_color_codes():
    theme.set_current(theme.make_theme("plain"))
    _, raw = drive(sidebar_screen, "\x1b[Bq")
    assert "38;2;" not in raw and "48;2;" not in raw and "38;5;" not in raw
    assert "TAMPER" in visible(raw)  # the word still carries the verdict


# ---- T5: search screens and input forms -----------------------------------------------------------------------------

INDEX = {
    "EV001": {"original_filename": "disk_image.E01", "sha256": "ab" * 32},
    "EV002": {"original_filename": "usb_dump.bin", "sha256": "cd" * 32},
}


def test_search_screen_styles_the_input_frame_the_selected_result_and_the_hash_prefix():
    theme.set_current(theme.make_theme("dark"))
    result, raw = drive(lambda: evidence_search.search_evidence(INDEX), "\r")
    assert result == "EV001"
    assert ACCENT in raw  # the focused input frame
    assert any("38;44;53" in s for s in sequences(raw))  # selected row tint
    assert DIM in raw and "abababab..." in visible(raw)


def test_multi_search_screen_keeps_its_behavior_with_the_theme_applied():
    theme.set_current(theme.make_theme("dark"))
    result, raw = drive(lambda: evidence_search.search_evidence_multi(INDEX), " \x1b[B \r")
    assert result == ["EV001", "EV002"]
    assert "[x]" in visible(raw) or ACCENT in raw


def test_prompt_text_has_an_accent_frame_and_returns_what_was_typed():
    theme.set_current(theme.make_theme("dark"))
    result, raw = drive(lambda: forms.prompt_text("Log custody event", "Actor:"), "J. Doe\r")
    assert result == "J. Doe" and ACCENT in raw and "Actor:" in visible(raw)


def test_prompt_path_lists_matches_and_selects_as_before(tmp_path):
    (tmp_path / "alpha.bin").write_text("x")
    theme.set_current(theme.make_theme("dark"))
    result, raw = drive(lambda: forms.prompt_path("Add evidence", "File path:", default=str(tmp_path) + "\\" if sys.platform == "win32" else str(tmp_path) + "/"), "\t\r")
    assert result is not None and result.endswith("alpha.bin")
    assert "alpha.bin" in visible(raw)


def test_confirm_accents_the_default_answer_and_answers_as_before():
    theme.set_current(theme.make_theme("dark"))
    result, raw = drive(lambda: forms.confirm("Proceed?", default=False), "y")
    assert result is True and ACCENT in raw and "[y/N]" in visible(raw)
    result, _ = drive(lambda: forms.confirm("Proceed?", default=True), "\r")
    assert result is True


@pytest.mark.parametrize("name", ["dark", "light", "hc", "plain"])
def test_every_form_runs_under_every_theme_and_the_ascii_fallback(name, tmp_path):
    for unicode in (True, False):
        theme.set_current(theme.make_theme(name, unicode=unicode))
        assert drive(lambda: forms.prompt_text("T", "Label:"), "x\r")[0] == "x"
        assert drive(lambda: forms.confirm("Sure?"), "n")[0] is False
        result, raw = drive(lambda: evidence_search.search_evidence(INDEX), "\r")
        assert result == "EV001"
        if not unicode:
            assert visible(raw).isascii()


# ---- T6: command output ----------------------------------------------------------------------------------------------

OUTPUT = (
    "Registered folder case_notes: 214 file(s)\n\nSummary\n  Files recorded : 214 (1.8 GB)\n"
    "  Custody event  : NOT logged (you chose not to log one)\nstatus: TAMPER DETECTED"
)


def test_command_output_is_colored_by_the_lexer():
    theme.set_current(theme.make_theme("dark"))
    _, raw = drive(lambda: forms.show_output("Add evidence", OUTPUT), "x")
    assert OK_GREEN in raw  # Registered
    assert ACCENT in raw  # Summary
    assert WARN in raw  # NOT logged
    assert TAMPER_RED in raw  # TAMPER DETECTED


def test_command_output_text_is_unchanged_and_any_key_still_dismisses_it():
    theme.set_current(theme.make_theme("dark"))
    result, raw = drive(lambda: forms.show_output("Add evidence", OUTPUT), "x")
    assert result is None
    text = visible(raw)
    assert "Registered folder case_notes: 214 file(s)" in text and "any other key returns to menu" in text


def test_command_output_in_the_ascii_fallback_is_ascii_and_in_plain_has_no_color():
    theme.set_current(theme.make_theme("dark", unicode=False))
    _, raw = drive(lambda: forms.show_output("Add evidence", OUTPUT), "x")
    assert visible(raw).isascii() and "^/v/PgUp/PgDn scroll" in visible(raw)
    theme.set_current(theme.make_theme("plain"))
    _, raw = drive(lambda: forms.show_output("Add evidence", OUTPUT), "x")
    assert "38;2;" not in raw and "48;2;" not in raw
