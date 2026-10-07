"""T16: every help line fits inside the frame of an 80-column terminal.

The frame leaves 78 columns. Three lines (Verification 91 characters, Search 85 and 81) used to be wider, so the end of
the line, including the key that leaves the screen (`Esc/q back`), was cut off. The key bindings themselves are unchanged:
Home, End and F5 still work, only their mention left the hint.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from test_theme_screens import INDEX, ROWS, DETAILS, drive, visible
from vcoc.interactive import evidence_search, forms, theme, verification_screen

FRAME_INNER_WIDTH = 78
MODULES = (evidence_search, forms, verification_screen)


def help_lines() -> dict[str, str]:
    return {f"{module.__name__.split('.')[-1]}.{name}": value for module in MODULES for name, value in vars(module).items() if name.startswith("HELP_")}


@pytest.fixture(autouse=True)
def _reset_current_theme():
    theme.set_current(theme.make_theme("dark"))
    yield
    theme.set_current(None)


def test_every_screen_has_its_help_line_as_a_named_constant():
    assert set(help_lines()) == {
        "evidence_search.HELP_SEARCH", "evidence_search.HELP_SEARCH_MULTI",
        "forms.HELP_TEXT", "forms.HELP_PATH", "forms.HELP_OUTPUT",
        "verification_screen.HELP_SIDEBAR", "verification_screen.HELP_VERIFICATION", "verification_screen.HELP_EVIDENCE",
    }


@pytest.mark.parametrize("name, line", sorted(help_lines().items()))
def test_every_help_line_fits_an_80_column_frame(name, line):
    assert len(line) <= FRAME_INNER_WIDTH, f"{name} is {len(line)} characters"


@pytest.mark.parametrize("name, line", sorted(help_lines().items()))
def test_every_help_line_styles_each_key_and_its_description_apart(name, line):
    """The renderer splits a help line into key / description pairs on gaps of three or more spaces. A line squeezed to
    two-space gaps rendered as one grey block after its first key, so it looked unlike every other screen's footer."""
    for style, part in theme.colorize(line, "hint", theme.make_theme("dark")):
        if style:  # a described part: one description, never several keys run together
            assert "  " not in part, f"{name}: {part!r}"


def test_the_evidence_tabs_help_line_reads_like_the_tabs_next_to_it():
    from vcoc.interactive import verification_screen as vs

    def keys(line):
        return [part.strip() for style, part in theme.colorize(line, "hint", theme.make_theme("dark")) if not style and part.strip()]

    assert keys(vs.HELP_EVIDENCE) == ["Tab/←→", "1-3", "f", "↑/↓ PgUp/PgDn", "Ctrl-R", "Esc/q"]
    assert keys(vs.HELP_VERIFICATION) == ["Tab/←→", "1-3", "↑/↓ PgUp/PgDn", "Ctrl-R", "Esc/q"]


def test_the_three_lines_that_used_to_clip_have_the_approved_wording():
    assert verification_screen.HELP_VERIFICATION == " Tab/←→ section   1-3 jump   ↑/↓ PgUp/PgDn   Ctrl-R refresh   Esc/q back"
    assert evidence_search.HELP_SEARCH == " ↑/↓ PgUp/PgDn select   Enter choose   Ctrl-R refresh   Esc cancel"
    assert evidence_search.HELP_SEARCH_MULTI == " ↑/↓ PgUp/PgDn select   Space toggle   Enter confirm   Esc cancel"


def test_the_lines_that_already_fit_are_unchanged():
    assert verification_screen.HELP_SIDEBAR == " ↑/↓ select   PgUp/PgDn/Home/End jump   Ctrl-R/F5 refresh   Esc/q back"
    assert forms.HELP_PATH == " Tab/↓ browse matches   Enter select/confirm   Esc cancel"
    assert forms.HELP_TEXT == " Enter confirm   Esc cancel"
    assert forms.HELP_OUTPUT == " ↑/↓/PgUp/PgDn scroll   any other key returns to menu"


def test_the_sidebar_screen_uses_the_default_help_line_when_none_is_given():
    _, raw = drive(lambda: verification_screen._run_sidebar_detail_app("Verify Chain", lambda: (ROWS, DETAILS)), "q")
    assert "Esc/q back" in visible(raw)


def test_the_real_verification_screen_shows_its_help_line_in_full_at_80_columns(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # no database here: the Chain tab says so, and the help line is what we are after
    _, raw = drive(lambda: verification_screen.run_verification_screen({}), "q")
    # The screen opens behind a loading screen, so read everything that was drawn, not just the first screen.
    text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", raw)
    assert verification_screen.HELP_VERIFICATION.strip() in text and "Esc/q back" in text


def test_the_search_help_lines_are_shown_in_full_at_80_columns():
    _, single = drive(lambda: evidence_search.search_evidence(INDEX), "\r")
    _, multi = drive(lambda: evidence_search.search_evidence_multi(INDEX), "\r")
    assert evidence_search.HELP_SEARCH.strip() in visible(single)
    assert evidence_search.HELP_SEARCH_MULTI.strip() in visible(multi)


def test_the_screens_actually_use_the_constants():
    """A constant nobody uses would let a long literal sneak back in; the drawn line must be the constant."""
    _, raw = drive(lambda: forms.prompt_text("T", "Label:"), "x\r")
    assert forms.HELP_TEXT.strip() in visible(raw)
    _, raw = drive(lambda: forms.show_output("T", "text"), "x")
    assert forms.HELP_OUTPUT.strip() in visible(raw)


# ---- the hint styling keeps both keys of "↑/↓ PgUp/PgDn" plain -----------------------------------------------------------

def test_consecutive_key_names_stay_plain_and_only_the_description_is_dim():
    frags = theme.colorize(" ↑/↓ PgUp/PgDn select   Enter choose", "hint", theme.make_theme("dark"))
    assert frags[:2] == [("", " ↑/↓ PgUp/PgDn"), ("class:dim", " select")]
    assert ("", "Enter") in frags and ("class:dim", " choose") in frags


def test_the_hint_styling_is_unchanged_for_single_key_lines():
    dark = theme.make_theme("dark")
    assert theme.colorize("↑/↓ navigate   1-9,0 jump   Esc/q quit", "hint", dark) == [
        ("", "↑/↓"), ("class:dim", " navigate"), ("", "   "), ("", "1-9,0"), ("class:dim", " jump"), ("", "   "), ("", "Esc/q"), ("class:dim", " quit"),
    ]
    assert theme.colorize(" any other key returns to menu", "hint", dark) == [("", " any"), ("class:dim", " other key returns to menu")]
