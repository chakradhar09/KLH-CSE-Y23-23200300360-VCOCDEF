"""Phase 4: the shell in the terminals people actually use, simulated end to end.

Each case is an environment (variables, platform, color depth, terminal size). The theme is resolved from it exactly as
`run_shell` does, the real screens are drawn into a virtual terminal, and what reaches the terminal is checked: which color
codes, which glyphs, and that every menu item and the hint are visible. Real terminals (Windows Terminal, cmd.exe, a Linux
console) still deserve a human look, but any regression in what each one is sent is caught here.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from prompt_toolkit.output import ColorDepth

from test_theme_screens import ROWS, DETAILS, drive, sequences, visible
from vcoc.interactive import app, theme, verification_screen

D24, D8, D4, D1 = ColorDepth.DEPTH_24_BIT, ColorDepth.DEPTH_8_BIT, ColorDepth.DEPTH_4_BIT, ColorDepth.DEPTH_1_BIT

# name: (environment, platform, windows build, color depth the terminal reports, TERM given to the output)
ENVIRONMENTS = {
    "windows-terminal": ({"WT_SESSION": "abc"}, "win32", 22631, D24, "xterm-256color"),
    "windows-11-classic-console": ({}, "win32", 22631, D24, "xterm-256color"),
    "legacy-windows-console": ({}, "win32", 14393, D4, "vt100"),
    "linux-xterm-256color": ({"TERM": "xterm-256color"}, "linux", 0, D8, "xterm-256color"),
    "linux-console": ({"TERM": "linux"}, "linux", 0, D4, "linux"),
    "no-color": ({"NO_COLOR": "1", "TERM": "xterm-256color"}, "linux", 0, D1, "xterm-256color"),
    "forced-ascii": ({"VCOC_ASCII": "1", "TERM": "xterm-256color"}, "linux", 0, D8, "xterm-256color"),
}
UNICODE = {"windows-terminal": True, "windows-11-classic-console": True, "legacy-windows-console": False,
           "linux-xterm-256color": True, "linux-console": False, "no-color": True, "forced-ascii": False}

ATTRIBUTE_CODES = {"0", "1", "2", "3", "4", "7", "22", "23", "24", "27", "39", "49"}
FOUR_BIT_CODES = ATTRIBUTE_CODES | {str(n) for n in (*range(30, 38), *range(40, 48), *range(90, 98), *range(100, 108))}


@pytest.fixture(autouse=True)
def _reset_current_theme():
    yield
    theme.set_current(None)


def activate(name: str):
    env, platform, build, depth, term = ENVIRONMENTS[name]
    shell_theme = theme.resolve_theme(env, platform=platform, encoding="utf-8", win_build=build, color_depth=depth)
    theme.set_current(shell_theme)
    return shell_theme, depth, term


def menu_screen(name: str, rows: int):
    _, depth, term = activate(name)
    return drive(app._run_main_menu, "q", rows=rows, depth=depth, term=term)[1]


def sidebar_screen(name: str, rows: int):
    _, depth, term = activate(name)
    return drive(lambda: verification_screen._run_sidebar_detail_app("Verify Chain", lambda: (ROWS, DETAILS)), "q", rows=rows, depth=depth, term=term)[1]


def codes(raw: str) -> set[str]:
    return {code for seq in sequences(raw) for code in seq.split(";") if code}


@pytest.mark.parametrize("name", ENVIRONMENTS)
@pytest.mark.parametrize("rows", [24, 15])
def test_the_menu_shows_every_item_and_the_hint_in_every_environment(name, rows):
    text = visible(menu_screen(name, rows))
    assert all(label in text for label in app.menu.MENU_ITEMS)
    assert ("Esc/q quit" in text)


@pytest.mark.parametrize("name", ENVIRONMENTS)
def test_glyphs_are_unicode_or_ascii_as_the_environment_calls_for(name):
    shell_theme, _, _ = activate(name)
    assert shell_theme.unicode is UNICODE[name]
    for screen in (menu_screen, sidebar_screen):
        text = visible(screen(name, 24))
        if UNICODE[name]:
            assert "─" in text and "│" in text
        else:
            assert text.isascii() and "+--" in text


@pytest.mark.parametrize("name", ["windows-terminal", "windows-11-classic-console"])
def test_truecolor_terminals_receive_truecolor_codes(name):
    assert "38;2" in ";".join(sequences(menu_screen(name, 24)))


def test_a_256_color_terminal_receives_256_color_codes_and_never_truecolor():
    raw = ";".join(sequences(sidebar_screen("linux-xterm-256color", 24)))
    assert "38;5" in raw and "38;2" not in raw and "48;2" not in raw


@pytest.mark.parametrize("name", ["legacy-windows-console", "linux-console"])
def test_16_color_terminals_receive_only_basic_ansi_colors(name):
    for screen in (menu_screen, sidebar_screen):
        raw = screen(name, 24)
        assert codes(raw) <= FOUR_BIT_CODES, codes(raw) - FOUR_BIT_CODES
        assert "38" not in codes(raw) and "48" not in codes(raw)  # no extended (256 / truecolor) color selectors


def test_the_linux_console_marks_a_tamper_row_in_bright_red_and_never_in_bright_black():
    codes_seen = codes(sidebar_screen("linux-console", 24))
    assert "91" in codes_seen  # ansibrightred: the TAMPER word
    assert "90" not in codes_seen  # ansibrightblack is nearly invisible on that console


@pytest.mark.parametrize("name", ["no-color"])
def test_no_color_sends_no_color_codes_at_all_but_keeps_every_word(name):
    for screen in (menu_screen, sidebar_screen):
        raw = screen(name, 24)
        assert codes(raw) <= ATTRIBUTE_CODES, codes(raw) - ATTRIBUTE_CODES
    assert "TAMPER" in visible(sidebar_screen(name, 24)) and "Add evidence" in visible(menu_screen(name, 24))


def test_forced_ascii_changes_the_shapes_but_not_the_colors():
    raw = sidebar_screen("forced-ascii", 24)
    assert visible(raw).isascii() and "38;5" in ";".join(sequences(raw))


@pytest.mark.parametrize("name", ENVIRONMENTS)
def test_the_logo_follows_the_terminal_height_in_every_environment(name):
    tall, short = visible(menu_screen(name, 24)), visible(menu_screen(name, 15))
    assert "VCoC" in tall and "VCoC" not in short
