"""T2: the main menu wears the theme without changing a character of its text.

The menu's own renderer (`_render_menu`) is pinned by existing tests, so the theme is applied on top of it:
fragments re-join to that exact string, the selected row alone is padded, and the ASCII fallback is a display-time step.
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
from prompt_toolkit.output import ColorDepth, DummyOutput
from prompt_toolkit.output.vt100 import Vt100_Output
from prompt_toolkit.widgets.base import Border

from vcoc.interactive import app, theme

ALL_THEMES = ["dark", "light", "hc", "plain"]


@pytest.fixture(autouse=True)
def _reset_current_theme():
    yield
    theme.set_current(None)


def joined(fragments) -> str:
    return "".join(text for _, text in fragments)


def run_menu(keys: str, output=None):
    with create_pipe_input() as pipe_input:
        pipe_input.send_text(keys)
        with create_app_session(input=pipe_input, output=output or DummyOutput()):
            return app._run_main_menu()


# ---- fragments ----------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("name", ALL_THEMES)
@pytest.mark.parametrize("unicode", [True, False])
def test_menu_fragments_rejoin_to_the_unstyled_menu_text(name, unicode):
    t = theme.make_theme(name, unicode=unicode)
    for selected in range(len(app.menu.MENU_ITEMS)):
        expected = app._render_menu(selected)
        if not unicode:
            expected = joined(theme.to_ascii([("", expected)]))
        assert joined(app._menu_fragments(selected, t)) == expected


def test_only_the_selected_row_is_padded_to_the_frame_width():
    t = theme.make_theme("dark")
    lines = joined(app._menu_fragments(2, t, width=78)).split("\n")
    assert lines[2] == app._render_menu(2).split("\n")[2].ljust(78)
    assert all(len(line) < 78 for i, line in enumerate(lines) if i != 2)


def test_menu_hint_line_is_styled_and_unchanged():
    frags = app._menu_fragments(0, theme.make_theme("dark"))
    assert ("class:dim", " navigate") in frags and joined(frags).endswith("Esc/q quit")


def test_menu_fragments_in_an_ascii_theme_contain_no_non_ascii_character():
    text = joined(app._menu_fragments(0, theme.make_theme("dark", unicode=False), width=78))
    assert text.isascii()


def test_menu_title_is_unchanged_in_unicode_and_ascii_in_the_fallback():
    assert app._menu_title(theme.make_theme("dark")) == "Verifiable Chain-of-Custody — Interactive Shell"
    assert app._menu_title(theme.make_theme("dark", unicode=False)) == "Verifiable Chain-of-Custody - Interactive Shell"


# ---- the application ----------------------------------------------------------------------------------------------

@pytest.mark.parametrize("name", ALL_THEMES)
@pytest.mark.parametrize("ansi16", [False, True])
@pytest.mark.parametrize("unicode", [True, False])
def test_main_menu_runs_under_every_theme(name, ansi16, unicode):
    theme.set_current(theme.make_theme(name, ansi16=ansi16, unicode=unicode))
    assert run_menu("q") == app.QUIT_INDEX
    theme.set_current(theme.make_theme(name, ansi16=ansi16, unicode=unicode))
    assert run_menu("\x1b[B\x1b[B\r") == 2  # keys still move and select exactly as before


def test_number_keys_and_enter_still_select_with_the_theme_applied():
    theme.set_current(theme.make_theme("dark"))
    assert run_menu("4") == 3


def vt100_capture(monkeypatch, keys: str, rows: int = 24) -> str:
    buffer = io.StringIO()
    output = Vt100_Output(buffer, lambda: Size(rows, 80), term="xterm-256color", default_color_depth=ColorDepth.DEPTH_24_BIT)
    run_menu(keys, output)
    return buffer.getvalue()


def test_dark_theme_paints_the_selected_row_with_the_tint_background(monkeypatch):
    theme.set_current(theme.make_theme("dark"))
    screen = vt100_capture(monkeypatch, "q")
    assert "48;2;38;44;53" in screen  # #262c35, the row tint
    assert "38;2;240;192;96" in screen  # #f0c060, the selected text


def test_plain_theme_emits_no_color_codes_but_still_marks_the_selection(monkeypatch):
    theme.set_current(theme.make_theme("plain"))
    screen = vt100_capture(monkeypatch, "q")
    assert "38;2;" not in screen and "48;2;" not in screen
    assert "Add evidence" in screen and "\x1b[0;1;7m" in screen.replace("\x1b[0;7;1m", "\x1b[0;1;7m")


# ---- the logo -----------------------------------------------------------------------------------------------------

def visible_text(screen: str) -> str:
    """What the terminal shows: the escape sequences stripped out of the captured stream."""
    import re

    return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", screen.replace("\x1b[?1049l", "\x1b[?1049h").split("\x1b[?1049h")[1])


def test_logo_fragments_are_the_logo_lines_then_one_blank_line():
    t = theme.make_theme("dark")
    text = joined(app._logo_fragments(t, 24))
    assert text.split("\n")[:3] == [joined(line) for line in theme.logo_lines(24)] and text.endswith("\n\n")
    assert joined(app._logo_fragments(t, 20)).count("\n") == 2  # one logo line, one blank line


def test_logo_fragments_are_empty_when_the_terminal_is_too_short():
    assert app._logo_fragments(theme.make_theme("dark"), 15) == []


def test_logo_fragments_in_an_ascii_theme_contain_no_non_ascii_character():
    assert joined(app._logo_fragments(theme.make_theme("dark", unicode=False), 24)).isascii()


def test_menu_shows_the_full_logo_at_24_rows_and_every_item_and_the_hint(monkeypatch):
    theme.set_current(theme.make_theme("dark"))
    text = visible_text(vt100_capture(monkeypatch, "q", rows=24))
    assert "╭─────╮" in text and "Verifiable Chain-of-Custody" in text.split("╭─────╮")[1]
    assert all(label in text for label in app.menu.MENU_ITEMS) and "Esc/q quit" in text


def test_menu_shows_the_one_line_logo_at_20_rows(monkeypatch):
    theme.set_current(theme.make_theme("dark"))
    text = visible_text(vt100_capture(monkeypatch, "q", rows=20))
    assert "╭◆━◆╮ VCoC" in text and "╭─────╮" not in text
    assert all(label in text for label in app.menu.MENU_ITEMS) and "Esc/q quit" in text


def test_menu_drops_the_logo_at_15_rows_but_keeps_every_item_and_the_hint(monkeypatch):
    theme.set_current(theme.make_theme("dark"))
    text = visible_text(vt100_capture(monkeypatch, "q", rows=15))
    assert "VCoC" not in text and "╭" not in text
    assert all(label in text for label in app.menu.MENU_ITEMS) and "Esc/q quit" in text


def test_ascii_menu_at_24_rows_shows_an_ascii_logo(monkeypatch):
    theme.set_current(theme.make_theme("dark", unicode=False))
    with theme.ascii_borders(theme.current()):
        text = visible_text(vt100_capture(monkeypatch, "q", rows=24))
    assert "VCoC" in text and text.isascii()


# ---- ASCII frame borders ------------------------------------------------------------------------------------------

def test_ascii_borders_apply_inside_the_context_and_are_restored_after():
    before = (Border.HORIZONTAL, Border.TOP_LEFT)
    with theme.ascii_borders(theme.make_theme("dark", unicode=False)):
        assert (Border.HORIZONTAL, Border.VERTICAL, Border.TOP_LEFT, Border.BOTTOM_RIGHT) == ("-", "|", "+", "+")
    assert (Border.HORIZONTAL, Border.TOP_LEFT) == before == ("─", "┌")


def test_ascii_borders_restore_even_when_the_body_raises():
    with pytest.raises(RuntimeError):
        with theme.ascii_borders(theme.make_theme("dark", unicode=False)):
            raise RuntimeError("boom")
    assert Border.HORIZONTAL == "─"


def test_unicode_themes_leave_the_borders_alone():
    with theme.ascii_borders(theme.make_theme("dark")):
        assert Border.HORIZONTAL == "─"


def test_current_theme_is_resolved_lazily_and_can_be_replaced():
    theme.set_current(None)
    first = theme.current()
    assert theme.current() is first
    custom = theme.make_theme("light")
    theme.set_current(custom)
    assert theme.current() is custom


# ---- run_shell ----------------------------------------------------------------------------------------------------

def run_shell_with(monkeypatch, tmp_path, **env):
    """Start the shell once (and quit) in a terminal that reports the given environment; return the theme it settled on."""
    for key in ("NO_COLOR", "VCOC_ASCII", "VCOC_THEME", "PROMPT_TOOLKIT_COLOR_DEPTH"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.chdir(tmp_path)
    with create_pipe_input() as pipe_input:
        pipe_input.send_text("q")
        with create_app_session(input=pipe_input, output=DummyOutput()):
            app.run_shell()
    return theme.current()


def test_run_shell_resolves_the_theme_from_the_environment_and_restores_borders(monkeypatch, tmp_path):
    shell_theme = run_shell_with(monkeypatch, tmp_path, VCOC_ASCII="1", VCOC_THEME="light", PROMPT_TOOLKIT_COLOR_DEPTH="DEPTH_24_BIT")
    assert shell_theme.name == "light" and shell_theme.unicode is False
    assert Border.HORIZONTAL == "─"  # restored when the shell exits


def test_run_shell_uses_the_ansi_palette_on_a_16_color_terminal(monkeypatch, tmp_path):
    shell_theme = run_shell_with(monkeypatch, tmp_path, TERM="xterm", PROMPT_TOOLKIT_COLOR_DEPTH="DEPTH_4_BIT")
    assert shell_theme.rules == theme.make_theme("dark", ansi16=True).rules


def test_run_shell_uses_the_linux_console_palette_on_term_linux(monkeypatch, tmp_path):
    shell_theme = run_shell_with(monkeypatch, tmp_path, TERM="linux", PROMPT_TOOLKIT_COLOR_DEPTH="DEPTH_4_BIT")
    assert shell_theme.rules["accent"] == "fg:ansibrightyellow" and shell_theme.unicode is False


def test_run_shell_uses_the_plain_theme_on_a_terminal_without_color(monkeypatch, tmp_path):
    assert run_shell_with(monkeypatch, tmp_path, PROMPT_TOOLKIT_COLOR_DEPTH="DEPTH_1_BIT").name == "plain"
    assert run_shell_with(monkeypatch, tmp_path, NO_COLOR="1", PROMPT_TOOLKIT_COLOR_DEPTH="DEPTH_24_BIT").name == "plain"
