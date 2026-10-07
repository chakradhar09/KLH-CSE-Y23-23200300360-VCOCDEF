
from __future__ import annotations

import os

from prompt_toolkit import Application
from prompt_toolkit.application import get_app
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import Layout, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.widgets import Frame

import cli as cli_module

from . import config, menu, stage, status, theme

QUIT_INDEX = len(menu.MENU_ITEMS) - 1
MENU_TITLE = "Verifiable Chain-of-Custody — Interactive Shell"


def _render_menu(selected: int) -> str:
    lines = []
    for i, label in enumerate(menu.MENU_ITEMS):
        marker = "▸" if i == selected else " "
        digit = "0" if i == 9 else str(i + 1)
        lines.append(f"{marker} {digit}  {label}")
    lines.append("")
    lines.append("↑/↓ navigate   1-9,0 jump   Enter select   Esc/q quit")
    return "\n".join(lines)


def _terminal_rows() -> int:
    try:
        return get_app().output.get_size().rows
    except Exception:
        return 0  # no terminal to ask: show no logo


def _menu_fragments(selected: int, shell_theme: theme.Theme, width: int | None = None):
    return theme.for_display(theme.colorize(_render_menu(selected), "menu", shell_theme, width=width), shell_theme)


def _logo_fragments(shell_theme: theme.Theme, rows: int):
    """The logo for a terminal `rows` tall, each line ended by a newline plus one blank line; empty when it does not fit."""
    out = []
    for line in theme.logo_lines(rows):
        out.extend(line)
        out.append(("", "\n"))
    if out:
        out.append(("", "\n"))
    return theme.for_display(out, shell_theme)


def _header_fragments(header: status.ChainStatus | None, shell_theme: theme.Theme, rows: int, width: int | None):
    """The status header for a terminal `rows` tall: a line, a rule and a blank line from 18 rows, just the line from 14."""
    if header is None or rows < 14:
        return []
    out = list(theme.colorize(status.header_text(header), "header", shell_theme)) + [("", "\n")]
    if rows >= 18:
        out += [("class:chrome", "─" * (width or 78)), ("", "\n"), ("", "\n")]
    return theme.for_display(out, shell_theme)


def _frame_style(header: status.ChainStatus | None) -> str:
    return f"class:state-{header.frame_state}" if header is not None and header.frame_state else ""


def _read_status(shell_config: dict) -> status.ChainStatus | None:
    """The header's data, read once each time the menu is about to appear; any failure just means no header."""
    try:
        return status.current_status(shell_config, os.path.abspath(cli_module.DEFAULT_DB))
    except Exception:
        return None


def _screen_fragments(selected: int, shell_theme: theme.Theme, width: int | None, rows: int, header=None):
    return (
        _logo_fragments(shell_theme, rows)
        + _header_fragments(header, shell_theme, rows, width)
        + _menu_fragments(selected, shell_theme, width)
    )


def _menu_title(shell_theme: theme.Theme) -> str:
    return "".join(text for _, text in theme.for_display([("", MENU_TITLE)], shell_theme))


def _run_main_menu(header: status.ChainStatus | None = None) -> int:
    shell_theme = theme.current()
    selected = [0]
    kb = KeyBindings()

    @kb.add("up")
    def _(event):
        selected[0] = (selected[0] - 1) % len(menu.MENU_ITEMS)

    @kb.add("down")
    def _(event):
        selected[0] = (selected[0] + 1) % len(menu.MENU_ITEMS)

    @kb.add("enter")
    def _(event):
        event.app.exit(result=selected[0])

    @kb.add("q")
    @kb.add("escape")
    def _(event):
        event.app.exit(result=QUIT_INDEX)

    for digit in "1234567890":

        def make_handler(d=digit):
            def handler(event):
                idx = 9 if d == "0" else int(d) - 1
                if idx < len(menu.MENU_ITEMS):
                    event.app.exit(result=idx)

            return handler

        kb.add(digit)(make_handler())

    control = FormattedTextControl(
        lambda: _screen_fragments(selected[0], shell_theme, theme.inner_width(), _terminal_rows(), header)
    )
    app = Application(
        layout=Layout(Frame(Window(control), title=_menu_title(shell_theme), style=_frame_style(header))),
        key_bindings=kb,
        full_screen=True,
        style=theme.app_style(shell_theme),
    )
    result = app.run()
    return QUIT_INDEX if result is None else result


def run_shell() -> None:
    shell_config = config.load_config()
    shell_theme = theme.resolve_theme(color_depth=theme.detect_color_depth())
    theme.set_current(shell_theme)
    with theme.ascii_borders(shell_theme), stage.stage():
        while True:
            index = _run_main_menu(_read_status(shell_config))
            if index == QUIT_INDEX:
                break
            menu.ACTIONS[index](shell_config)
