
from __future__ import annotations

from prompt_toolkit import Application
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import Layout, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.widgets import Frame

from . import config, menu

QUIT_INDEX = len(menu.MENU_ITEMS) - 1


def _render_menu(selected: int) -> str:
    lines = []
    for i, label in enumerate(menu.MENU_ITEMS):
        marker = "▸" if i == selected else " "
        digit = "0" if i == 9 else str(i + 1)
        lines.append(f"{marker} {digit}  {label}")
    lines.append("")
    lines.append("↑/↓ navigate   1-9,0 jump   Enter select   Esc/q quit")
    return "\n".join(lines)


def _run_main_menu() -> int:
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

    control = FormattedTextControl(lambda: _render_menu(selected[0]))
    app = Application(
        layout=Layout(Frame(Window(control), title="Verifiable Chain-of-Custody — Interactive Shell")),
        key_bindings=kb,
        full_screen=True,
    )
    result = app.run()
    return QUIT_INDEX if result is None else result


def run_shell() -> None:
    shell_config = config.load_config()
    while True:
        index = _run_main_menu()
        if index == QUIT_INDEX:
            break
        menu.ACTIONS[index](shell_config)
