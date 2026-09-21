"""Main menu: key bindings, screen switching, store lifecycle.

Screens run as a sequence of independent, top-level Application.run() calls
-- never nested (nesting an Application.run() inside another running
Application's key handler deadlocks prompt_toolkit's asyncio event loop).
Each menu selection exits the menu Application with a result, the action
runs to completion, then the next loop iteration draws a fresh menu.
"""

from __future__ import annotations

from pathlib import Path

from prompt_toolkit import Application
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import Layout, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.widgets import Frame

from vcoc.storage import EncryptedStore

from . import config, forms, menu, store_bridge

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
    """Run the menu screen once; return the chosen index (or QUIT_INDEX)."""
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

    for digit in "1234567890":  # "0" maps to the 10th item

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


def _get_store() -> EncryptedStore | None:
    """Ask the user once whether to open/create the encrypted store mirror."""
    key_path, db_path = store_bridge.DEFAULT_KEY_PATH, store_bridge.DEFAULT_DB_PATH
    if not Path(key_path).exists():
        if not forms.confirm(f"No encrypted store key found. Generate one now at {key_path}?"):
            return None
    store, message = store_bridge.open_or_create_store(key_path, db_path)
    forms.show_output("Encrypted store", message)
    return store


def run_shell() -> None:
    store: EncryptedStore | None = None
    store_prompted = False
    shell_config = config.load_config()
    try:
        while True:
            index = _run_main_menu()
            if index == QUIT_INDEX:
                break
            if index == 0 and not store_prompted:  # Add evidence: first-use store prompt
                store_prompted = True
                store = _get_store()
            menu.ACTIONS[index](store, shell_config)
    finally:
        if store is not None:
            store.close()
