"""Small full-screen text-input prompts (file path, actor, action, key paths).

Each function blocks until the user hits Enter (returns the typed string) or
Escape (returns None).
"""

from __future__ import annotations

import os
from pathlib import Path

from prompt_toolkit import Application
from prompt_toolkit.buffer import Buffer
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import HSplit, Layout, Window
from prompt_toolkit.layout.controls import BufferControl, FormattedTextControl
from prompt_toolkit.layout.dimension import D
from prompt_toolkit.widgets import Frame


def prompt_text(title: str, label: str, default: str = "") -> str | None:
    buf = Buffer(multiline=False)
    buf.text = default

    kb = KeyBindings()

    @kb.add("enter")
    def _(event):
        event.app.exit(result=buf.text)

    @kb.add("escape")
    @kb.add("c-c")
    def _(event):
        event.app.exit(result=None)

    body = HSplit(
        [
            Window(FormattedTextControl(lambda: f" {label}"), height=1),
            Frame(Window(BufferControl(buffer=buf)), height=D(min=3, max=3)),
            Window(FormattedTextControl(lambda: " Enter confirm   Esc cancel"), height=1),
        ]
    )
    app = Application(
        layout=Layout(Frame(body, title=title)),
        key_bindings=kb,
        full_screen=True,
    )
    return app.run()


def _glob_matches(text: str, dirs_only: bool) -> list[Path]:
    """List filesystem entries matching the partial last path segment of text."""
    if not text:
        parent, fragment = Path("."), ""
    elif text.endswith(("/", "\\")):
        parent, fragment = Path(text), ""
    else:
        raw = Path(text)
        parent, fragment = (raw.parent, raw.name) if raw.name else (raw, "")
    if not parent.is_dir():
        return []
    try:
        entries = sorted(parent.glob(fragment + "*"))
    except OSError:
        return []
    if dirs_only:
        entries = [e for e in entries if e.is_dir()]
    return entries


def prompt_path(title: str, label: str, default: str = "", dirs_only: bool = False) -> str | None:
    """Text prompt with live filesystem autofill.

    Typing filters a results pane (sibling files/dirs matching the partial
    last path segment). Tab/Down moves into the results; Enter on a
    highlighted directory descends into it (keeps editing); Enter on a
    highlighted file returns its full path; Enter with nothing highlighted
    submits the typed text as-is -- manual/absolute paths always work even
    with no filesystem match.
    # ponytail: glob-per-keystroke against the literal parent dir, same
    # approach as store_bridge's in-memory filter -- no fuzzy matching, no
    # recursive walk; add fuzzy ranking only if flat prefix listing proves
    # annoying in practice.
    """
    buf = Buffer(multiline=False)
    buf.text = default
    matches: list[Path] = _glob_matches(default, dirs_only)
    selected = [-1]  # -1 = no result highlighted (typed text wins on Enter)

    def refresh(_=None):
        nonlocal matches
        matches = _glob_matches(buf.text, dirs_only)
        selected[0] = -1

    buf.on_text_changed += refresh

    def get_results_text():
        if not matches:
            return "  (no matches)"
        lines = []
        for i, entry in enumerate(matches):
            marker = "▸" if i == selected[0] else " "
            suffix = os.sep if entry.is_dir() else ""
            lines.append(f"{marker} {entry.name}{suffix}")
        return "\n".join(lines)

    kb = KeyBindings()

    @kb.add("tab")
    @kb.add("down")
    def _(event):
        if matches:
            selected[0] = (selected[0] + 1) % len(matches)

    @kb.add("up")
    def _(event):
        if matches:
            selected[0] = (selected[0] - 1) % len(matches)

    @kb.add("enter")
    def _(event):
        if selected[0] == -1 or not matches:
            event.app.exit(result=buf.text)
            return
        chosen = matches[selected[0]]
        if chosen.is_dir() and not dirs_only:
            buf.text = str(chosen) + os.sep
            buf.cursor_position = len(buf.text)
            selected[0] = -1
        else:
            event.app.exit(result=str(chosen))

    @kb.add("escape")
    @kb.add("c-c")
    def _(event):
        event.app.exit(result=None)

    body = HSplit(
        [
            Window(FormattedTextControl(lambda: f" {label}"), height=1),
            Frame(Window(BufferControl(buffer=buf)), height=D(min=3, max=3)),
            Window(FormattedTextControl(get_results_text)),
            Window(
                FormattedTextControl(
                    lambda: " Tab/↓ browse matches   Enter select/confirm   Esc cancel"
                ),
                height=1,
            ),
        ]
    )
    app = Application(
        layout=Layout(Frame(body, title=title)),
        key_bindings=kb,
        full_screen=True,
    )
    return app.run()


def confirm(question: str) -> bool:
    kb = KeyBindings()

    @kb.add("y")
    @kb.add("Y")
    def _(event):
        event.app.exit(result=True)

    @kb.add("n")
    @kb.add("N")
    @kb.add("escape")
    @kb.add("c-c")
    @kb.add("enter")
    def _(event):
        event.app.exit(result=False)

    control = FormattedTextControl(lambda: f" {question} [y/N]: ")
    app = Application(
        layout=Layout(Frame(Window(control))),
        key_bindings=kb,
        full_screen=True,
    )
    return bool(app.run())


def show_output(title: str, text: str) -> None:
    kb = KeyBindings()

    @kb.add("<any>")
    def _(event):
        event.app.exit()

    control = FormattedTextControl(lambda: text + "\n\n[press any key to return to menu]")
    app = Application(
        layout=Layout(Frame(Window(control), title=title)),
        key_bindings=kb,
        full_screen=True,
    )
    app.run()
