"""Live search-as-you-type screen over evidence_index.json + EncryptedStore."""

from __future__ import annotations

from prompt_toolkit import Application
from prompt_toolkit.buffer import Buffer
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import HSplit, Layout, Window
from prompt_toolkit.layout.controls import BufferControl, FormattedTextControl
from prompt_toolkit.layout.dimension import D
from prompt_toolkit.widgets import Frame

from vcoc.storage import EncryptedStore

from . import store_bridge


def _format_result(entry: dict, selected: bool) -> str:
    marker = "▸" if selected else " "
    eid = entry["evidence_id"].ljust(10)
    fname = entry["original_filename"][:28].ljust(28)
    sha = (entry["index_sha256"] or entry["store_sha256"] or "")[:8]
    tag = entry["tag"]
    line = f"{marker} {eid} {fname} {sha}...  [{tag}]"
    if tag == "DIVERGED":
        line += (
            f"\n     index sha256: {entry['index_sha256']}"
            f"\n     store sha256: {entry['store_sha256']}"
        )
    return line


def search_evidence(index: dict, store: EncryptedStore | None) -> str | None:
    """Run the live search screen; return the selected evidence_id, or None."""
    query_buf = Buffer(multiline=False)
    results: list[dict] = store_bridge.search(index, store, "")
    selected = [0]

    def get_results_text():
        if not results:
            return "  (no matches)"
        lines = []
        for i, entry in enumerate(results):
            lines.append(_format_result(entry, i == selected[0]))
        return "\n".join(lines)

    def refresh(_=None):
        nonlocal results
        results = store_bridge.search(index, store, query_buf.text)
        selected[0] = min(selected[0], max(len(results) - 1, 0))

    query_buf.on_text_changed += refresh

    kb = KeyBindings()

    @kb.add("up")
    def _(event):
        if results:
            selected[0] = max(0, selected[0] - 1)

    @kb.add("down")
    def _(event):
        if results:
            selected[0] = min(len(results) - 1, selected[0] + 1)

    @kb.add("enter")
    def _(event):
        if results:
            event.app.exit(result=results[selected[0]]["evidence_id"])
        else:
            event.app.exit(result=None)

    @kb.add("c-r")
    @kb.add("f5")
    def _(event):
        refresh()

    @kb.add("escape")
    @kb.add("c-c")
    def _(event):
        event.app.exit(result=None)

    body = HSplit(
        [
            Window(FormattedTextControl(lambda: " Query:"), height=1),
            Frame(Window(BufferControl(buffer=query_buf)), height=D(min=3, max=3)),
            Window(FormattedTextControl(get_results_text)),
            Window(
                FormattedTextControl(
                    lambda: " ↑/↓ select   Enter choose   Ctrl-R/F5 refresh   Esc cancel"
                ),
                height=1,
            ),
        ]
    )
    app = Application(
        layout=Layout(Frame(body, title="Search / Browse Evidence")),
        key_bindings=kb,
        full_screen=True,
    )
    return app.run()
