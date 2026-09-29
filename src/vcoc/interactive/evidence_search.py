
from __future__ import annotations

from prompt_toolkit import Application
from prompt_toolkit.buffer import Buffer
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import HSplit, Layout, Window
from prompt_toolkit.layout.controls import BufferControl, FormattedTextControl
from prompt_toolkit.layout.dimension import D
from prompt_toolkit.widgets import Frame


def search(index: dict, query: str) -> list[dict]:
    q = query.lower()
    results = [
        {
            "evidence_id": eid,
            "original_filename": rec.get("original_filename", ""),
            "sha256": rec.get("sha256", ""),
        }
        for eid, rec in index.items()
    ]
    if q:
        results = [r for r in results if q in r["evidence_id"].lower() or q in r["original_filename"].lower()]
    results.sort(key=lambda r: r["evidence_id"])
    return results


def _format_result(entry: dict, selected: bool) -> str:
    marker = "▸" if selected else " "
    eid = entry["evidence_id"].ljust(10)
    fname = entry["original_filename"][:28].ljust(28)
    return f"{marker} {eid} {fname} {entry['sha256'][:8]}..."


def _format_result_multi(entry: dict, selected: bool, checked: bool) -> str:
    marker = "▸" if selected else " "
    box = "[x]" if checked else "[ ]"
    eid = entry["evidence_id"].ljust(10)
    fname = entry["original_filename"][:28].ljust(28)
    return f"{marker} {box} {eid} {fname} {entry['sha256'][:8]}..."


def search_evidence_multi(index: dict) -> list[str] | None:
    query_buf = Buffer(multiline=False)
    results: list[dict] = search(index, "")
    selected = [0]
    checked: set[str] = set()

    def get_results_text():
        if not results:
            return "  (no matches)"
        lines = []
        for i, entry in enumerate(results):
            lines.append(_format_result_multi(entry, i == selected[0], entry["evidence_id"] in checked))
        return "\n".join(lines)

    def refresh(_=None):
        nonlocal results
        results = search(index, query_buf.text)
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

    @kb.add(" ")
    def _(event):
        if not results:
            return
        eid = results[selected[0]]["evidence_id"]
        if eid in checked:
            checked.discard(eid)
        else:
            checked.add(eid)

    @kb.add("enter")
    def _(event):
        if checked:
            event.app.exit(result=[r["evidence_id"] for r in results if r["evidence_id"] in checked])
        elif results:
            event.app.exit(result=[results[selected[0]]["evidence_id"]])
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
                    lambda: " ↑/↓ select   Space toggle   Enter confirm   Ctrl-R/F5 refresh   Esc cancel"
                ),
                height=1,
            ),
        ]
    )
    app = Application(
        layout=Layout(Frame(body, title="Search / Browse Evidence (multi-select)")),
        key_bindings=kb,
        full_screen=True,
    )
    return app.run()


def search_evidence(index: dict) -> str | None:
    query_buf = Buffer(multiline=False)
    results: list[dict] = search(index, "")
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
        results = search(index, query_buf.text)
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
