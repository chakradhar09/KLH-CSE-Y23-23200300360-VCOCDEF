"""Reproduces two bugs found in show_output's scroll handling for long stdout
(e.g. a Merkle proof screen taller than the terminal):

1. show_output originally bound "<any>" key to exit -- so pressing up/down/
   PageDown to scroll bounced the user straight back to the menu instead of
   scrolling.
2. After binding up/down/PageUp/PageDown as scroll keys, they were wired to
   prompt_toolkit's scroll_one_line_down/up and scroll_page_down/up, which
   move event.app.current_buffer's cursor -- but the window used a bare
   FormattedTextControl (no Buffer, no cursor), so those bindings silently
   did nothing: content never actually moved, even though the screen no
   longer exited.

Fixed by giving the window a real (read-only) Buffer/BufferControl so the
cursor exists and scrolling has something to move.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from prompt_toolkit.application import create_app_session
from prompt_toolkit.input.defaults import create_pipe_input
from prompt_toolkit.output import DummyOutput

from vcoc.interactive import forms

LONG_TEXT = "\n".join(f"line {i}" for i in range(200))


def _run_show_output_with_keys(keys: str, text: str = LONG_TEXT) -> None:
    with create_pipe_input() as pipe_input:
        pipe_input.send_text(keys)
        with create_app_session(input=pipe_input, output=DummyOutput()):
            forms.show_output("Merkle proof", text)


def test_scroll_keys_do_not_exit_show_output():
    # 'down' would previously match the "<any>" binding and exit immediately;
    # if that regresses, this call blocks (pipe runs dry) and pytest times out.
    _run_show_output_with_keys("\x1b[B\x1b[B\x1b[5~q")


def test_q_exits_show_output():
    _run_show_output_with_keys("q")


def test_scroll_bindings_move_a_real_buffer_cursor():
    # Guards against scroll keys being wired up but inert (bug #2 above): with
    # a bare FormattedTextControl there is no buffer, so scroll_one_line_down
    # / scroll_page_down silently no-op. Exercise the same binding against
    # the Buffer/BufferControl show_output now uses, directly.
    from prompt_toolkit.application import Application
    from prompt_toolkit.buffer import Buffer
    from prompt_toolkit.document import Document
    from prompt_toolkit.key_binding import KeyBindings
    from prompt_toolkit.key_binding.bindings.scroll import scroll_page_down
    from prompt_toolkit.layout import Layout, Window
    from prompt_toolkit.layout.controls import BufferControl

    buf = Buffer(document=Document(LONG_TEXT, 0), read_only=True)
    window = Window(BufferControl(buffer=buf, focusable=True))

    kb = KeyBindings()
    kb.add("pagedown")(scroll_page_down)

    @kb.add("q")
    def _(event):
        event.app.exit()

    with create_pipe_input() as pipe_input:
        pipe_input.send_text("\x1b[6~q")
        with create_app_session(input=pipe_input, output=DummyOutput()):
            app = Application(
                layout=Layout(window, focused_element=window),
                key_bindings=kb,
                full_screen=True,
            )
            app.run()

    assert buf.document.cursor_position_row > 0
