"""Reproduces the reported bug: show_output's `<any>` key binding exited the
screen on ANY keypress, so pressing up/down/PageDown to scroll long output
(e.g. Merkle proof) bounced the user straight back to the menu instead of
scrolling. Only Esc/q/Ctrl-C should exit; arrow/page keys must scroll instead.
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


def _run_show_output_with_keys(keys: str) -> None:
    with create_pipe_input() as pipe_input:
        pipe_input.send_text(keys)
        with create_app_session(input=pipe_input, output=DummyOutput()):
            forms.show_output("Merkle proof", "\n".join(f"line {i}" for i in range(200)))


def test_scroll_keys_do_not_exit_show_output():
    # 'down' would previously match the "<any>" binding and exit immediately;
    # if that regresses, this call blocks (pipe runs dry) and pytest times out.
    _run_show_output_with_keys("\x1b[B\x1b[B\x1b[5~q")


def test_q_exits_show_output():
    _run_show_output_with_keys("q")
