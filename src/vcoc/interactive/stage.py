from __future__ import annotations

from contextlib import contextmanager

from prompt_toolkit.application import create_app_session, get_app_session
from prompt_toolkit.data_structures import Size


class StageOutput:
    """Wraps the real output so the shell's screens share one alternate screen.

    Every screen is its own full-screen app, and each used to enter the alternate screen on start and leave it on exit, so
    the user's plain terminal showed between any two screens. Here a screen's enter is ignored and its leave only homes the
    cursor: the app that just closed ended below its layout, and the next one assumes it starts at the top. The previous
    frame stays up until the next app paints over it (its first write erases from the top down).
    """

    def __init__(self, real) -> None:
        self._real = real

    def enter_alternate_screen(self) -> None:
        pass

    def quit_alternate_screen(self) -> None:
        self._real.cursor_goto(0, 0)
        self._real.flush()

    def get_size(self) -> Size:
        # A closing app puts the cursor on the row below its layout with a newline; a frame as tall as the terminal would
        # scroll the screen up one row at that moment. One spare row keeps that newline on screen.
        size = self._real.get_size()
        return Size(rows=max(1, size.rows - 1), columns=size.columns)

    def __getattr__(self, name: str):
        return getattr(self._real, name)


@contextmanager
def stage():
    """Enter the alternate screen once, run the shell inside it, leave once, even if the shell raises."""
    session = get_app_session()
    real = session.output
    real.enter_alternate_screen()
    try:
        with create_app_session(input=session.input, output=StageOutput(real)):
            yield
    finally:
        real.quit_alternate_screen()
        real.show_cursor()
        real.flush()
