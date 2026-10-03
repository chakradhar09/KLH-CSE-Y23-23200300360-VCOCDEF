from __future__ import annotations

import asyncio
import threading
import time

from prompt_toolkit import Application
from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import Layout, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.widgets import Frame

from . import theme


def loading_text(label: str, status: str | None, elapsed: float, hint: str | None = None) -> str:
    """The loading screen's text: label, optional live status lines, the elapsed-time clock, optional key hint."""
    body = f"\n  {label}\n"
    if status:
        body += "\n" + "\n".join(f"  {line}" for line in status.splitlines()) + "\n"
    body += f"\n  {elapsed:.1f} s"
    return f"{body}\n\n  {hint}" if hint else body


def run_with_loading(title: str, work, label: str = "Loading...", status=None, cancel=None):
    """Run work() on a worker thread behind a full-screen loading screen; return its value or re-raise its error.

    Each shell screen used to leave the alternate screen (the menu exits), do its slow work with the user's plain terminal
    on display (280-706 ms on 92,879 rows), and only then open the next full-screen app. Keeping a screen up while the work
    runs removes that flash: hand-offs between full-screen apps take 6-27 ms.

    By default the screen has its own empty input and never reads the keyboard, so keys typed meanwhile stay queued for
    the next screen. Ctrl-C is not a cancel: the work may write to the database, so it always runs to completion.

    `cancel`, if given, is a zero-argument callable and turns Esc into a cancel request: the screen then reads the real
    keyboard, calls it once, and shows "Cancelling..." until work() returns. work() must notice the request itself and
    stop (the caller decides what a cancelled result looks like); nothing is interrupted from here.

    `status`, if given, is a zero-argument callable returning live progress text; it is re-read on every refresh
    (10 times a second) from the event loop, so it must be cheap, and a failure in it never breaks the screen.
    """
    outcome: dict = {}
    started = time.monotonic()
    cancelling = False

    def render() -> str:
        elapsed = time.monotonic() - started
        try:
            live = status() if status is not None else theme.marquee(elapsed)  # no status, no percentage: show a wait
        except Exception:
            live = None
        hint = None if cancel is None else "Cancelling... finishing the current file" if cancelling else "Esc cancels"
        return loading_text(label, live, elapsed, hint)

    keys = KeyBindings()

    @keys.add("escape", eager=True)
    def _(event) -> None:
        nonlocal cancelling
        if cancel is not None and not cancelling:
            cancelling = True
            cancel()

    control = FormattedTextControl(theme.styled(render, "loading"))
    workers: list[threading.Thread] = []

    with create_pipe_input() as no_keys:
        app = Application(
            layout=Layout(Frame(Window(control), title=title)),
            key_bindings=keys,
            full_screen=True,
            input=None if cancel is not None else no_keys,
            refresh_interval=0.1,  # keeps the elapsed-time line ticking
            style=theme.app_style(theme.current()),
        )

        def pre_run() -> None:
            # Runs on the event loop with the app's future already set, so app.exit() is safe once the work is done.
            loop = asyncio.get_running_loop()
            finished = loop.create_future()

            def run() -> None:
                try:
                    outcome["value"] = work()
                except BaseException as exc:  # re-raised on the caller's thread below
                    outcome["error"] = exc
                finally:
                    try:
                        loop.call_soon_threadsafe(lambda: finished.done() or finished.set_result(None))
                    except RuntimeError:
                        pass  # the loop is already closed (Ctrl-C path): the caller joins this thread instead

            async def close_when_done() -> None:
                await finished
                if app.is_running:
                    app.exit()

            app.create_background_task(close_when_done())
            worker = threading.Thread(target=run, daemon=True, name="vcoc-bgload")
            workers.append(worker)
            worker.start()

        try:
            app.run(pre_run=pre_run)
        except KeyboardInterrupt:
            pass  # wait for the work below instead of abandoning it half done
        for worker in workers:
            worker.join()

    if "error" in outcome:
        raise outcome["error"]
    return outcome.get("value")
