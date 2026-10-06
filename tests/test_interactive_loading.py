"""Task 6d: heavy loads run INSIDE a full-screen 'Loading...' screen, so the plain terminal never shows between screens.

Measured 2026-09-30 on the real 92,879-row DB: the shell left the alternate screen (menu exit), did its work with the
user's plain terminal on display (280-706 ms), and only then opened the next full-screen app.
"""

from __future__ import annotations

import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from prompt_toolkit.application import create_app_session
from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput

import cli as cli_module
from vcoc.interactive import forms, menu, stage
from vcoc.interactive.app import run_shell


class RecordingOutput(DummyOutput):
    """Counts alternate-screen entries: each one is a full-screen app drawing (the plain terminal is hidden)."""

    instances: list = []

    def __init__(self, enters: int = 0):
        self.enters = enters
        self.second_screen = threading.Event()  # set on the 2nd entry = a screen other than the main menu is up
        RecordingOutput.instances.append(self)

    def enter_alternate_screen(self):
        self.screen_changed()

    def screen_changed(self):
        self.enters += 1
        if self.enters >= 2:
            self.second_screen.set()


def _session(pipe_input, output=None):
    return create_app_session(input=pipe_input, output=output or DummyOutput())


def test_run_with_loading_returns_the_value_from_a_worker_thread():
    from vcoc.interactive.loading import run_with_loading

    seen = {}

    def work():
        seen["thread"] = threading.current_thread()
        return 42

    with create_pipe_input() as pipe_input, _session(pipe_input):
        assert run_with_loading("T", work, "Loading...") == 42

    assert seen["thread"] is not threading.main_thread()
    assert seen["thread"].name == "vcoc-bgload"


def test_run_with_loading_reraises_the_workers_exception():
    from vcoc.interactive.loading import run_with_loading

    def boom():
        raise ValueError("boom")

    with create_pipe_input() as pipe_input, _session(pipe_input):
        with pytest.raises(ValueError, match="boom"):
            run_with_loading("T", boom, "Loading...")


def test_the_loading_screen_is_already_up_while_the_work_runs():
    """The whole point: the work must not run while the plain terminal is showing."""
    from vcoc.interactive.loading import run_with_loading

    out = RecordingOutput(enters=1)  # as in the real shell, where the main menu has already entered once

    def work():
        return out.second_screen.wait(5)  # True only if the loading screen entered the alt-screen during the work

    with create_pipe_input() as pipe_input, _session(pipe_input, out):
        assert run_with_loading("T", work, "Loading...") is True


def test_the_loading_screen_never_reads_the_keyboard_so_typed_ahead_keys_reach_the_next_screen():
    from vcoc.interactive.loading import run_with_loading

    with create_pipe_input() as pipe_input, _session(pipe_input):
        pipe_input.send_text("x")  # typed before / during the load
        run_with_loading("T", lambda: None, "Loading...")
        pipe_input.send_text("\r")
        assert forms.prompt_text("T", "label:") == "x"  # the 'x' was not swallowed by the loading screen


# --- the shell's data-heavy actions use it -------------------------------------------------------------------


class CountingStage(stage.StageOutput):
    """The shell keeps one alternate screen up, so a screen closing (the next one is about to draw) is the signal."""

    def quit_alternate_screen(self):
        super().quit_alternate_screen()
        self._real.screen_changed()


def _run_shell(monkeypatch, tmp_path, keys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(stage, "StageOutput", CountingStage)
    RecordingOutput.instances.clear()
    with create_pipe_input() as pipe_input:
        pipe_input.send_text(keys)
        with create_app_session(input=pipe_input, output=RecordingOutput()):
            run_shell()
    for t in threading.enumerate():
        if t.name == "vcoc-bgload":
            t.join(5)


def test_check_evidence_integrity_opens_its_search_without_loading_the_whole_index(tmp_path, monkeypatch):
    """Was: the index (92,879 rows, ~290 ms) loaded behind a loading screen. Task M3: the search reads the table a page
    at a time, so nothing is loaded up front and the screen opens at once."""

    def boom(db_path):
        raise AssertionError("the whole evidence index must not be loaded")

    monkeypatch.setattr(cli_module, "_load_evidence_index", boom)

    _run_shell(monkeypatch, tmp_path, "2" "" "q")  # Check evidence integrity, cancel, quit

    # reaching here without the AssertionError (raised on the worker/UI thread) is the point; the shell exited cleanly
    assert RecordingOutput.instances[0].enters >= 2  # the menu and the search screen both drew


def test_merkle_root_computes_behind_a_loading_screen(tmp_path, monkeypatch):
    seen = {}

    def slow_merkle_root(args):
        seen["screen_up_during_compute"] = RecordingOutput.instances[0].second_screen.wait(5)
        print("Merkle root: 00")

    monkeypatch.setattr(cli_module, "cmd_merkle_root", slow_merkle_root)

    _run_shell(monkeypatch, tmp_path, "5" "x" "q")  # Merkle root, dismiss the output screen, quit

    assert seen["screen_up_during_compute"] is True


def test_a_command_run_behind_the_loading_screen_still_returns_its_captured_output(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    shown = {}
    monkeypatch.setattr(forms, "show_output", lambda title, text: shown.update(title=title, text=text))
    monkeypatch.setattr(cli_module, "cmd_merkle_root", lambda args: print("Merkle root: abc123"))

    with create_pipe_input() as pipe_input, _session(pipe_input):
        menu.action_merkle_root({})

    assert shown == {"title": "Merkle root", "text": "Merkle root: abc123"}


# --- Task 4c: live folder-ingest view, and a final summary that no longer looks like it is still hashing -----------


def test_loading_text_without_status_is_exactly_what_it_was():
    from vcoc.interactive.loading import loading_text

    assert loading_text("Loading...", None, 1.234) == "\n  Loading...\n\n  1.2 s"


def test_loading_text_shows_the_live_status_lines_between_the_label_and_the_clock():
    from vcoc.interactive.loading import loading_text

    text = loading_text("Hashing...", "Hashing file 3 of 9\n  a/b.bin (1.0 KB)", 65.0)

    assert text == "\n  Hashing...\n\n  Hashing file 3 of 9\n    a/b.bin (1.0 KB)\n\n  65.0 s"


def test_run_with_loading_asks_for_the_status_while_the_work_runs():
    from vcoc.interactive.loading import run_with_loading

    asked = threading.Event()
    calls = []

    def status():
        calls.append(1)
        if len(calls) >= 2:  # the screen re-reads it as it refreshes, not just once
            asked.set()
        return "live"

    def work():
        return asked.wait(5)

    with create_pipe_input() as pipe_input, _session(pipe_input):
        assert run_with_loading("T", work, "L", status=status) is True


def test_a_failing_status_callback_never_breaks_the_screen():
    from vcoc.interactive.loading import run_with_loading

    def bad():
        raise RuntimeError("status exploded")

    with create_pipe_input() as pipe_input, _session(pipe_input):
        assert run_with_loading("T", lambda: 7, "L", status=bad) == 7


@pytest.mark.parametrize(
    "seconds, text",
    [(0.04, "0.0 s"), (12.34, "12.3 s"), (59.9, "59.9 s"), (60, "1 min 00 s"), (205, "3 min 25 s"), (3723, "1 h 02 min 03 s")],
)
def test_fmt_duration(seconds, text):
    assert menu._fmt_duration(seconds) == text


def test_ingest_progress_text_before_during_and_after_hashing():
    progress = menu._IngestProgress(clock=iter([100.0, 110.0, 110.0, 120.0, 120.0, 130.0]).__next__)

    assert progress.text() == "Scanning the folder..."  # the walk takes a while on big folders and reports nothing

    progress(3, 10, "sub/dir/file.bin", 2048, 1024 * 1024, 10 * 1024 * 1024)  # first call: the clock starts (100.0)
    text = progress.text()  # the clock reads 110.0: 10 s since the first call
    assert "Hashing file 3 of 10" in text
    assert "sub/dir/file.bin (2.0 KB)" in text
    assert "1.0 MB of 10.0 MB (10%)" in text
    assert "/s" in text and "left" in text  # rate and ETA

    progress(10, 10, "z.bin", 5, 10 * 1024 * 1024, 10 * 1024 * 1024)
    done = progress.text()
    assert "All 10 file(s) hashed" in done and "Recording to the database" in done
    assert "Hashing file" not in done  # the reported confusion: it must not still say it is hashing once it is not


def test_ingest_progress_shortens_very_long_paths():
    progress = menu._IngestProgress()
    progress(1, 2, "d/" * 80 + "file.bin", 1, 0, 100)

    line = [l for l in progress.text().splitlines() if "file.bin" in l][0]

    assert len(line) < 100 and "file.bin" in line


def _shell_add_folder(tmp_path, monkeypatch, *, log_event: bool, files=("a.bin", "b.bin", "sub/c.bin")):
    monkeypatch.chdir(tmp_path)
    folder = tmp_path / "evidence_dir"
    for rel in files:
        (folder / rel).parent.mkdir(parents=True, exist_ok=True)
        (folder / rel).write_bytes(rel.encode() * 100)
    shown = {}
    monkeypatch.setattr(forms, "prompt_path", lambda title, label, default="": str(folder))
    monkeypatch.setattr(
        forms, "prompt_text", lambda title, label, default="": "BATCH1" if "ID" in label else "tester"
    )
    monkeypatch.setattr(forms, "confirm", lambda question, default=False: log_event)
    monkeypatch.setattr(forms, "show_output", lambda title, text: shown.update(title=title, text=text))
    shell_config = {}
    if log_event:
        from vcoc.ecdsa_signer import generate_keypair, save_keypair

        key, _ = generate_keypair()
        save_keypair(key, tmp_path / "private_key.pem", tmp_path / "public_key.pem")
        shell_config = {"private_key": str(tmp_path / "private_key.pem"), "public_key": str(tmp_path / "public_key.pem")}
    with create_pipe_input() as pipe_input, _session(pipe_input):
        menu.action_add_evidence(shell_config)
    return shown["text"]


def test_batch_register_final_output_has_no_per_file_lines_and_a_summary_with_total_time(tmp_path, monkeypatch):
    out = _shell_add_folder(tmp_path, monkeypatch, log_event=True)

    assert "hashing" not in out.replace("Hashing", "")  # no "[i/N] hashing <file>" lines
    assert "[1/3]" not in out
    assert "Registered folder BATCH1: 3 file(s)" in out
    assert "Logged batch-register event #0 for BATCH1" in out
    assert "Files recorded" in out and "3" in out.split("Files recorded")[1].splitlines()[0]
    assert "Total time" in out and " s" in out.split("Total time")[1].splitlines()[0]
    assert "Custody event" in out and "logged" in out.split("Custody event")[1].splitlines()[0]


def test_batch_register_summary_says_when_no_custody_event_was_logged(tmp_path, monkeypatch):
    out = _shell_add_folder(tmp_path, monkeypatch, log_event=False)

    assert "Registered folder BATCH1: 3 file(s)" in out
    line = out.split("Custody event")[1].splitlines()[0]
    assert "NOT logged" in line


def test_the_shell_gives_the_loading_screen_the_live_ingest_status(tmp_path, monkeypatch):
    seen = {}
    real = menu.run_with_loading

    def spy(title, work, label="", status=None, cancel=None):
        seen["status"] = status
        return real(title, work, label, status=status, cancel=cancel)

    monkeypatch.setattr(menu, "run_with_loading", spy)

    _shell_add_folder(tmp_path, monkeypatch, log_event=False)

    assert callable(seen["status"])


def test_single_file_add_evidence_output_is_unchanged_and_has_no_summary(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    f = tmp_path / "solo.bin"
    f.write_bytes(b"solo")
    shown = {}
    monkeypatch.setattr(forms, "prompt_path", lambda title, label, default="": str(f))
    monkeypatch.setattr(forms, "prompt_text", lambda title, label, default="": "EV001")
    monkeypatch.setattr(forms, "show_output", lambda title, text: shown.update(text=text))

    with create_pipe_input() as pipe_input, _session(pipe_input):
        menu.action_add_evidence({})

    assert shown["text"].startswith("Registered evidence EV001: sha256=")
    assert "Total time" not in shown["text"]


# --- Task 4c (rest): batch-register defaults to Yes; Esc cancels a running folder ingest -----------------------------


def _answer(keys, **kw):
    with create_pipe_input() as pipe_input, _session(pipe_input):
        pipe_input.send_text(keys)
        return forms.confirm("Q?", **kw)


def test_confirm_defaults_to_no_on_enter_and_yes_when_asked():
    assert _answer("\r") is False
    assert _answer("\r", default=True) is True
    assert _answer("n", default=True) is False
    assert _answer("y") is True


def test_confirm_prompt_shows_which_answer_enter_gives():
    from vcoc.interactive.forms import confirm_prompt

    assert confirm_prompt("Q?", False).endswith("[y/N]: ")
    assert confirm_prompt("Q?", True).endswith("[Y/n]: ")


def test_batch_register_question_defaults_to_yes(tmp_path, monkeypatch):
    asked = {}
    _shell_add_folder_with(
        tmp_path,
        monkeypatch,
        confirm=lambda question, default=False: asked.update(question=question, default=default) or False,
    )
    assert "batch-register" in asked["question"] and asked["default"] is True


def _shell_add_folder_with(tmp_path, monkeypatch, run=None, confirm=lambda question, default=False: False):
    monkeypatch.chdir(tmp_path)
    folder = tmp_path / "evidence_dir"
    folder.mkdir()
    (folder / "a.bin").write_bytes(b"a" * 100)
    shown = {}
    monkeypatch.setattr(forms, "prompt_path", lambda title, label, default="": str(folder))
    monkeypatch.setattr(forms, "prompt_text", lambda title, label, default="": "BATCH1")
    monkeypatch.setattr(forms, "show_output", lambda title, text: shown.update(text=text))
    monkeypatch.setattr(forms, "confirm", confirm)
    if run is not None:
        monkeypatch.setattr(menu, "run_with_loading", run)
    with create_pipe_input() as pipe_input, _session(pipe_input):
        menu.action_add_evidence({})
    return shown.get("text", "")


def test_escape_on_the_loading_screen_calls_cancel_and_waits_for_the_work():
    from vcoc.interactive.loading import run_with_loading

    stop = threading.Event()

    def work():
        stop.wait(10)
        return "done"

    with create_pipe_input() as pipe_input, _session(pipe_input):
        pipe_input.send_text("\x1b")
        assert run_with_loading("T", work, "Loading...", cancel=stop.set) == "done"
    assert stop.is_set()


def test_loading_screen_without_cancel_still_ignores_keys_and_shows_no_esc_hint():
    from vcoc.interactive.loading import loading_text

    assert "Esc" not in loading_text("L", None, 1.0)
    assert "Esc" in loading_text("L", None, 1.0, hint="Esc cancels")


def test_cancelling_a_folder_add_records_nothing_and_says_so(tmp_path, monkeypatch):
    def cancel_at_once(title, work, label="", status=None, cancel=None):
        cancel()  # the user pressed Esc before the first file
        return work()

    out = _shell_add_folder_with(tmp_path, monkeypatch, run=cancel_at_once)

    assert "Cancelled" in out and "nothing was recorded" in out
    assert "Registered folder" not in out
    assert cli_module._load_evidence_index(cli_module.DEFAULT_DB) == {}
    assert cli_module._load_folder_index(cli_module.DEFAULT_DB) == {}
