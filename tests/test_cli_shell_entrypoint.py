"""Headless smoke tests for the interactive shell (no real TTY)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from prompt_toolkit.application import create_app_session
from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput

from vcoc.interactive.app import run_shell


def run_with_keys(keys: str, cwd: Path) -> None:
    import os

    old_cwd = os.getcwd()
    os.chdir(cwd)
    try:
        with create_pipe_input() as pipe_input:
            pipe_input.send_text(keys)
            with create_app_session(input=pipe_input, output=DummyOutput()):
                run_shell()
    finally:
        os.chdir(old_cwd)


def test_shell_quits_immediately(tmp_path):
    run_with_keys("q", tmp_path)


def test_shell_verify_chain_then_quit(tmp_path):
    # Verify chain now gates on ensure_keys first (Task 8); with no keys
    # configured/present in a fresh dir, Ctrl-C at the key-path prompt
    # cancels the gate and returns to the menu without crashing. (Ctrl-C,
    # not Escape: a bare \x1b immediately followed by another character in
    # one send_text() burst is parsed as an Alt-modified keypress rather
    # than two separate keys, which stalls the next screen waiting for
    # input that was consumed as part of the Alt sequence.)
    run_with_keys("5" + "\x03" + "q", tmp_path)


def test_shell_merkle_root_then_quit(tmp_path):
    run_with_keys("6" + "x" + "q", tmp_path)


def test_shell_add_evidence_then_check(tmp_path):
    evidence_file = tmp_path / "sample.txt"
    evidence_file.write_text("synthetic evidence bytes", encoding="utf-8")

    keys = (
        "1"  # Add evidence
        + "n"  # decline encrypted-store creation
        + str(evidence_file) + "\r"  # file path
        + "EV001\r"  # evidence id
        + "x"  # dismiss output screen
        + "3"  # Check evidence integrity
        + "EV001\r"  # search screen: type id, Enter selects
        + str(evidence_file) + "\r"  # file path
        + "x"  # dismiss output screen
        + "q"  # quit
    )
    run_with_keys(keys, tmp_path)

    index_path = tmp_path / "evidence_index.json"
    assert index_path.exists()
    assert '"EV001"' in index_path.read_text(encoding="utf-8")


def test_shell_verification_screen_empty_state(tmp_path):
    # No evidence/log/keys exist yet -- every tab should show an empty-state
    # row rather than crash. Open the screen (item 9), cycle all three tabs,
    # then back out to the menu and quit.
    keys = (
        "9"  # Verification
        + "\t"  # Chain -> Evidence
        + "\t"  # Evidence -> Merkle
        + "\t"  # Merkle -> Chain (wraps)
        + "q"  # back to main menu
        + "q"  # quit
    )
    run_with_keys(keys, tmp_path)


def test_shell_verification_screen_after_add_evidence(tmp_path):
    evidence_file = tmp_path / "sample.txt"
    evidence_file.write_text("synthetic evidence bytes", encoding="utf-8")

    keys = (
        "1"  # Add evidence
        + "n"  # decline encrypted-store creation
        + str(evidence_file) + "\r"
        + "EV001\r"
        + "x"
        + "9"  # Verification
        + "2"  # jump to Evidence tab
        + "\x12"  # Ctrl-R refresh
        + "q"
        + "q"
    )
    run_with_keys(keys, tmp_path)
