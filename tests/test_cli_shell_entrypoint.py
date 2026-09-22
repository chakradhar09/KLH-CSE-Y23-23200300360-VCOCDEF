"""Headless smoke tests for the interactive shell (no real TTY)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from prompt_toolkit.application import create_app_session
from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput

from vcoc.interactive import menu
from vcoc.interactive.app import run_shell


def test_search_browse_evidence_menu_item_removed():
    assert "Search / browse evidence" not in menu.MENU_ITEMS
    assert not hasattr(menu, "action_search")


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
    run_with_keys("4" + "\x03" + "q", tmp_path)


def test_shell_merkle_root_then_quit(tmp_path):
    run_with_keys("5" + "x" + "q", tmp_path)


def test_shell_add_evidence_then_check(tmp_path):
    evidence_file = tmp_path / "sample.txt"
    evidence_file.write_text("synthetic evidence bytes", encoding="utf-8")

    keys = (
        "1"  # Add evidence
        + "n"  # decline encrypted-store creation
        + str(evidence_file) + "\r"  # file path
        + "EV001\r"  # evidence id
        + "x"  # dismiss output screen
        + "2"  # Check evidence integrity
        + "EV001\r"  # search screen: type id, Enter selects
        + "x"  # dismiss output screen
        + "q"  # quit
    )
    run_with_keys(keys, tmp_path)

    index_path = tmp_path / "evidence_index.json"
    assert index_path.exists()
    assert '"EV001"' in index_path.read_text(encoding="utf-8")


def test_shell_verification_screen_empty_state(tmp_path):
    # No evidence/log/keys exist yet -- every tab should show an empty-state
    # row rather than crash. Open the screen (item 8), cycle all three tabs,
    # then back out to the menu and quit.
    keys = (
        "8"  # Verification
        + "\t"  # Chain -> Evidence
        + "\t"  # Evidence -> Merkle
        + "\t"  # Merkle -> Chain (wraps)
        + "q"  # back to main menu
        + "q"  # quit
    )
    run_with_keys(keys, tmp_path)


def test_shell_add_evidence_folder_mirrors_all_members(tmp_path):
    folder = tmp_path / "batchdir"
    folder.mkdir()
    (folder / "a.txt").write_text("aaa", encoding="utf-8")
    (folder / "b.txt").write_text("bbb", encoding="utf-8")

    keys = (
        "1"  # Add evidence
        + "y"  # accept encrypted-store creation
        + "x"  # dismiss "Encrypted store" info screen
        + str(folder) + "\r"  # folder path
        + "BATCH1\r"  # folder/batch id
        + "n"  # decline batch custody-event logging
        + "x"  # dismiss output screen
        + "q"  # quit
    )
    run_with_keys(keys, tmp_path)

    index_path = tmp_path / "evidence_index.json"
    assert index_path.exists()
    assert '"BATCH1/a.txt"' in index_path.read_text(encoding="utf-8")
    assert '"BATCH1/b.txt"' in index_path.read_text(encoding="utf-8")

    import sys as _sys

    _sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
    from vcoc.storage import EncryptedStore, load_key

    key = load_key(str(tmp_path / "vcoc.key"))
    store = EncryptedStore(str(tmp_path / "evidence_store.db"), key)
    try:
        stored_ids = {e.evidence_id for e in store.list_evidence()}
    finally:
        store.close()
    assert "BATCH1/a.txt" in stored_ids
    assert "BATCH1/b.txt" in stored_ids


def test_shell_verification_screen_after_add_evidence(tmp_path):
    evidence_file = tmp_path / "sample.txt"
    evidence_file.write_text("synthetic evidence bytes", encoding="utf-8")

    keys = (
        "1"  # Add evidence
        + "n"  # decline encrypted-store creation
        + str(evidence_file) + "\r"
        + "EV001\r"
        + "x"
        + "8"  # Verification
        + "2"  # jump to Evidence tab
        + "\x12"  # Ctrl-R refresh
        + "q"
        + "q"
    )
    run_with_keys(keys, tmp_path)
