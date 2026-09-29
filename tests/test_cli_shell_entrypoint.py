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


def test_shell_verify_chain_sidebar_screen_with_keys_present(tmp_path):
    """Verify chain (menu item 4) is now a sidebar+detail screen, one row
    per custody event -- navigable with up/down, not a static text dump."""
    from vcoc.ecdsa_signer import generate_keypair, save_keypair
    from vcoc import db
    from vcoc.hash_chain import HashChain

    signing_key, _ = generate_keypair()
    save_keypair(signing_key, tmp_path / "private_key.pem", tmp_path / "public_key.pem")

    chain = HashChain()
    chain.add_event(evidence_id="EV001", actor="J. Doe", action="collected", signing_key=signing_key)
    chain.add_event(evidence_id="EV002", actor="A. Smith", action="reviewed", signing_key=signing_key)
    chain.save_db(db.connect(tmp_path / "vcoc.db"))

    keys = (
        "4"  # Verify chain
        + "\r"  # ensure_keys: accept default private_key.pem path (exists on disk)
        + "\r"  # ensure_keys: accept default public_key.pem path (exists on disk)
        + "\x1b[B"  # down to second event row
        + "\x12"  # Ctrl-R refresh
        + "q"  # back to menu
        + "q"  # quit shell
    )
    run_with_keys(keys, tmp_path)


def test_shell_merkle_root_then_quit(tmp_path):
    run_with_keys("5" + "x" + "q", tmp_path)


def test_shell_add_evidence_then_check(tmp_path):
    evidence_file = tmp_path / "sample.txt"
    evidence_file.write_text("synthetic evidence bytes", encoding="utf-8")

    keys = (
        "1"  # Add evidence
        + str(evidence_file) + "\r"  # file path
        + "EV001\r"  # evidence id
        + "x"  # dismiss output screen
        + "2"  # Check evidence integrity
        + "EV001\r"  # search screen: type id, Enter selects
        + "x"  # dismiss output screen
        + "q"  # quit
    )
    run_with_keys(keys, tmp_path)

    from vcoc import db

    assert "EV001" in db.load_evidence_index(db.connect(tmp_path / "vcoc.db"))


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


def test_shell_add_evidence_folder_registers_all_members(tmp_path):
    folder = tmp_path / "batchdir"
    folder.mkdir()
    (folder / "a.txt").write_text("aaa", encoding="utf-8")
    (folder / "b.txt").write_text("bbb", encoding="utf-8")

    keys = (
        "1"  # Add evidence
        + str(folder) + "\r"  # folder path
        + "BATCH1\r"  # folder/batch id
        + "n"  # decline batch custody-event logging
        + "x"  # dismiss output screen
        + "q"  # quit
    )
    run_with_keys(keys, tmp_path)

    from vcoc import db

    conn = db.connect(tmp_path / "vcoc.db")
    assert {"BATCH1/a.txt", "BATCH1/b.txt"} <= set(db.load_evidence_index(conn))
    assert "BATCH1" in db.load_folder_index(conn)


def test_shell_log_event_no_keys_cancels_cleanly(tmp_path):
    """Log custody event still gates on ensure_keys first, same as before
    Task 18 -- Ctrl-C at the key-path prompt cancels without crashing or
    reaching the (now multi-select) evidence picker."""
    run_with_keys("3" + "\x03" + "q", tmp_path)
    assert not (tmp_path / "vcoc.db").exists()


def test_shell_log_event_multi_select_with_keys_present(tmp_path):
    import sys as _sys

    _sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
    from vcoc.ecdsa_signer import generate_keypair, save_keypair

    signing_key, _ = generate_keypair()
    save_keypair(signing_key, tmp_path / "private_key.pem", tmp_path / "public_key.pem")

    ev1 = tmp_path / "a.txt"
    ev1.write_text("aaa", encoding="utf-8")
    ev2 = tmp_path / "b.txt"
    ev2.write_text("bbb", encoding="utf-8")

    keys = (
        "1" + str(ev1) + "\r" + "EV001\r" + "x"
        + "1" + str(ev2) + "\r" + "EV002\r" + "x"
        + "3"  # Log custody event
        + "\r"  # ensure_keys: accept default private_key.pem path (exists on disk)
        + "\r"  # ensure_keys: accept default public_key.pem path (exists on disk)
        + " "  # toggle EV001 (row 0, already highlighted)
        + "\x1b[B"  # down to EV002
        + " "  # toggle EV002
        + "\r"  # confirm multi-select
        + "J. Doe\r"  # actor
        + "seized\r"  # action
        + "\r"  # case number: blank, accept
        + "\r"  # tag: blank, accept
        + "\r"  # notes: blank, accept
        + "x"  # dismiss output
        + "q"
    )
    run_with_keys(keys, tmp_path)

    from vcoc import db
    from vcoc.hash_chain import HashChain

    db_path = tmp_path / "vcoc.db"
    assert db_path.exists()
    entries = HashChain.load_db(db.connect(db_path)).entries
    assert len(entries) == 1
    assert entries[0].evidence_ids == ["EV001", "EV002"]


def test_shell_verification_screen_after_add_evidence(tmp_path):
    evidence_file = tmp_path / "sample.txt"
    evidence_file.write_text("synthetic evidence bytes", encoding="utf-8")

    keys = (
        "1"  # Add evidence
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
