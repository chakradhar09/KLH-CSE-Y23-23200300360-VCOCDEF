"""Pure-function tests for vcoc.interactive.verification_screen's chain check.

Reproduces the reported bug: the Verification screen's Chain tab hardcodes
DEFAULT_PUBLIC_KEY (public_key.pem in cwd) instead of honoring the shell's
configured key path (shell_config["public_key"], set via Task 8's
ensure_keys gate) -- so a keypair generated/located anywhere other than the
cwd default is invisible to chain verification even though Log custody
event / Verify chain (which do use shell_config) work fine.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import argparse
import hashlib

import pytest

from vcoc import db
from vcoc.ecdsa_signer import generate_keypair, save_keypair
from vcoc.hash_chain import HashChain
from vcoc.interactive import menu, verification_screen

import cli as cli_module


def _write_signed_log(log_path: Path, signing_key) -> None:
    chain = HashChain()
    chain.add_event(evidence_id="EV001", actor="tester", action="collected", signing_key=signing_key)
    chain.save_db(db.connect(log_path))


def test_chain_check_recognizes_keypair_at_configured_non_default_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    # Keypair lives OUTSIDE the cwd default (public_key.pem), e.g. in a
    # "keys" subdirectory the user pointed the shell at via ensure_keys.
    keydir = tmp_path / "keys"
    keydir.mkdir()
    private_path = keydir / "my_private.pem"
    public_path = keydir / "my_public.pem"
    signing_key, verifying_key = generate_keypair()
    save_keypair(signing_key, private_path, public_path)

    log_path = tmp_path / "vcoc.db"
    _write_signed_log(log_path, signing_key)

    shell_config = {"private_key": str(private_path), "public_key": str(public_path)}

    rows, details = verification_screen._run_chain_check(shell_config)

    assert rows == ["OK  #0 collected on EV001"]
    assert "OK" in "\n".join(details[0])


def test_chain_check_falls_back_to_default_when_no_shell_config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    signing_key, verifying_key = generate_keypair()
    save_keypair(signing_key, "private_key.pem", "public_key.pem")

    log_path = tmp_path / "vcoc.db"
    _write_signed_log(log_path, signing_key)

    rows, details = verification_screen._run_chain_check({})

    assert rows == ["OK  #0 collected on EV001"]


def test_chain_check_detail_lists_all_evidence_ids_for_multi_evidence_entry(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    signing_key, verifying_key = generate_keypair()
    save_keypair(signing_key, "private_key.pem", "public_key.pem")

    chain = HashChain()
    chain.add_event(
        evidence_ids=["EV001", "EV002"],
        actor="J. Doe",
        action="seized",
        signing_key=signing_key,
        case_number="C-001",
        tag="disk+memory",
    )
    chain.save_db(db.connect(tmp_path / "vcoc.db"))

    rows, details = verification_screen._run_chain_check({})

    assert len(rows) == 1
    joined = "\n".join(details[0])
    assert "EV001" in joined
    assert "EV002" in joined
    assert "C-001" in joined
    assert "disk+memory" in joined


def test_chain_check_detail_shows_legacy_entry_without_clutter(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    signing_key, _ = generate_keypair()
    save_keypair(signing_key, "private_key.pem", "public_key.pem")

    log_path = tmp_path / "vcoc.db"
    _write_signed_log(log_path, signing_key)

    rows, details = verification_screen._run_chain_check({})

    joined = "\n".join(details[0])
    assert "EV001" in joined
    assert "case_number" not in joined.lower() or "None" not in joined


def test_chain_check_lists_one_row_per_custody_event(tmp_path, monkeypatch):
    """Task 27: Chain tab sidebar is one row per event, not one aggregate
    row -- so the user can navigate between individual log events."""
    monkeypatch.chdir(tmp_path)
    signing_key, _ = generate_keypair()
    save_keypair(signing_key, "private_key.pem", "public_key.pem")

    chain = HashChain()
    chain.add_event(evidence_id="EV001", actor="J. Doe", action="collected", signing_key=signing_key)
    chain.add_event(evidence_id="EV002", actor="A. Smith", action="reviewed", signing_key=signing_key)
    chain.add_event(evidence_id="EV003", actor="A. Smith", action="transferred", signing_key=signing_key)
    chain.save_db(db.connect(tmp_path / "vcoc.db"))

    rows, details = verification_screen._run_chain_check({})

    assert len(rows) == 3
    assert len(details) == 3
    assert "collected" in rows[0]
    assert "EV001" in rows[0]
    assert "reviewed" in rows[1]
    assert "transferred" in rows[2]
    for row in rows:
        assert row.startswith("OK")


def test_chain_check_marks_tampered_entry_row_distinctly(tmp_path, monkeypatch):
    """A tampered entry's row is visually distinguishable, matching the
    Evidence tab's existing OK/!! convention."""
    monkeypatch.chdir(tmp_path)
    signing_key, _ = generate_keypair()
    save_keypair(signing_key, "private_key.pem", "public_key.pem")

    chain = HashChain()
    chain.add_event(evidence_id="EV001", actor="J. Doe", action="collected", signing_key=signing_key)
    chain.add_event(evidence_id="EV002", actor="A. Smith", action="reviewed", signing_key=signing_key)
    chain.entries[1].actor = "Mallory"
    chain.save_db(db.connect(tmp_path / "vcoc.db"))

    rows, details = verification_screen._run_chain_check({})

    assert rows[0].startswith("OK")
    assert not rows[1].startswith("OK")
    assert "TAMPER" in rows[1] or "!!" in rows[1]
    assert "TAMPER" in "\n".join(details[1]) or "tamper" in "\n".join(details[1]).lower()


def test_chain_check_detail_shows_both_hashes_and_signature_per_event(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    signing_key, _ = generate_keypair()
    save_keypair(signing_key, "private_key.pem", "public_key.pem")

    chain = HashChain()
    e0 = chain.add_event(evidence_id="EV001", actor="J. Doe", action="collected", signing_key=signing_key)
    chain.save_db(db.connect(tmp_path / "vcoc.db"))

    rows, details = verification_screen._run_chain_check({})

    joined = "\n".join(details[0])
    assert e0.entry_hash in joined
    assert e0.prev_hash in joined
    assert e0.signature[:16] in joined


def test_chain_check_missing_log_file_preserved(tmp_path, monkeypatch):
    """Task 27: the pre-existing empty-state message for a log file that
    doesn't exist at all is preserved, not replaced by zero rows."""
    monkeypatch.chdir(tmp_path)

    rows, details = verification_screen._run_chain_check({})

    assert rows == ["No custody log found"]


def test_chain_check_empty_log_array_has_explanatory_row(tmp_path, monkeypatch):
    """An existing but empty vcoc.db (distinct from a missing
    file) gets its own explanatory row, not a crash or silent zero rows."""
    monkeypatch.chdir(tmp_path)
    signing_key, _ = generate_keypair()
    save_keypair(signing_key, "private_key.pem", "public_key.pem")
    db.connect(tmp_path / "vcoc.db").close()  # schema only, no entries

    rows, details = verification_screen._run_chain_check({})

    assert len(rows) == 1
    assert "no custody events" in rows[0].lower()


def test_chain_check_reports_missing_key_at_configured_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    log_path = tmp_path / "vcoc.db"
    signing_key, _ = generate_keypair()
    _write_signed_log(log_path, signing_key)

    shell_config = {"public_key": str(tmp_path / "nonexistent.pem")}
    rows, details = verification_screen._run_chain_check(shell_config)

    assert rows == ["No public key found"]


# --- Reported bugs: "Merkle root" section throws an error, and the
# Verification screen's "Evidence" tab is broken -- both introduced by
# Phase 5 (folder batch registration / nested Merkle proofs) changing
# cmd_merkle_root's and verify_evidence_index's signatures without
# updating menu.py's _defaults()/verification_screen.py to match. ---


def test_menu_action_merkle_root_does_not_crash_on_missing_folder_index_attr(tmp_path, monkeypatch):
    """Bug repro: action_merkle_root -> cmd_merkle_root now reads
    args.folder_index, but menu._defaults() never sets it, so every call
    fails with AttributeError (surfaced in-shell as 'Error: ...')."""
    monkeypatch.chdir(tmp_path)
    f = tmp_path / "solo.bin"
    f.write_bytes(b"solo-content")
    cli_module.cmd_add_evidence(
        argparse.Namespace(
            file=str(f),
            evidence_id="EV001",
            db=cli_module.DEFAULT_DB,
            private_key=None,
            actor=None,
        )
    )

    ns = menu._defaults()
    output = menu._run_cmd(cli_module.cmd_merkle_root, ns)

    assert "Error" not in output
    assert "Merkle root" in output


def test_verification_screen_evidence_tab_handles_folder_batch_records(tmp_path, monkeypatch):
    """Bug repro: verify_evidence_index groups by folder_id and looks up
    folder_index[gid]["root"] for any grouped id not in evidence_index --
    but _run_evidence_check() never loads/passes the folders table, so a
    folder-registered evidence set raises KeyError instead of rendering."""
    monkeypatch.chdir(tmp_path)
    folder = tmp_path / "batchdir"
    folder.mkdir()
    (folder / "a.txt").write_bytes(b"a-content")
    (folder / "b.txt").write_bytes(b"b-content")
    cli_module.cmd_add_evidence(
        argparse.Namespace(
            file=str(folder),
            evidence_id="BATCH1",
            db=cli_module.DEFAULT_DB,
            private_key=None,
            actor=None,
        )
    )

    rows, details = verification_screen._run_evidence_check()

    assert not any("Error" in r or "Traceback" in r for r in rows)
    assert any("BATCH1" in r for r in rows)


def test_verification_screen_merkle_tab_verifies_nested_proof_format(tmp_path, monkeypatch):
    """Bug repro: _run_merkle_check()'s proof.json check calls
    verifier.verify_merkle_proof(proof_data["proof"], ...) expecting a flat
    list of {sibling, is_left} steps, but cmd_merkle_proof now writes the
    nested {"local_proof": ..., "subtree_root": ..., "folder_proof": ...}
    dict -- iterating that dict as if it were a list of steps and indexing
    step["is_left"] on a string key raises TypeError."""
    monkeypatch.chdir(tmp_path)
    f = tmp_path / "solo.bin"
    f.write_bytes(b"solo-content")
    cli_module.cmd_add_evidence(
        argparse.Namespace(
            file=str(f),
            evidence_id="EV001",
            db=cli_module.DEFAULT_DB,
            private_key=None,
            actor=None,
        )
    )
    cli_module.cmd_merkle_proof(
        argparse.Namespace(
            evidence_id="EV001",
            db=cli_module.DEFAULT_DB,
            out="proof.json",
        )
    )

    rows, details = verification_screen._run_merkle_check()

    assert not any("Error" in r or "Traceback" in r for r in rows)
    assert any(r.startswith("OK") for r in rows if "proof.json" in r)


def test_run_verify_chain_screen_uses_shared_sidebar_detail_runner(tmp_path, monkeypatch):
    """The standalone 'Verify chain' screen (menu item 4) reuses the same
    sidebar+detail rendering as the Verification screen's Chain tab, via
    _run_chain_check -- just as its own dedicated entry point, no tab bar."""
    monkeypatch.chdir(tmp_path)
    signing_key, _ = generate_keypair()
    save_keypair(signing_key, "private_key.pem", "public_key.pem")

    chain = HashChain()
    chain.add_event(evidence_id="EV001", actor="J. Doe", action="collected", signing_key=signing_key)
    chain.add_event(evidence_id="EV002", actor="A. Smith", action="reviewed", signing_key=signing_key)
    chain.save_db(db.connect(tmp_path / "vcoc.db"))

    captured = {}

    def fake_runner(title, load_rows, **kwargs):
        captured["title"] = title
        captured["rows"], captured["details"] = load_rows()

    monkeypatch.setattr(verification_screen, "_run_sidebar_detail_app", fake_runner)

    verification_screen.run_verify_chain_screen({})

    assert captured["title"] == "Verify Chain"
    assert len(captured["rows"]) == 2
    assert "EV001" in captured["rows"][0]
    assert "EV002" in captured["rows"][1]


def test_action_verify_chain_opens_sidebar_screen_not_static_output(tmp_path, monkeypatch):
    """menu.action_verify_chain (menu item 4) opens the sidebar screen
    instead of dumping static text via forms.show_output."""
    monkeypatch.chdir(tmp_path)
    signing_key, _ = generate_keypair()
    save_keypair(signing_key, "private_key.pem", "public_key.pem")

    chain = HashChain()
    chain.add_event(evidence_id="EV001", actor="J. Doe", action="collected", signing_key=signing_key)
    chain.save_db(db.connect(tmp_path / "vcoc.db"))

    called = {}

    def fake_screen(shell_config):
        called["shell_config"] = shell_config

    def fail_show_output(title, text):
        raise AssertionError("action_verify_chain must not use forms.show_output")

    monkeypatch.setattr(menu, "run_verify_chain_screen", fake_screen)
    monkeypatch.setattr(menu.forms, "show_output", fail_show_output)

    shell_config = {"private_key": "private_key.pem", "public_key": "public_key.pem"}
    menu.action_verify_chain(shell_config)

    assert called["shell_config"] == shell_config


# --- Task 1c: the Evidence tab's re-hash must not freeze the shell ---------------------------------
# Before: load() ran the whole re-hash synchronously inside a key handler, on prompt_toolkit's event
# loop, so a multi-GB re-hash froze redraws and Esc. Now the slow tab loads on a background thread.


def test_evidence_check_forwards_progress_and_returns_same_rows(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    f = tmp_path / "a.bin"
    f.write_bytes(b"x" * 100)
    cli_module.cmd_add_evidence(
        argparse.Namespace(file=str(f), evidence_id="EV001", db=cli_module.DEFAULT_DB, private_key=None, actor=None)
    )
    calls = []

    with_progress = verification_screen._run_evidence_check(progress=lambda *a: calls.append(a))

    assert with_progress == verification_screen._run_evidence_check()
    assert calls[0] == (1, 1, "EV001", 0, 100)
    assert calls[-1][3] == 100


def test_background_load_publishes_result_and_shows_progress_status():
    import threading

    done = threading.Event()
    seen = {}

    def on_result(result):
        seen["published"] = result
        done.set()

    bg = verification_screen._BackgroundLoad(on_change=lambda: None, on_result=on_result, min_interval=0)

    def load(progress):
        progress(1, 2, "EV001", 5, 10)
        seen["status"] = bg.status
        return (["row"], [["detail"]])

    bg.start(load)

    assert done.wait(5)
    assert "1/2" in seen["status"] and "EV001" in seen["status"] and "50%" in seen["status"]
    assert seen["published"] == (["row"], [["detail"]])
    assert bg.loading is False


def test_background_load_cancel_stops_worker_at_next_progress_call_and_publishes_nothing():
    import threading

    gate, finished = threading.Event(), threading.Event()
    published, outcome = [], {}
    bg = verification_screen._BackgroundLoad(on_change=lambda: None, on_result=published.append, min_interval=0)

    def load(progress):
        try:
            progress(1, 1, "EV001", 0, 10)
            gate.wait(5)
            progress(1, 1, "EV001", 5, 10)  # must raise once cancelled
            outcome["ran_past_cancel"] = True
            return (["x"], [["x"]])
        finally:
            finished.set()

    bg.start(load)
    bg.cancel()
    gate.set()

    assert finished.wait(5)
    assert "ran_past_cancel" not in outcome
    assert published == []
    assert bg.loading is False


def test_background_load_superseded_load_never_overwrites_newer_result():
    import threading

    gate, slow_finished, got_b = threading.Event(), threading.Event(), threading.Event()
    published = []

    def on_result(result):
        published.append(result)
        got_b.set()

    bg = verification_screen._BackgroundLoad(on_change=lambda: None, on_result=on_result, min_interval=0)

    def slow(progress):
        try:
            gate.wait(5)
            return (["A"], [["A"]])  # finishes AFTER B; must be discarded
        finally:
            slow_finished.set()

    bg.start(slow)
    bg.start(lambda progress: (["B"], [["B"]]))
    assert got_b.wait(5)
    gate.set()
    assert slow_finished.wait(5)

    assert published == [(["B"], [["B"]])]


def test_background_load_reports_an_exception_as_an_error_row():
    import threading

    done = threading.Event()
    published = []

    def on_result(result):
        published.append(result)
        done.set()

    bg = verification_screen._BackgroundLoad(on_change=lambda: None, on_result=on_result, min_interval=0)

    def boom(progress):
        raise ValueError("boom")

    bg.start(boom)

    assert done.wait(5)
    assert published == [(["Error: boom"], [["Error: boom"]])]
    assert bg.loading is False


def test_cancelled_is_not_an_oserror_so_it_cannot_be_swallowed_as_an_io_error():
    assert issubclass(verification_screen._Cancelled, Exception)
    assert not issubclass(verification_screen._Cancelled, OSError)  # InterruptedError IS an OSError


def test_sidebar_app_stays_responsive_during_slow_load_and_quit_cancels_it():
    """Real prompt_toolkit app, headless. The slow load blocks on a gate; 'q' is only sent once the worker
    is inside it, so the app can exit only if the event loop is NOT blocked by the load (the old behaviour)."""
    import threading

    from prompt_toolkit.application import create_app_session
    from prompt_toolkit.input import create_pipe_input
    from prompt_toolkit.output import DummyOutput

    at_gate, gate, finished = threading.Event(), threading.Event(), threading.Event()
    outcome = {}

    def slow(progress):
        try:
            progress(1, 1, "EV001", 0, 10)
            at_gate.set()
            gate.wait(5)
            progress(1, 1, "EV001", 5, 10)  # raises _Cancelled: the screen was closed
            outcome["ran_past_cancel"] = True
            return (["x"], [["x"]])
        finally:
            finished.set()

    with create_pipe_input() as pipe_input:
        sender = threading.Thread(target=lambda: at_gate.wait(5) and pipe_input.send_text("q"), daemon=True)
        sender.start()
        with create_app_session(input=pipe_input, output=DummyOutput()):
            verification_screen._run_sidebar_detail_app(
                "T", lambda: (["fast"], [["fast"]]), slow_load=(lambda: True, slow)
            )

    assert not finished.is_set()  # the app returned while the load was still blocked
    gate.set()
    assert finished.wait(5)
    assert "ran_past_cancel" not in outcome


# --- Task 1d: the Evidence re-hash must survive tab switches (one hash, not one per visit) -----------
# Before: every tab change cancelled the running hash and restarted it from file 1. The scripted keys
# 1..5 below drive the real Verification screen headlessly; every assertion is a count taken after the
# screen has closed and its worker threads have finished, so nothing depends on timing.


def _drive_verification_screen(monkeypatch, tmp_path, keys, followup=None, after_exit=None):
    import threading

    from prompt_toolkit.application import create_app_session
    from prompt_toolkit.input import create_pipe_input
    from prompt_toolkit.output import DummyOutput

    monkeypatch.chdir(tmp_path)
    with create_pipe_input() as pipe_input:
        pipe_input.send_text(keys)
        if followup is not None:
            threading.Thread(target=lambda: followup(pipe_input), daemon=True).start()
        with create_app_session(input=pipe_input, output=DummyOutput()):
            verification_screen.run_verification_screen({})
    if after_exit is not None:
        after_exit()  # runs once the screen is CLOSED (and has cancelled its loaders), before waiting for workers
    for t in threading.enumerate():
        if t.name == "vcoc-bgload":
            t.join(5)


def _fake_evidence_check(monkeypatch, gate=None, done=None, at_gate=None):
    """Stands in for the real re-hash: counts starts, reports progress, and records whether it was cancelled."""
    outcome = {"starts": 0, "finished_normally": False}

    def fake(progress=None, db_path=None, shell_config=None):
        outcome["starts"] += 1
        try:
            progress(1, 1, "EV001", 0, 10)  # raises _Cancelled if this load was superseded or cancelled
            if at_gate is not None:
                at_gate.set()
            if gate is not None:
                gate.wait(5)
            progress(1, 1, "EV001", 5, 10)  # ...and again after the gate: cancelled while blocked also raises here
            outcome["finished_normally"] = True
            return (["EV001 done"], [["detail"]])
        finally:
            if done is not None:
                done.set()

    monkeypatch.setattr(verification_screen, "_run_evidence_check", fake)
    return outcome


def test_visiting_the_evidence_tab_three_times_starts_the_rehash_only_once(tmp_path, monkeypatch):
    outcome = _fake_evidence_check(monkeypatch)

    _drive_verification_screen(monkeypatch, tmp_path, "2" "1" "2" "1" "2" "q")  # Evidence, Chain, Evidence, ...

    assert outcome["starts"] == 1


def test_rehash_keeps_running_while_another_tab_is_shown(tmp_path, monkeypatch):
    import threading

    gate, done, on_chain_tab = threading.Event(), threading.Event(), threading.Event()
    chain_calls = []
    real_chain = verification_screen._run_chain_check

    def counting_chain(shell_config=None):
        chain_calls.append(1)
        if len(chain_calls) >= 2:  # 1st call = initial load; 2nd = the visit to the Chain tab after Evidence
            on_chain_tab.set()
        return real_chain(shell_config)

    monkeypatch.setattr(verification_screen, "_run_chain_check", counting_chain)
    outcome = _fake_evidence_check(monkeypatch, gate=gate, done=done)

    def followup(pipe_input):
        # No asserts in here: a failing wait must still fall through to "q", or the screen would never close.
        on_chain_tab.wait(5)  # the user has switched away from Evidence...
        gate.set()  # ...and the hash carries on: it must NOT have been cancelled
        done.wait(5)
        pipe_input.send_text("q")

    _drive_verification_screen(monkeypatch, tmp_path, "2" "1", followup=followup)

    assert on_chain_tab.is_set() and done.is_set()
    assert outcome["starts"] == 1
    assert outcome["finished_normally"] is True


def test_finished_evidence_result_is_not_recomputed_when_returning_to_the_tab(tmp_path, monkeypatch):
    import threading

    done = threading.Event()
    outcome = _fake_evidence_check(monkeypatch, done=done)

    def followup(pipe_input):
        done.wait(5)  # the check has finished
        pipe_input.send_text("1" "2" "q")  # leave the tab and come back, then close

    _drive_verification_screen(monkeypatch, tmp_path, "2", followup=followup)

    assert done.is_set()
    assert outcome["starts"] == 1
    assert outcome["finished_normally"] is True


def test_ctrl_r_on_the_evidence_tab_restarts_the_rehash(tmp_path, monkeypatch):
    outcome = _fake_evidence_check(monkeypatch)

    _drive_verification_screen(monkeypatch, tmp_path, "2" "\x12" "q")  # Evidence, Ctrl-R

    assert outcome["starts"] == 2


def test_leaving_the_screen_cancels_a_running_evidence_rehash(tmp_path, monkeypatch):
    import threading

    gate, done, at_gate = threading.Event(), threading.Event(), threading.Event()
    outcome = _fake_evidence_check(monkeypatch, gate=gate, done=done, at_gate=at_gate)

    def followup(pipe_input):
        at_gate.wait(5)  # the hash is now running and blocked...
        pipe_input.send_text("q")  # ...and the user leaves the screen

    # The gate opens only AFTER the screen has closed, so the next progress call must see the cancellation.
    _drive_verification_screen(monkeypatch, tmp_path, "2", followup=followup, after_exit=gate.set)

    assert at_gate.is_set() and done.wait(5)
    assert outcome["finished_normally"] is False  # the screen's cancel stopped it at the next progress call


# --- Task 1e: a background load must never resolve a relative "vcoc.db" after the cwd has moved --------
# Found 2026-09-30: worker threads from the shell tests outlived their test; the test restored the cwd
# to the repo root and the thread then opened the *real* ./vcoc.db there.


def _register_evidence(directory: Path, evidence_id: str = "EV001") -> Path:
    f = directory / "a.bin"
    f.write_bytes(b"x" * 10)
    cli_module.cmd_add_evidence(
        argparse.Namespace(
            file=str(f), evidence_id=evidence_id, db=str(directory / "vcoc.db"), private_key=None, actor=None
        )
    )
    return directory / "vcoc.db"


def test_evidence_check_reads_the_db_it_was_given_even_after_the_cwd_changes(tmp_path, monkeypatch):
    home, elsewhere = tmp_path / "home", tmp_path / "elsewhere"
    home.mkdir()
    elsewhere.mkdir()
    db_path = _register_evidence(home)
    monkeypatch.chdir(elsewhere)  # the cwd moved after the load was requested

    rows, _ = verification_screen._run_evidence_check(db_path=str(db_path))

    assert any("EV001" in r for r in rows)


def test_verification_screen_binds_the_db_path_when_it_opens_not_when_the_thread_runs(tmp_path, monkeypatch):
    home, elsewhere = tmp_path / "home", tmp_path / "elsewhere"
    home.mkdir()
    elsewhere.mkdir()
    _register_evidence(home)
    monkeypatch.chdir(home)
    captured = {}
    monkeypatch.setattr(
        verification_screen, "_run_sidebar_detail_app", lambda title, load_rows, **kw: captured.update(kw)
    )

    verification_screen.run_verification_screen({})  # the screen opens in `home`
    monkeypatch.chdir(elsewhere)  # ...the cwd moves before the worker thread runs
    rows, _ = captured["slow_load"][1]["Evidence"](lambda *a: None)

    assert any("EV001" in r for r in rows)
    assert rows != ["No evidence registered"]
    assert not (elsewhere / "vcoc.db").exists()  # nothing was created or opened in the new cwd


def test_background_load_thread_is_named_so_tests_can_wait_for_it():
    import threading

    gate, running = threading.Event(), threading.Event()
    bg = verification_screen._BackgroundLoad(on_change=lambda: None, min_interval=0)

    def load(progress):
        running.set()
        gate.wait(5)
        return (["x"], [["x"]])

    bg.start(load)
    assert running.wait(5)
    try:
        assert any(t.name == "vcoc-bgload" for t in threading.enumerate())
    finally:
        gate.set()
        for t in threading.enumerate():
            if t.name == "vcoc-bgload":
                t.join(5)


def test_verification_screen_marks_only_the_evidence_tab_as_slow(tmp_path, monkeypatch):
    from prompt_toolkit.key_binding import KeyBindings

    monkeypatch.chdir(tmp_path)
    captured = {}
    monkeypatch.setattr(
        verification_screen, "_run_sidebar_detail_app", lambda title, load_rows, **kw: captured.update(kw)
    )

    verification_screen.run_verification_screen({})

    slow_key, load_fns = captured["slow_load"]
    assert slow_key() is None  # Chain tab is the initial tab: not a slow tab
    kb = KeyBindings()
    captured["extra_keybindings"](kb, lambda: None)
    kb.get_bindings_for_keys(("2",))[0].handler(None)  # jump to the Evidence tab
    assert slow_key() == "Evidence"  # Task 1d: the key identifies WHICH slow tab is active
    kb.get_bindings_for_keys(("3",))[0].handler(None)  # Task 6d: the Merkle tab is a slow tab too
    assert slow_key() == "Merkle"
    kb.get_bindings_for_keys(("1",))[0].handler(None)
    assert slow_key() is None
    assert set(load_fns) == {"Evidence", "Merkle"}
    rows, _ = load_fns["Evidence"](lambda *a: None)
    assert rows == ["No evidence registered"]


# --- Task 6b: the sidebar renders only the visible window (was: one string of EVERY row per redraw) ------
# Measured on the real 92,879-row Evidence tab: 143 ms per redraw. Same fix as the search screens (Task 6).

PGDN, PGUP, HOME, END, DOWN = "\x1b[6~", "\x1b[5~", "\x1b[H", "\x1b[F", "\x1b[B"


def _sidebar_height() -> int:
    from prompt_toolkit.application import create_app_session
    from prompt_toolkit.input import create_pipe_input
    from prompt_toolkit.output import DummyOutput

    from vcoc.interactive import evidence_search

    with create_pipe_input() as pipe_input, create_app_session(input=pipe_input, output=DummyOutput()):
        return evidence_search._visible_height()


def _drive_sidebar(monkeypatch, n_rows: int, keys: str):
    """Run the real sidebar app on n_rows rows; return one (selected, rendered_lines, height) per redraw."""
    from prompt_toolkit.application import create_app_session
    from prompt_toolkit.input import create_pipe_input
    from prompt_toolkit.output import DummyOutput

    seen = []
    real = verification_screen._sidebar_text

    def spy(rows, selected, top, height):
        text = real(rows, selected, top, height)
        seen.append((selected, len(text.splitlines()), height))
        return text

    monkeypatch.setattr(verification_screen, "_sidebar_text", spy)
    rows = [f"row {i}" for i in range(n_rows)]
    details = [[f"detail {i}"] for i in range(n_rows)]
    with create_pipe_input() as pipe_input:
        pipe_input.send_text(keys)
        with create_app_session(input=pipe_input, output=DummyOutput()):
            verification_screen._run_sidebar_detail_app("T", lambda: (rows, details))
    return seen


def test_sidebar_text_small_list_is_rendered_exactly_as_before():
    from vcoc.interactive.verification_screen import _sidebar_text

    assert _sidebar_text(["a", "b", "c"], selected=1, top=[0], height=31) == "  a\n▸ b\n  c"
    assert _sidebar_text([], selected=0, top=[0], height=31) == "  (nothing to show)"


def test_sidebar_text_windows_a_long_list_and_reports_position():
    from vcoc.interactive.verification_screen import _sidebar_text

    rows = [f"row {i}" for i in range(20_000)]
    top = [0]

    text = _sidebar_text(rows, selected=0, top=top, height=30)
    assert len(text.splitlines()) == 31  # 30 rows + the position line, NOT 20,000
    assert text.splitlines()[0] == "▸ row 0"
    assert text.splitlines()[-1].strip() == "1-30 of 20,000"

    text = _sidebar_text(rows, selected=19_999, top=top, height=30)
    assert text.splitlines()[-2] == "▸ row 19999"
    assert text.splitlines()[-1].strip() == "19,971-20,000 of 20,000"


def test_sidebar_app_renders_only_a_window_of_a_20k_row_list(monkeypatch):
    seen = _drive_sidebar(monkeypatch, 20_000, DOWN * 3 + "q")

    assert seen
    assert all(lines <= height + 1 for _, lines, height in seen)  # before: 20,000 lines per redraw


def test_sidebar_jump_keys_reach_any_row(monkeypatch):
    h = _sidebar_height()

    assert _drive_sidebar(monkeypatch, 20_000, DOWN * 3 + "q")[-1][0] == 3
    assert _drive_sidebar(monkeypatch, 20_000, PGDN + "q")[-1][0] == h
    assert _drive_sidebar(monkeypatch, 20_000, PGDN + PGDN + "q")[-1][0] == 2 * h
    assert _drive_sidebar(monkeypatch, 20_000, END + "q")[-1][0] == 19_999
    assert _drive_sidebar(monkeypatch, 20_000, END + PGUP + "q")[-1][0] == 19_999 - h
    assert _drive_sidebar(monkeypatch, 20_000, END + HOME + "q")[-1][0] == 0
    assert _drive_sidebar(monkeypatch, 5, PGDN + PGDN + "q")[-1][0] == 4  # clamps on a short list


# --- Task 6d: the Merkle tab must not block the screen either (it loads the whole index synchronously) ---


def test_merkle_tab_loads_in_the_background_and_the_screen_stays_responsive(tmp_path, monkeypatch):
    import threading

    gate, done, at_gate = threading.Event(), threading.Event(), threading.Event()
    state = {"starts": 0}

    def fake_merkle(db_path=None, proof_path=None):
        state["starts"] += 1
        at_gate.set()
        try:
            gate.wait(2)  # the old code ran this ON the event loop, freezing the screen for the whole wait
            return (["Root over 1 leaf(ves)/folder(s)"], [["root"]])
        finally:
            done.set()

    monkeypatch.setattr(verification_screen, "_run_merkle_check", fake_merkle)

    def followup(pipe_input):
        at_gate.wait(5)
        pipe_input.send_text("q")  # the user leaves while the Merkle tab is still loading

    def after_exit():
        state["finished_at_exit"] = done.is_set()  # was the screen blocked until the load finished?
        gate.set()

    _drive_verification_screen(monkeypatch, tmp_path, "3", followup=followup, after_exit=after_exit)

    assert state["starts"] == 1
    assert state["finished_at_exit"] is False  # the screen closed while the Merkle load was still running


def test_merkle_tab_keeps_its_result_across_tab_switches(tmp_path, monkeypatch):
    import threading

    done = threading.Event()
    state = {"starts": 0}

    def fake_merkle(db_path=None, proof_path=None):
        state["starts"] += 1
        done.set()
        return (["Root over 1 leaf(ves)/folder(s)"], [["root"]])

    monkeypatch.setattr(verification_screen, "_run_merkle_check", fake_merkle)

    def followup(pipe_input):
        done.wait(5)
        pipe_input.send_text("1" "3" "1" "3" "q")  # away and back twice

    _drive_verification_screen(monkeypatch, tmp_path, "3", followup=followup)

    assert state["starts"] == 1


def test_merkle_check_reads_the_db_it_was_given_even_after_the_cwd_changes(tmp_path, monkeypatch):
    home, elsewhere = tmp_path / "home", tmp_path / "elsewhere"
    home.mkdir()
    elsewhere.mkdir()
    db_path = _register_evidence(home)
    monkeypatch.chdir(elsewhere)

    rows, _ = verification_screen._run_merkle_check(db_path=str(db_path), proof_path=str(elsewhere / "proof.json"))

    assert rows[0].startswith("Root over 1 leaf")


# --- Task M2: the Evidence/Merkle tabs read the database instead of holding every row on the heap ----------------


def _reference_evidence_check(db_path: str):
    """The pre-M2 rows/details, built the old way: whole index in memory + verifier.verify_evidence_index."""
    import verifier

    index = cli_module._load_evidence_index(db_path)
    entries = verification_screen._load_entries(db_path) or []
    folder_index = cli_module._load_folder_index(db_path)
    results, root = verifier.verify_evidence_index(index, entries, folder_index=folder_index)
    rows, details = [], []
    for r in results:
        rows.append(f"{'OK ' if r.ok else '!! '}{r.evidence_id}  ({r.original_filename})")
        details.append(
            [
                f"evidence_id: {r.evidence_id}",
                f"original_filename: {r.original_filename}",
                f"recorded sha256: {r.recorded_sha256}",
                f"source_path: {r.source_path or '(not recorded)'}",
                f"re-hash: {r.rehash_status}",
                f"custody log: {r.logged_status}",
            ]
        )
    rows.append("--  Merkle root over all evidence")
    details.append([f"Recomputed root over {len(results)} evidence file(s):", root])
    return rows, details


def _mixed_db(tmp_path, monkeypatch, members: int = 700):
    """A folder of `members` rows (mostly 'not found' / no path, two real: matching and tampered), a standalone file
    with a non-ASCII name, and two logged events."""
    import hashlib

    from vcoc.models import Evidence

    monkeypatch.chdir(tmp_path)
    good = tmp_path / "good.bin"
    good.write_bytes(b"good")
    bad = tmp_path / "bad.bin"
    bad.write_bytes(b"changed after registering")
    conn = db.connect(tmp_path / "vcoc.db")

    def ev(eid, path, sha, folder=None, name=None):
        return Evidence(eid, name or Path(eid).name, sha, 4, "2026-01-01T00:00:00Z", path, folder)

    members_ev = [
        ev(f"F1/m{i:04d}", str(tmp_path / f"missing{i}") if i % 7 else "", "ab" * 32, "F1") for i in range(members)
    ]
    members_ev.append(ev("F1/zgood.bin", str(good), hashlib.sha256(b"good").hexdigest(), "F1"))
    members_ev.append(ev("F1/zbad.bin", str(bad), "cd" * 32, "F1"))
    db.put_folder(conn, "F1", "ef" * 32, [m.evidence_id for m in members_ev], members_ev)
    db.put_evidence(conn, ev("SOLO", str(good), hashlib.sha256(b"good").hexdigest(), None, "Sölo ünï.bin"))
    signing_key, _ = generate_keypair()
    chain = HashChain()
    chain.add_event(evidence_id="SOLO", actor="a", action="collected", signing_key=signing_key)
    chain.add_event(evidence_ids=["F1/m0001", "F1/zgood.bin"], actor="a", action="seen", signing_key=signing_key)
    chain.save_db(conn)
    conn.close()
    return str(tmp_path / "vcoc.db")


def test_evidence_check_rows_and_details_equal_the_old_in_memory_result(tmp_path, monkeypatch):
    path = _mixed_db(tmp_path, monkeypatch)

    rows, details = verification_screen._run_evidence_check(db_path=path)
    want_rows, want_details = _reference_evidence_check(path)

    assert len(rows) == len(details) == len(want_rows) == 704  # 702 folder rows + SOLO + the Merkle root row
    assert list(rows) == want_rows
    assert [list(d) for d in details] == want_details


def test_evidence_check_supports_random_access_across_block_boundaries_and_negative_indexes(tmp_path, monkeypatch):
    path = _mixed_db(tmp_path, monkeypatch)
    rows, details = verification_screen._run_evidence_check(db_path=path)
    want_rows, want_details = _reference_evidence_check(path)

    for i in (0, 1, 255, 256, 257, 511, 512, 700, 703, -1, -2):
        assert rows[i] == want_rows[i], i
        assert list(details[i]) == want_details[i], i
    assert rows[-1].startswith("--  Merkle root")
    with pytest.raises(IndexError):
        rows[704]


def test_evidence_check_never_loads_the_index_or_folder_tables_into_dicts(tmp_path, monkeypatch):
    path = _mixed_db(tmp_path, monkeypatch, members=20)

    def boom(*a, **k):
        raise AssertionError("the whole index must not be loaded")

    monkeypatch.setattr(cli_module, "_load_evidence_index", boom)
    monkeypatch.setattr(cli_module, "_load_folder_index", boom)
    monkeypatch.setattr(db, "load_evidence_index", boom)
    monkeypatch.setattr(db, "load_folder_index", boom)

    rows, _ = verification_screen._run_evidence_check(db_path=path)

    assert len(rows) == 24


def test_evidence_check_result_can_be_read_from_another_thread_than_the_one_that_built_it(tmp_path, monkeypatch):
    import threading

    path = _mixed_db(tmp_path, monkeypatch, members=300)
    box = {}
    t = threading.Thread(target=lambda: box.update(res=verification_screen._run_evidence_check(db_path=path)))
    t.start()
    t.join()
    rows, details = box["res"]  # the worker thread built it; the UI thread reads it

    assert rows[300].startswith(("OK ", "!! "))
    assert len(list(details[299])) == 6


def test_evidence_check_with_no_database_or_no_rows_is_unchanged(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    missing = verification_screen._run_evidence_check(db_path=str(tmp_path / "nope.db"))
    db.connect(tmp_path / "empty.db").close()
    empty = verification_screen._run_evidence_check(db_path=str(tmp_path / "empty.db"))

    for rows, details in (missing, empty):
        assert list(rows) == ["No evidence registered"]
        assert [list(d) for d in details] == [["No evidence in the database."]]


@pytest.mark.parametrize(
    "jobs, small, large",
    [(1, 1000, 8000), (2, 2500, 9500)],  # both sizes on the SAME code path: the pool's fixed start-up cost is not per-row
)
def test_evidence_check_memory_per_row_is_tiny(tmp_path, monkeypatch, jobs, small, large):
    """Before: ~1.9 KB of Python objects per row (index dict, result objects, row string, 6-string details)."""
    import tracemalloc

    from vcoc.models import Evidence

    monkeypatch.chdir(tmp_path)

    def build(n: int) -> str:
        path = tmp_path / f"m{n}.db"
        conn = db.connect(path)
        members = [
            Evidence(f"F/{i:06d}", f"file_{i:06d}.bin", "ab" * 32, 1, "2026-01-01T00:00:00Z", "", "F") for i in range(n)
        ]
        db.put_folder(conn, "F", "ef" * 32, [m.evidence_id for m in members], members)
        conn.close()
        return str(path)

    small_db, large_db = build(small), build(large)

    def peak(path: str) -> int:
        tracemalloc.start()
        try:
            rows, details = verification_screen._run_evidence_check(db_path=path, jobs=jobs)
            return tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()

    assert (peak(large_db) - peak(small_db)) / (large - small) < 150  # bytes per extra row


def test_evidence_sidebar_window_of_a_big_result_is_cheap_and_touches_the_database_rarely(tmp_path, monkeypatch):
    import sqlite3
    import time

    from vcoc.interactive.verification_screen import _sidebar_text

    path = _mixed_db(tmp_path, monkeypatch, members=2000)
    rows, _ = verification_screen._run_evidence_check(db_path=path)
    connects = []
    real_connect = sqlite3.connect
    monkeypatch.setattr(sqlite3, "connect", lambda *a, **k: connects.append(a) or real_connect(*a, **k))
    top = [0]

    start = time.perf_counter()
    text = _sidebar_text(rows, selected=len(rows) - 1, top=top, height=30)
    elapsed = time.perf_counter() - start

    assert text.count("\n") == 30 and "Merkle root" in text
    assert len(connects) <= 3  # one block of rows per window, not one query per row
    assert elapsed < 0.05


def test_merkle_check_equals_the_old_index_based_result_without_loading_the_index(tmp_path, monkeypatch):
    import verifier

    path = _mixed_db(tmp_path, monkeypatch, members=50)
    index = cli_module._load_evidence_index(path)
    folders = cli_module._load_folder_index(path)
    grouped = sorted({rec.get("folder_id") or eid for eid, rec in index.items()})
    want_root = verifier.merkle_root([folders[g]["root"] if g in folders else index[g]["sha256"] for g in grouped])

    def boom(*a, **k):
        raise AssertionError("the whole index must not be loaded")

    monkeypatch.setattr(cli_module, "_load_evidence_index", boom)
    monkeypatch.setattr(cli_module, "_load_folder_index", boom)

    rows, details = verification_screen._run_merkle_check(db_path=path)

    assert rows == [f"Root over {len(grouped)} leaf(ves)/folder(s)"]
    assert details[0][1] == want_root


# --- the Evidence re-hash must not lock the database for the minutes it runs (Merkle tab: "database is locked") ----


def test_opening_the_database_while_the_evidence_check_is_mid_hash_does_not_lock(tmp_path, monkeypatch):
    import threading
    import time

    path = _mixed_db(tmp_path, monkeypatch, members=1500)
    paused, release = threading.Event(), threading.Event()

    def stall(i, n, evidence_id, done, total):
        if i == 1200:  # past the first page of rows, with the cursor of an unpaged implementation still open
            paused.set()
            release.wait(30)

    worker = threading.Thread(target=lambda: verification_screen._run_evidence_check(progress=stall, db_path=path))
    # the folder's missing/no-path rows never call progress: make every row a real file so every row reports
    conn = db.connect(path)
    with conn:
        conn.execute("UPDATE evidence SET source_path = ?", (str(tmp_path / "good.bin"),))
    conn.close()
    worker.start()
    try:
        assert paused.wait(30), "the evidence check never reached the stall point"
        start = time.perf_counter()
        db.connect(path).close()  # what the Merkle tab does as it opens
        rows, _ = verification_screen._run_merkle_check(db_path=path)
        assert time.perf_counter() - start < 2.0  # a locked database waits 5 s and then raises
        assert rows[0].startswith("Root over")
    finally:
        release.set()
        worker.join(30)


def test_connect_does_not_take_a_write_lock_when_the_schema_version_is_already_current(tmp_path):
    """db.connect used to run `PRAGMA user_version = N` + commit every time: a write that waits for any reader."""
    import sqlite3
    import time

    path = tmp_path / "v.db"
    db.connect(path).close()
    reader = sqlite3.connect(path)
    reader.execute("BEGIN")
    reader.execute("SELECT * FROM custody_log").fetchall()  # the open transaction now holds a read (SHARED) lock

    started = time.perf_counter()
    try:
        db.connect(path).close()
        assert time.perf_counter() - started < 2.0  # a write would wait the 5 s busy timeout and raise
    finally:
        reader.rollback()
        reader.close()


def test_connect_still_stamps_the_schema_version_on_a_new_database(tmp_path):
    conn = db.connect(tmp_path / "new.db")

    assert conn.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION


# --- re-hash speed: no exists()/stat() round trips per file (each costs ~100 us on Windows), lazy status text --------


def test_rehash_of_an_existing_file_makes_no_separate_exists_or_stat_calls(tmp_path, monkeypatch):
    import os

    import verifier

    f = tmp_path / "a.bin"
    f.write_bytes(b"x" * 100)
    target = os.path.normcase(str(f))
    calls = []

    def spying(real, label):
        def wrapper(self_or_path, *a, **k):
            if os.path.normcase(str(self_or_path)) == target:  # only OUR file: pytest itself stats other paths
                calls.append(label)
            return real(self_or_path, *a, **k)

        return wrapper

    monkeypatch.setattr(Path, "exists", spying(Path.exists, "Path.exists"))
    monkeypatch.setattr(Path, "stat", spying(Path.stat, "Path.stat"))
    monkeypatch.setattr(os, "stat", spying(os.stat, "os.stat"))
    seen = []

    status = verifier.evidence_rehash_status(
        3, 9, "EV1", str(f), hashlib.sha256(b"x" * 100).hexdigest(), lambda *a: seen.append(a)
    )

    assert status == "match"
    assert calls == []  # one open() per file is enough: no exists()/stat() round trip
    assert seen[0] == (3, 9, "EV1", 0, 100) and seen[-1] == (3, 9, "EV1", 100, 100)


@pytest.mark.parametrize("path", ["", "does-not-exist.bin"])
def test_rehash_statuses_for_missing_records_are_unchanged(tmp_path, path):
    import verifier

    source = str(tmp_path / path) if path else path
    calls = []

    status = verifier.evidence_rehash_status(1, 1, "EV1", source, "ab" * 32, lambda *a: calls.append(a))

    assert status == ("no source_path recorded" if not path else "not found")
    assert calls == []  # nothing hashed, nothing reported


def test_rehash_does_not_hide_a_real_read_error_as_not_found(tmp_path, monkeypatch):
    import verifier

    f = tmp_path / "locked.bin"
    f.write_bytes(b"x")

    def deny(*a, **k):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(verifier, "open", deny, raising=False)

    with pytest.raises(PermissionError):
        verifier.evidence_rehash_status(1, 1, "EV1", str(f), "ab" * 32)


def test_background_load_formats_the_status_text_only_when_it_is_read(monkeypatch):
    import threading

    import verifier

    formatted = []
    real = verifier._fmt_bytes
    monkeypatch.setattr(verifier, "_fmt_bytes", lambda n: formatted.append(n) or real(n))
    done = threading.Event()
    seen = {}
    bg = verification_screen._BackgroundLoad(on_change=lambda: None, on_result=lambda r: done.set())

    def load(progress):
        for i in range(1, 51):
            progress(i, 50, f"EV{i}", 10, 100)
        seen["before_read"] = len(formatted)
        seen["status"] = bg.status
        seen["after_read"] = len(formatted)
        return ([], [])

    bg.start(load)
    assert done.wait(10)

    assert seen["before_read"] == 0  # 50 progress calls, no string formatting
    assert seen["status"] == "Re-hashing 50/50  EV50  10 B / 100 B (10%)"
    assert seen["after_read"] == 2


def test_group_leaves_can_skip_the_member_counts_and_then_never_parses_member_ids(tmp_path, monkeypatch):
    """json_array_length(member_ids) makes SQLite parse the whole JSON text of every folder (40 MB at 416k files:
    a 215 MiB peak). The verification tabs never use the counts, so they must not pay for them."""
    path = _mixed_db(tmp_path, monkeypatch, members=30)
    conn = db.connect(path)
    statements = []
    conn.set_trace_callback(statements.append)

    without = db.group_leaves(conn, counts=False)
    with_counts = db.group_leaves(conn)

    assert [(g, leaf) for g, leaf, _ in without] == [(g, leaf) for g, leaf, _ in with_counts]
    assert all(count is None for _, _, count in without)
    assert {g: c for g, _, c in with_counts}["F1"] == 32  # unchanged default (merkle-root needs it)
    assert "json_array_length" not in statements[0] and "json_array_length" in statements[1]
    conn.close()


def test_the_verification_tabs_do_not_ask_for_member_counts(tmp_path, monkeypatch):
    path = _mixed_db(tmp_path, monkeypatch, members=10)
    asked = []
    real = db.group_leaves
    monkeypatch.setattr(db, "group_leaves", lambda conn, counts=True: asked.append(counts) or real(conn, counts))

    verification_screen._run_evidence_check(db_path=path)
    verification_screen._run_merkle_check(db_path=path)

    assert asked == [False, False]


def test_evidence_check_counts_folder_members_as_logged_when_the_folder_id_is_logged(tmp_path, monkeypatch):
    path = _mixed_db(tmp_path, monkeypatch, members=3)
    conn = db.connect(path)
    chain = HashChain.load_db(conn)
    signing_key, _ = generate_keypair()
    chain.add_event(evidence_id="F1", actor="a", action="batch-register", signing_key=signing_key)
    chain.save_db(conn)
    conn.close()

    rows, details = verification_screen._run_evidence_check(db_path=path)
    want_rows, want_details = _reference_evidence_check(path)

    assert list(rows) == want_rows
    assert [list(d) for d in details] == want_details
    i = next(n for n, r in enumerate(rows) if "F1/m0002" in r)  # 'not found' (benign) and logged only via its folder
    assert rows[i].startswith("OK ")
    assert "custody log: logged (via folder F1)" in details[i]
