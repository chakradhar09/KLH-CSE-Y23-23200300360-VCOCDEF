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

from vcoc.ecdsa_signer import generate_keypair, save_keypair
from vcoc.hash_chain import HashChain
from vcoc.interactive import menu, verification_screen

import cli as cli_module


def _write_signed_log(log_path: Path, signing_key) -> None:
    chain = HashChain()
    chain.add_event(evidence_id="EV001", actor="tester", action="collected", signing_key=signing_key)
    chain.save(str(log_path))


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

    log_path = tmp_path / "custody_log.json"
    _write_signed_log(log_path, signing_key)

    shell_config = {"private_key": str(private_path), "public_key": str(public_path)}

    rows, details = verification_screen._run_chain_check(shell_config)

    assert rows == ["OK  #0 collected on EV001"]
    assert "OK" in "\n".join(details[0])


def test_chain_check_falls_back_to_default_when_no_shell_config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    signing_key, verifying_key = generate_keypair()
    save_keypair(signing_key, "private_key.pem", "public_key.pem")

    log_path = tmp_path / "custody_log.json"
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
    chain.save(str(tmp_path / "custody_log.json"))

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

    log_path = tmp_path / "custody_log.json"
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
    chain.save(str(tmp_path / "custody_log.json"))

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
    chain.save(str(tmp_path / "custody_log.json"))

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
    chain.save(str(tmp_path / "custody_log.json"))

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
    """An existing but empty custody_log.json (distinct from a missing
    file) gets its own explanatory row, not a crash or silent zero rows."""
    monkeypatch.chdir(tmp_path)
    signing_key, _ = generate_keypair()
    save_keypair(signing_key, "private_key.pem", "public_key.pem")
    (tmp_path / "custody_log.json").write_text("[]", encoding="utf-8")

    rows, details = verification_screen._run_chain_check({})

    assert len(rows) == 1
    assert "no custody events" in rows[0].lower()


def test_chain_check_reports_missing_key_at_configured_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    log_path = tmp_path / "custody_log.json"
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
            evidence_index=cli_module.DEFAULT_EVIDENCE_INDEX,
            folder_index=cli_module.DEFAULT_FOLDER_INDEX,
            log=cli_module.DEFAULT_LOG,
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
    but _run_evidence_check() never loads/passes folder_index.json, so a
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
            evidence_index=cli_module.DEFAULT_EVIDENCE_INDEX,
            folder_index=cli_module.DEFAULT_FOLDER_INDEX,
            log=cli_module.DEFAULT_LOG,
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
            evidence_index=cli_module.DEFAULT_EVIDENCE_INDEX,
            folder_index=cli_module.DEFAULT_FOLDER_INDEX,
            log=cli_module.DEFAULT_LOG,
            private_key=None,
            actor=None,
        )
    )
    cli_module.cmd_merkle_proof(
        argparse.Namespace(
            evidence_id="EV001",
            evidence_index=cli_module.DEFAULT_EVIDENCE_INDEX,
            folder_index=cli_module.DEFAULT_FOLDER_INDEX,
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
    chain.save(str(tmp_path / "custody_log.json"))

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
    chain.save(str(tmp_path / "custody_log.json"))

    called = {}

    def fake_screen(shell_config):
        called["shell_config"] = shell_config

    def fail_show_output(title, text):
        raise AssertionError("action_verify_chain must not use forms.show_output")

    monkeypatch.setattr(menu, "run_verify_chain_screen", fake_screen)
    monkeypatch.setattr(menu.forms, "show_output", fail_show_output)

    shell_config = {"private_key": "private_key.pem", "public_key": "public_key.pem"}
    menu.action_verify_chain(None, shell_config)

    assert called["shell_config"] == shell_config
