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

    assert rows == ["OK  chain of 1 entries"]
    assert "verified independently" in details[0][0]


def test_chain_check_falls_back_to_default_when_no_shell_config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    signing_key, verifying_key = generate_keypair()
    save_keypair(signing_key, "private_key.pem", "public_key.pem")

    log_path = tmp_path / "custody_log.json"
    _write_signed_log(log_path, signing_key)

    rows, details = verification_screen._run_chain_check({})

    assert rows == ["OK  chain of 1 entries"]


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
