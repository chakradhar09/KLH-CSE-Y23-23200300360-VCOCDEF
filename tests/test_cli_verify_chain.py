"""Tests for cli.py's verify-chain command: richer per-entry output."""

from __future__ import annotations

import sys
from io import StringIO
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import contextlib

import cli as cli_module
from vcoc.ecdsa_signer import generate_keypair, save_keypair
from vcoc.hash_chain import HashChain


def _run_verify_chain(tmp_path, expect_exit: bool = False) -> str:
    args = cli_module.build_parser().parse_args(
        ["verify-chain", "--log", str(tmp_path / "log.json"), "--public-key", str(tmp_path / "pub.pem")]
    )
    buf = StringIO()
    with contextlib.redirect_stdout(buf):
        if expect_exit:
            try:
                cli_module.cmd_verify_chain(args)
            except SystemExit as exc:
                assert exc.code == 1
            else:
                raise AssertionError("expected SystemExit(1)")
        else:
            cli_module.cmd_verify_chain(args)
    return buf.getvalue()


def test_verify_chain_lists_each_entry_single_evidence(tmp_path):
    signing_key, _ = generate_keypair()
    save_keypair(signing_key, tmp_path / "priv.pem", tmp_path / "pub.pem")

    chain = HashChain()
    chain.add_event(evidence_id="EV001", actor="J. Doe", action="collected", signing_key=signing_key)
    chain.add_event(evidence_id="EV001", actor="A. Smith", action="reviewed", signing_key=signing_key)
    chain.save(tmp_path / "log.json")

    output = _run_verify_chain(tmp_path)

    assert "OK: chain of 2 entries verified" in output
    assert "#0" in output
    assert "collected" in output
    assert "EV001" in output
    assert "J. Doe" in output
    assert "#1" in output
    assert "reviewed" in output
    assert "A. Smith" in output


def test_verify_chain_lists_multi_evidence_entry_with_case_tag(tmp_path):
    signing_key, _ = generate_keypair()
    save_keypair(signing_key, tmp_path / "priv.pem", tmp_path / "pub.pem")

    chain = HashChain()
    chain.add_event(
        evidence_ids=["EV001", "EV002"],
        actor="J. Doe",
        action="seized",
        signing_key=signing_key,
        case_number="C-001",
        tag="disk+memory",
    )
    chain.save(tmp_path / "log.json")

    output = _run_verify_chain(tmp_path)

    assert "EV001" in output
    assert "EV002" in output
    assert "C-001" in output
    assert "disk+memory" in output


def test_verify_chain_shows_both_hashes_signature_and_per_entry_status_clean(tmp_path):
    """Task 26: clean chain shows entry_hash, prev_hash, a truncated
    signature, and an OK status for every entry."""
    signing_key, _ = generate_keypair()
    save_keypair(signing_key, tmp_path / "priv.pem", tmp_path / "pub.pem")

    chain = HashChain()
    e0 = chain.add_event(evidence_id="EV001", actor="J. Doe", action="collected", signing_key=signing_key)
    e1 = chain.add_event(evidence_id="EV002", actor="J. Doe", action="reviewed", signing_key=signing_key)
    chain.save(tmp_path / "log.json")

    output = _run_verify_chain(tmp_path)

    assert e0.entry_hash in output
    assert e1.entry_hash in output
    assert e1.prev_hash in output
    assert e0.signature[:16] in output
    assert output.count("OK") >= 2  # per-entry OK status, not just the aggregate line


def test_verify_chain_shows_per_entry_tamper_status_for_broken_entry(tmp_path):
    """A tampered entry shows TAMPER for itself and downstream entries,
    while earlier untouched entries still report OK. A tampered chain still
    exits 1, same as before this task."""
    signing_key, _ = generate_keypair()
    save_keypair(signing_key, tmp_path / "priv.pem", tmp_path / "pub.pem")

    chain = HashChain()
    chain.add_event(evidence_id="EV001", actor="J. Doe", action="collected", signing_key=signing_key)
    chain.add_event(evidence_id="EV002", actor="J. Doe", action="reviewed", signing_key=signing_key)
    chain.entries[1].actor = "Mallory"
    chain.save(tmp_path / "log.json")

    output = _run_verify_chain(tmp_path, expect_exit=True)

    assert "TAMPER" in output
