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

from vcoc.ecdsa_signer import generate_keypair, save_keypair
from vcoc.hash_chain import HashChain
from vcoc.interactive import verification_screen


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
