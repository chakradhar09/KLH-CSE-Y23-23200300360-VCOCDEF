"""Witnesses from the shell, custodian side: write a checkpoint (and a consistency proof) for the witnesses, check the log
against a checkpoint they cosigned, and show how much of the log the last cosigned checkpoint covers. Cosigning itself
stays in witness.py, run by the independent witness."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

import cli as cli_module
import verifier
from vcoc.ecdsa_signer import load_verifying_key
from vcoc.interactive import forms, menu


def _custody_log(events: int) -> None:
    """A database in the current directory with `events` custody events, signed with the default keys."""
    for i in range(events):
        cli_module.main(["log-event", "--evidence-id", f"EV{i}", "--actor", "J. Doe", "--action", "reviewed"])


def _db_entries() -> list[dict]:
    from vcoc.interactive.verification_screen import _load_entries

    return _load_entries(cli_module.DEFAULT_DB)


@pytest.fixture
def shell(tmp_path, monkeypatch):
    """A custodian's shell in an empty directory: keys, a 3-event log, prompts and output captured."""
    monkeypatch.chdir(tmp_path)
    cli_module.main(["init-keys"])
    _custody_log(3)
    answers, shown = {}, {}
    monkeypatch.setattr(forms, "prompt_path", lambda title, label, default="": answers.get(label, default))
    monkeypatch.setattr(forms, "prompt_text", lambda title, label, default="": answers.get(label, default))
    monkeypatch.setattr(forms, "show_output", lambda title, text: shown.update(title=title, text=text))
    monkeypatch.setattr(menu, "run_with_loading", lambda title, work, label, **kw: work())
    config = {"private_key": cli_module.DEFAULT_PRIVATE_KEY, "public_key": cli_module.DEFAULT_PUBLIC_KEY}
    return tmp_path, config, answers, shown


def test_the_menu_offers_both_witness_actions():
    actions = dict(zip(menu.MENU_ITEMS, menu.ACTIONS))
    assert actions["Write checkpoint for witnesses"] is menu.action_write_checkpoint
    assert actions["Verify against cosigned checkpoint"] is menu.action_verify_checkpoint
    assert len(menu.MENU_ITEMS) == len(menu.ACTIONS) and menu.MENU_ITEMS[-1] == "Quit"


def test_menu_labels_stay_in_one_column_past_the_ten_digit_shortcuts():
    from vcoc.interactive import app

    lines = app._render_menu(0).split("\n")[: len(menu.MENU_ITEMS)]
    assert len(menu.MENU_ITEMS) > 10  # the 11th item has no digit key: it gets no number, not "11"
    assert {line.index(label) for line, label in zip(lines, menu.MENU_ITEMS)} == {5}
    assert "11" not in "".join(line[:5] for line in lines)


# --- write a checkpoint for the witnesses ------------------------------------------------------------------------------


def test_write_checkpoint_signs_the_whole_log_and_remembers_where_it_went(shell):
    tmp_path, config, answers, shown = shell

    menu.action_write_checkpoint(config)

    checkpoint = json.loads((tmp_path / "checkpoint.json").read_text(encoding="utf-8"))
    assert checkpoint["body"]["size"] == 3
    assert verifier.checkpoint_problem(checkpoint, _db_entries(), load_verifying_key(cli_module.DEFAULT_PUBLIC_KEY)) is None
    assert "Checkpoint written" in shown["text"] and "witness.py cosign" in shown["text"]  # says what to send, and to whom
    assert config["checkpoint"] == str(tmp_path / "checkpoint.json")


def test_write_checkpoint_with_the_last_cosigned_size_also_writes_the_consistency_proof(shell):
    tmp_path, config, answers, shown = shell
    answers["Size of the last checkpoint the witnesses cosigned (blank if none):"] = "2"

    menu.action_write_checkpoint(config)

    proof = json.loads((tmp_path / "checkpoint_proof.json").read_text(encoding="utf-8"))
    checkpoint = json.loads((tmp_path / "checkpoint.json").read_text(encoding="utf-8"))
    old_root = verifier.merkle_root([e["entry_hash"] for e in _db_entries()[:2]])
    assert (proof["from_size"], proof["to_size"]) == (2, 3)
    assert verifier.verify_consistency(2, 3, old_root, checkpoint["body"]["root"], proof["proof"])
    assert "checkpoint_proof.json" in shown["text"]


def test_write_checkpoint_refuses_a_size_that_is_not_a_number_and_writes_nothing(shell):
    tmp_path, config, answers, shown = shell
    answers["Size of the last checkpoint the witnesses cosigned (blank if none):"] = "two"

    menu.action_write_checkpoint(config)

    assert not (tmp_path / "checkpoint.json").exists() and "checkpoint" not in config
    assert "whole number" in shown["text"]


# --- check the log against a checkpoint the witnesses cosigned ---------------------------------------------------------

import witness  # noqa: E402  (the witness's own tool makes the cosignatures, as it would on the witness's machine)
from vcoc.ecdsa_signer import generate_keypair, save_keypair  # noqa: E402

KEYS, QUORUM = "Witness public keys (comma-separated):", "How many witnesses must have cosigned (quorum):"


def _cosign(tmp_path, signers: int, of: int = 2) -> list[str]:
    """Write `of` witness key pairs; the first `signers` of them cosign checkpoint.json. Returns the witnesses' public key paths."""
    path = tmp_path / "checkpoint.json"
    checkpoint = json.loads(path.read_text(encoding="utf-8"))
    pubs, cosignatures = [], []
    for n in range(of):
        sk, _ = generate_keypair()
        save_keypair(sk, tmp_path / f"w{n}.pem", tmp_path / f"w{n}.pub")
        pubs.append(str(tmp_path / f"w{n}.pub"))
        if n < signers:
            cosignatures.append(witness.make_cosignature(sk, checkpoint["body"], "2026-10-14T10:00:00+00:00"))
    checkpoint["cosignatures"] = cosignatures
    path.write_text(json.dumps(checkpoint), encoding="utf-8")
    return pubs


def test_a_checkpoint_cosigned_by_the_quorum_matches_the_log_and_is_remembered(shell):
    tmp_path, config, answers, shown = shell
    menu.action_write_checkpoint(config)
    answers.update({KEYS: ",".join(_cosign(tmp_path, signers=2)), QUORUM: "2"})

    menu.action_verify_checkpoint(config)

    assert "cosigned by 2 of 2 trusted witnesses (quorum 2)" in shown["text"] and "OK" in shown["text"]
    record = config["last_witness"]
    assert (record["ok"], record["size"], record["events"], record["cosigners"], record["quorum"]) == (True, 3, 3, 2, 2)
    assert config["witness_keys"] == answers[KEYS].split(",") and config["quorum"] == 2  # offered again next time


def test_entries_added_after_the_checkpoint_are_reported_as_not_yet_witnessed(shell):
    tmp_path, config, answers, shown = shell
    menu.action_write_checkpoint(config)
    answers.update({KEYS: ",".join(_cosign(tmp_path, signers=2)), QUORUM: "2"})
    _custody_log(1)

    menu.action_verify_checkpoint(config)

    assert "1 entry added since the checkpoint is not witnessed yet" in shown["text"]
    assert (config["last_witness"]["ok"], config["last_witness"]["size"], config["last_witness"]["events"]) == (True, 3, 4)


def test_too_few_cosignatures_fail_the_check(shell):
    tmp_path, config, answers, shown = shell
    menu.action_write_checkpoint(config)
    answers.update({KEYS: ",".join(_cosign(tmp_path, signers=1)), QUORUM: "2"})

    menu.action_verify_checkpoint(config)

    assert "cosigned by 1 of 2 trusted witnesses (quorum 2)" in shown["text"] and "NOT ENOUGH" in shown["text"]
    assert config["last_witness"]["ok"] is False


def test_a_checkpoint_of_another_log_fails_with_the_reason(shell):
    tmp_path, config, answers, shown = shell
    menu.action_write_checkpoint(config)
    pubs = _cosign(tmp_path, signers=2)
    cli_module.main(["init-keys", "--private-key", "other.pem", "--public-key", "other.pub"])
    config["private_key"], config["public_key"] = "other.pem", "other.pub"  # checked under a key that did not sign it
    answers.update({KEYS: ",".join(pubs), QUORUM: "2"})

    menu.action_verify_checkpoint(config)

    assert "FAIL" in shown["text"] and "does not verify" in shown["text"]
    assert config["last_witness"]["ok"] is False


# --- the menu header: how much of the log the last cosigned checkpoint covers -------------------------------------------

import os  # noqa: E402

from vcoc.interactive import app, status, theme  # noqa: E402


def _witnessed(shell, signers: int = 2) -> dict:
    tmp_path, config, answers, shown = shell
    menu.action_write_checkpoint(config)
    answers.update({KEYS: ",".join(_cosign(tmp_path, signers=signers)), QUORUM: "2"})
    menu.action_verify_checkpoint(config)
    return config


def _witness_line(config) -> str | None:
    return status.current_status(config, os.path.abspath(cli_module.DEFAULT_DB)).witness


def test_header_says_every_entry_is_cosigned_when_nothing_was_added_since(shell):
    assert _witness_line(_witnessed(shell)) == "witness ● all 3 entries cosigned · 2 witnesses, quorum 2"


def test_header_counts_the_entries_added_since_the_cosigned_checkpoint(shell):
    config = _witnessed(shell)
    _custody_log(2)
    assert _witness_line(config) == "witness ◐ 3 of 5 entries cosigned · 2 not yet"


def test_header_shows_a_failed_witness_check(shell):
    assert _witness_line(_witnessed(shell, signers=1)).startswith("witness ✖ FAIL")


def test_header_has_no_witness_line_before_any_check_or_for_another_database(shell):
    tmp_path, config, answers, shown = shell
    assert _witness_line(config) is None
    config = _witnessed(shell)
    config["last_witness"] = dict(config["last_witness"], db=str(tmp_path / "other.db"))
    assert _witness_line(config) is None


def test_the_witness_line_is_shown_under_the_status_line_from_24_rows_only(shell):
    config = _witnessed(shell)
    header, t = status.current_status(config, os.path.abspath(cli_module.DEFAULT_DB)), theme.make_theme("dark")
    tall = "".join(text for _, text in app._header_fragments(header, t, 24, 78)).split("\n")
    short = "".join(text for _, text in app._header_fragments(header, t, 20, 78))
    assert tall[1] == " witness ● all 3 entries cosigned · 2 witnesses, quorum 2" and "witness" not in short


@pytest.mark.parametrize("quorum", ["0", "3", "two"])
def test_an_impossible_quorum_is_refused_and_nothing_is_recorded(shell, quorum):
    tmp_path, config, answers, shown = shell
    menu.action_write_checkpoint(config)
    answers.update({KEYS: ",".join(_cosign(tmp_path, signers=2)), QUORUM: quorum})

    menu.action_verify_checkpoint(config)

    assert "quorum" in shown["text"].lower() and "last_witness" not in config
