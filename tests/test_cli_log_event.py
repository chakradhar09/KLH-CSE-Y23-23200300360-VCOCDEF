"""Tests for cli.py's log-event command: single and repeated --evidence-id."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import cli as cli_module
from vcoc.ecdsa_signer import generate_keypair, save_keypair


def _make_keys(tmp_path):
    signing_key, _ = generate_keypair()
    priv, pub = tmp_path / "priv.pem", tmp_path / "pub.pem"
    save_keypair(signing_key, priv, pub)
    return priv, pub


def test_log_event_single_evidence_id_unchanged(tmp_path):
    priv, _ = _make_keys(tmp_path)
    log_path = tmp_path / "log.json"
    args = cli_module.build_parser().parse_args(
        [
            "log-event",
            "--evidence-id",
            "EV001",
            "--actor",
            "J. Doe",
            "--action",
            "collected",
            "--log",
            str(log_path),
            "--private-key",
            str(priv),
        ]
    )
    cli_module.cmd_log_event(args)

    entries = json.loads(log_path.read_text(encoding="utf-8"))
    assert len(entries) == 1
    assert entries[0]["evidence_id"] == "EV001"
    assert "evidence_ids" not in entries[0]


def test_log_event_repeated_evidence_id_produces_one_multi_evidence_entry(tmp_path):
    priv, _ = _make_keys(tmp_path)
    log_path = tmp_path / "log.json"
    args = cli_module.build_parser().parse_args(
        [
            "log-event",
            "--evidence-id",
            "EV001",
            "--evidence-id",
            "EV002",
            "--actor",
            "J. Doe",
            "--action",
            "seized",
            "--log",
            str(log_path),
            "--private-key",
            str(priv),
            "--case-number",
            "C-001",
            "--tag",
            "disk+memory",
        ]
    )
    cli_module.cmd_log_event(args)

    entries = json.loads(log_path.read_text(encoding="utf-8"))
    assert len(entries) == 1
    assert entries[0]["evidence_ids"] == ["EV001", "EV002"]
    assert entries[0]["case_number"] == "C-001"
    assert entries[0]["tag"] == "disk+memory"
