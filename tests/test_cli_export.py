"""export: regenerate the JSON files verifier.py reads from the SQLite store."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import cli as cli_module
import verifier
from vcoc import db
from vcoc.ecdsa_signer import generate_keypair, save_keypair
from vcoc.hash_chain import HashChain
from vcoc.models import Evidence


def _seed(tmp_path):
    signing_key, _ = generate_keypair()
    save_keypair(signing_key, tmp_path / "priv.pem", tmp_path / "pub.pem")
    conn = db.connect(tmp_path / "vcoc.db")
    chain = HashChain()
    chain.add_event(evidence_id="EV001", actor="J. Doe", action="collected", signing_key=signing_key)
    chain.add_event(evidence_ids=["EV001", "EV002"], actor="A", action="moved", signing_key=signing_key, notes="n")
    chain.save_db(conn)
    db.put_evidence(conn, Evidence("EV001", "a.bin", "ab" * 32, 1, "t", "/x/a.bin"))
    db.put_folder(conn, "F1", "cd" * 32, ["F1/a"])
    return conn, chain


def _export(tmp_path):
    out = tmp_path / "out"
    args = cli_module.build_parser().parse_args(
        ["export", "--db", str(tmp_path / "vcoc.db"), "--out-dir", str(out)]
    )
    cli_module.cmd_export(args)
    return out


def test_export_writes_three_json_files(tmp_path):
    _, chain = _seed(tmp_path)
    out = _export(tmp_path)

    assert (out / "custody_log.json").read_text(encoding="utf-8") == chain.to_json()
    assert json.loads((out / "evidence_index.json").read_text(encoding="utf-8"))["EV001"]["sha256"] == "ab" * 32
    assert json.loads((out / "folder_index.json").read_text(encoding="utf-8")) == {
        "F1": {"root": "cd" * 32, "member_ids": ["F1/a"]}
    }


def test_verifier_accepts_exported_log_and_rejects_tampered(tmp_path, capsys):
    _seed(tmp_path)
    out = _export(tmp_path)

    try:
        verifier.main(["--log", str(out / "custody_log.json"), "--public-key", str(tmp_path / "pub.pem")])
    except SystemExit as exc:
        assert exc.code == 0
    assert "OK: chain of 2 entries verified" in capsys.readouterr().out

    entries = json.loads((out / "custody_log.json").read_text(encoding="utf-8"))
    entries[0]["actor"] = "Mallory"
    (out / "custody_log.json").write_text(json.dumps(entries), encoding="utf-8")
    try:
        verifier.main(["--log", str(out / "custody_log.json"), "--public-key", str(tmp_path / "pub.pem")])
    except SystemExit as exc:
        assert exc.code != 0
    else:
        raise AssertionError("verifier accepted a tampered log")
