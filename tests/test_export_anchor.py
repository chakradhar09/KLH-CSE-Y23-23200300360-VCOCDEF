"""export also writes anchor.json: the chain head hash and the Merkle root, to be kept somewhere outside the database."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import cli as cli_module
import verifier
from vcoc import db
from vcoc.ecdsa_signer import generate_keypair
from vcoc.hash_chain import GENESIS_HASH, HashChain
from vcoc.models import Evidence


def _export(tmp_path):
    out = tmp_path / "out"
    cli_module.cmd_export(
        cli_module.build_parser().parse_args(["export", "--db", str(tmp_path / "vcoc.db"), "--out-dir", str(out)])
    )
    return out


def _seed(tmp_path):
    signing_key, _ = generate_keypair()
    conn = db.connect(tmp_path / "vcoc.db")
    chain = HashChain()
    chain.add_event(evidence_id="EV001", actor="a", action="collected", signing_key=signing_key)
    chain.add_event(evidence_id="EV002", actor="a", action="moved", signing_key=signing_key)
    chain.save_db(conn)
    db.put_evidence(conn, Evidence("EV001", "a.bin", "ab" * 32, 1, "t", "/x/a.bin"))
    db.put_evidence(conn, Evidence("EV002", "b.bin", "cd" * 32, 1, "t", "/x/b.bin"))
    conn.close()
    return chain


def test_anchor_holds_the_chain_head_and_the_merkle_root(tmp_path, capsys):
    chain = _seed(tmp_path)
    out = _export(tmp_path)

    anchor = json.loads((out / "anchor.json").read_text(encoding="utf-8"))

    assert anchor["chain_entries"] == 2
    assert anchor["chain_head_hash"] == chain.entries[-1].entry_hash
    assert anchor["merkle_root"] == verifier.merkle_root(["ab" * 32, "cd" * 32])
    assert anchor["merkle_leaves"] == 2
    assert anchor["exported_at"]


def test_the_anchor_is_printed_so_it_can_be_copied_elsewhere(tmp_path, capsys):
    chain = _seed(tmp_path)
    _export(tmp_path)

    text = capsys.readouterr().out
    assert chain.entries[-1].entry_hash in text
    assert verifier.merkle_root(["ab" * 32, "cd" * 32]) in text


def test_anchor_of_an_empty_store_is_the_genesis_hash_and_no_root(tmp_path):
    db.connect(tmp_path / "vcoc.db").close()
    out = _export(tmp_path)

    anchor = json.loads((out / "anchor.json").read_text(encoding="utf-8"))

    assert anchor["chain_entries"] == 0
    assert anchor["chain_head_hash"] == GENESIS_HASH
    assert anchor["merkle_root"] is None
    assert anchor["merkle_leaves"] == 0


def test_anchor_changes_when_the_log_grows_or_evidence_changes(tmp_path):
    _seed(tmp_path)
    first = json.loads((_export(tmp_path) / "anchor.json").read_text(encoding="utf-8"))

    conn = db.connect(tmp_path / "vcoc.db")
    db.put_evidence(conn, Evidence("EV001", "a.bin", "ee" * 32, 1, "t", "/x/a.bin"))
    chain = HashChain.load_db(conn)
    chain.add_event(evidence_id="EV001", actor="a", action="seen", signing_key=generate_keypair()[0])
    chain.save_db(conn)
    conn.close()
    second = json.loads((_export(tmp_path) / "anchor.json").read_text(encoding="utf-8"))

    assert second["chain_head_hash"] != first["chain_head_hash"]
    assert second["merkle_root"] != first["merkle_root"]
