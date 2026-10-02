"""verifier.py --anchor: check an exported log / evidence set against an anchor.json saved outside the database."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import cli as cli_module
import verifier
from vcoc import db
from vcoc.ecdsa_signer import generate_keypair, save_keypair
from vcoc.hash_chain import GENESIS_HASH, HashChain
from vcoc.models import Evidence


@pytest.fixture
def case(tmp_path):
    key, _ = generate_keypair()
    save_keypair(key, tmp_path / "priv.pem", tmp_path / "pub.pem")
    conn = db.connect(tmp_path / "vcoc.db")
    chain = HashChain()
    chain.add_event(evidence_id="EV001", actor="a", action="collected", signing_key=key)
    chain.add_event(evidence_id="EV002", actor="a", action="moved", signing_key=key)
    chain.save_db(conn)
    db.put_evidence(conn, Evidence("EV001", "a.bin", "ab" * 32, 1, "t", ""))
    db.put_evidence(conn, Evidence("EV002", "b.bin", "cd" * 32, 1, "t", ""))
    conn.close()
    out = _export(tmp_path, "out")
    shutil.copy(out / "anchor.json", tmp_path / "saved_anchor.json")  # the copy kept outside the database
    return tmp_path, key


def _export(tmp_path, name):
    out = tmp_path / name
    cli_module.cmd_export(
        cli_module.build_parser().parse_args(["export", "--db", str(tmp_path / "vcoc.db"), "--out-dir", str(out)])
    )
    return out


def _verify(tmp_path, out, *extra, anchor="saved_anchor.json"):
    argv = ["--log", str(out / "custody_log.json"), "--public-key", str(tmp_path / "pub.pem")]
    if anchor:
        argv += ["--anchor", str(tmp_path / anchor)]
    with pytest.raises(SystemExit) as exc:
        verifier.main(argv + list(extra))
    return exc.value.code


def _with_evidence(out):
    return ["--evidence-index", str(out / "evidence_index.json"), "--folder-index", str(out / "folder_index.json")]


def test_matching_anchor_passes(case, capsys):
    tmp, _ = case
    out = tmp / "out"

    assert _verify(tmp, out, *_with_evidence(out)) == 0
    text = capsys.readouterr().out
    assert "== Anchor ==" in text
    assert "OK: custody log matches the anchor" in text
    assert "OK: Merkle root matches the anchor" in text


def test_a_log_that_grew_since_the_anchor_still_passes_and_says_so(case, capsys):
    tmp, key = case
    conn = db.connect(tmp / "vcoc.db")
    chain = HashChain.load_db(conn)
    chain.add_event(evidence_id="EV001", actor="b", action="seen", signing_key=key)
    chain.save_db(conn)
    conn.close()
    out = _export(tmp, "out2")

    assert _verify(tmp, out) == 0
    assert "1 entry added since the anchor" in capsys.readouterr().out


def test_a_log_cut_short_is_caught_even_though_the_chain_itself_still_verifies(case, capsys):
    tmp, _ = case
    out = tmp / "out"
    entries = json.loads((out / "custody_log.json").read_text(encoding="utf-8"))
    (out / "custody_log.json").write_text(json.dumps(entries[:1]), encoding="utf-8")

    assert _verify(tmp, out) == 1
    text = capsys.readouterr().out
    assert "OK: chain of 1 entries verified" in text  # a shorter chain is a valid chain ...
    assert "TAMPER DETECTED: the log has 1 entries but the anchor was taken at 2" in text  # ... the anchor catches it


def test_a_rewritten_and_re_signed_log_is_caught(case, capsys):
    tmp, key = case
    other = HashChain()
    other.add_event(evidence_id="EV001", actor="x", action="forged", signing_key=key)
    other.add_event(evidence_id="EV002", actor="x", action="forged", signing_key=key)
    out = tmp / "out"
    (out / "custody_log.json").write_text(other.to_json(), encoding="utf-8")

    assert _verify(tmp, out) == 1
    text = capsys.readouterr().out
    assert "OK: chain of 2 entries verified" in text
    assert "TAMPER DETECTED: entry #1 does not match the anchor" in text


def test_a_changed_evidence_set_fails_the_merkle_root_check(case, capsys):
    tmp, _ = case
    out = tmp / "out"
    index = json.loads((out / "evidence_index.json").read_text(encoding="utf-8"))
    index["EV001"]["sha256"] = "ee" * 32
    (out / "evidence_index.json").write_text(json.dumps(index), encoding="utf-8")

    assert _verify(tmp, out, *_with_evidence(out)) == 1
    text = capsys.readouterr().out
    assert "TAMPER DETECTED: Merkle root does not match the anchor" in text
    assert "Evidence was added, removed or changed" in text


def test_without_an_evidence_index_the_root_check_is_skipped_not_failed(case, capsys):
    tmp, _ = case

    assert _verify(tmp, tmp / "out") == 0
    assert "Merkle root not checked (pass --evidence-index" in capsys.readouterr().out


def test_no_anchor_option_changes_nothing(case, capsys):
    tmp, _ = case

    assert _verify(tmp, tmp / "out", anchor=None) == 0
    assert "Anchor" not in capsys.readouterr().out


@pytest.mark.parametrize("content", ["not json", "[]", '{"chain_entries": 2}', '{"chain_entries": "x", "chain_head_hash": "a"}'])
def test_an_unreadable_anchor_is_an_error_not_a_pass(case, capsys, content):
    tmp, _ = case
    (tmp / "bad.json").write_text(content, encoding="utf-8")

    assert _verify(tmp, tmp / "out", anchor="bad.json") == 1
    assert "anchor" in capsys.readouterr().out.lower()


def test_anchor_of_an_empty_log_accepts_any_log_and_a_missing_file_is_an_error(tmp_path):
    empty = {"chain_entries": 0, "chain_head_hash": GENESIS_HASH, "merkle_leaves": 0, "merkle_root": None}

    assert verifier.anchor_chain_problem(empty, []) is None
    assert verifier.anchor_chain_problem(empty, [{"entry_hash": "x"}]) is None
    with pytest.raises(SystemExit) as exc:
        verifier.main(["--log", "nope.json", "--public-key", "nope.pem", "--anchor", str(tmp_path / "missing.json")])
    assert exc.value.code != 0
