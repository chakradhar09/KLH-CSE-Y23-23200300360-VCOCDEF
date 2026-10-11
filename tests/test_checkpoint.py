"""A checkpoint commits to the custody log at one moment (size, an RFC 6962 root over the entry hashes, the chain head, the
evidence root), signed by the custodian. verifier.py accepts a log that matches it or has only grown, and rejects anything
else. Witness cosigning (a later task) builds on exactly this."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
from ecdsa import BadSignatureError
from ecdsa.util import sigdecode_string

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import cli as cli_module
import verifier
from vcoc import checkpoint as checkpoint_module
from vcoc import db
from vcoc.ecdsa_signer import generate_keypair, save_keypair, sign_message
from vcoc.hash_chain import HashChain
from vcoc.merkle import MerkleTree, verify_consistency


def _chain(signing_key, events: int = 5) -> HashChain:
    chain = HashChain()
    for i in range(events):
        chain.add_event(actor="J. Doe", action="reviewed", signing_key=signing_key, evidence_id=f"EV{i}")
    return chain


def _entries(chain: HashChain) -> list[dict]:
    return [e.to_dict() for e in chain.entries]


def _problem(checkpoint: dict, entries: list[dict], verifying_key) -> str | None:
    return verifier.checkpoint_problem(checkpoint, entries, verifying_key)


# --- the checkpoint itself ---------------------------------------------------------------------------------------------


def test_a_checkpoint_has_the_documented_body_and_a_sha256_signature():
    signing_key, verifying_key = generate_keypair()
    chain = _chain(signing_key)

    checkpoint = checkpoint_module.build_checkpoint(chain, signing_key, evidence_root="ab" * 32, timestamp="2026-10-08T10:00:00+00:00")

    body = checkpoint["body"]
    assert set(body) == {"v", "log_id", "size", "root", "head_hash", "evidence_root", "merkle_format", "timestamp"}
    assert (body["v"], body["size"], body["evidence_root"], body["merkle_format"]) == (1, 5, "ab" * 32, 2)
    assert body["head_hash"] == chain.entries[-1].entry_hash
    assert body["timestamp"] == "2026-10-08T10:00:00+00:00"
    message = checkpoint_module.body_bytes(body)
    signature = bytes.fromhex(checkpoint["signature"])
    assert verifying_key.verify(signature, message, hashfunc=hashlib.sha256, sigdecode=sigdecode_string)
    with pytest.raises(BadSignatureError):
        verifying_key.verify(signature, message, hashfunc=hashlib.sha1, sigdecode=sigdecode_string)


def test_the_root_is_the_rfc_6962_root_over_the_entry_hashes_and_the_log_id_is_the_key_hash():
    signing_key, verifying_key = generate_keypair()
    chain = _chain(signing_key, events=6)
    hashes = [e.entry_hash for e in chain.entries]

    body = checkpoint_module.build_checkpoint(chain, signing_key)["body"]

    assert body["root"] == MerkleTree(hashes).root == verifier.merkle_root(hashes)
    assert body["log_id"] == hashlib.sha256(verifying_key.to_string()).hexdigest()
    assert body["log_id"] == checkpoint_module.log_id(verifying_key) == verifier.checkpoint_log_id(verifying_key)
    assert checkpoint_module.body_bytes(body) == verifier.checkpoint_body_bytes(body)
    assert body["evidence_root"] is None


def test_a_checkpoint_of_an_empty_log_is_refused():
    signing_key, _ = generate_keypair()

    with pytest.raises(ValueError, match="no custody events"):
        checkpoint_module.build_checkpoint(HashChain(), signing_key)


def test_a_consistency_proof_since_an_earlier_size_verifies_against_both_roots():
    signing_key, _ = generate_keypair()
    chain = _chain(signing_key, events=9)
    hashes = [e.entry_hash for e in chain.entries]

    proof = checkpoint_module.consistency_proof_since(hashes, 4)

    assert (proof["v"], proof["from_size"], proof["to_size"]) == (1, 4, 9)
    assert verify_consistency(4, 9, MerkleTree(hashes[:4]).root, MerkleTree(hashes).root, proof["proof"])
    assert checkpoint_module.consistency_proof_since(hashes, 9)["proof"] == []
    for bad in (0, 10, -1):
        with pytest.raises(ValueError):
            checkpoint_module.consistency_proof_since(hashes, bad)


# --- the verifier checks a log against a checkpoint --------------------------------------------------------------------


def test_an_honest_log_and_a_log_that_only_grew_match_the_checkpoint():
    signing_key, verifying_key = generate_keypair()
    chain = _chain(signing_key, events=5)
    checkpoint = checkpoint_module.build_checkpoint(chain, signing_key)

    assert _problem(checkpoint, _entries(chain), verifying_key) is None
    assert verifier.checkpoint_entries_since(checkpoint, _entries(chain)) == 0

    chain.add_event(actor="J. Doe", action="reviewed", signing_key=signing_key, evidence_id="EV9")
    chain.add_event(actor="J. Doe", action="reviewed", signing_key=signing_key, evidence_id="EV10")
    assert _problem(checkpoint, _entries(chain), verifying_key) is None
    assert verifier.checkpoint_entries_since(checkpoint, _entries(chain)) == 2


def test_a_bad_signature_or_a_changed_body_is_refused():
    signing_key, verifying_key = generate_keypair()
    chain = _chain(signing_key)
    checkpoint = checkpoint_module.build_checkpoint(chain, signing_key)

    flipped = copy.deepcopy(checkpoint)
    flipped["signature"] = ("0" if flipped["signature"][0] != "0" else "1") + flipped["signature"][1:]
    assert "signature" in _problem(flipped, _entries(chain), verifying_key)

    for field, value in (("size", 4), ("root", "cd" * 32), ("head_hash", "ef" * 32), ("timestamp", "2020-01-01")):
        changed = copy.deepcopy(checkpoint)
        changed["body"][field] = value
        assert "signature" in _problem(changed, _entries(chain), verifying_key), field

    _, other_key = generate_keypair()
    assert "signature" in _problem(checkpoint, _entries(chain), other_key)


def test_a_checkpoint_signed_for_another_log_id_is_refused():
    signing_key, verifying_key = generate_keypair()
    chain = _chain(signing_key)
    checkpoint = checkpoint_module.build_checkpoint(chain, signing_key)
    checkpoint["body"]["log_id"] = "00" * 32
    checkpoint["signature"] = sign_message(signing_key, checkpoint_module.body_bytes(checkpoint["body"]))

    assert "different log" in _problem(checkpoint, _entries(chain), verifying_key)


def test_removed_rewritten_and_reordered_entries_do_not_match_the_checkpoint_root():
    signing_key, verifying_key = generate_keypair()
    chain = _chain(signing_key, events=5)
    checkpoint = checkpoint_module.build_checkpoint(chain, signing_key)
    for _ in range(2):  # the log grows afterwards, so removing one entry does not shorten it below the checkpoint size
        chain.add_event(actor="J. Doe", action="reviewed", signing_key=signing_key, evidence_id="EVX")
    entries = _entries(chain)

    removed = entries[:2] + entries[3:]
    rewritten = copy.deepcopy(entries)
    rewritten[2]["entry_hash"] = "ab" * 32
    reordered = copy.deepcopy(entries)
    reordered[1], reordered[2] = reordered[2], reordered[1]

    for tampered in (removed, rewritten, reordered):
        problem = _problem(checkpoint, tampered, verifying_key)
        assert problem is not None and "do not match" in problem


def test_a_log_shorter_than_the_checkpoint_has_lost_entries():
    signing_key, verifying_key = generate_keypair()
    chain = _chain(signing_key, events=5)
    checkpoint = checkpoint_module.build_checkpoint(chain, signing_key)

    problem = _problem(checkpoint, _entries(chain)[:3], verifying_key)

    assert "has 3 entries" in problem and "covers 5" in problem and "entries were removed" in problem
    assert "entries were removed" in _problem(checkpoint, [], verifying_key)


def test_a_lying_size_is_caught_because_the_root_is_rebuilt_over_exactly_that_many_entries():
    """A consistency proof cannot tell which tree size a root belongs to (tests/test_merkle_consistency.py), so the size in
    the signed body is only trusted after the verifier rebuilds the root over the first `size` entries of the log."""
    signing_key, verifying_key = generate_keypair()
    chain = _chain(signing_key, events=6)
    hashes = [e.entry_hash for e in chain.entries]
    lie = checkpoint_module.build_checkpoint(chain, signing_key)
    lie["body"]["size"] = 4  # the root is the 3-entry one: not the root of any 4 entries
    lie["body"]["root"] = MerkleTree(hashes[:3]).root
    lie["body"]["head_hash"] = hashes[3]
    lie["signature"] = sign_message(signing_key, checkpoint_module.body_bytes(lie["body"]))

    assert "do not match" in _problem(lie, _entries(chain), verifying_key)


def test_a_head_hash_that_disagrees_with_the_log_is_refused():
    signing_key, verifying_key = generate_keypair()
    chain = _chain(signing_key)
    checkpoint = checkpoint_module.build_checkpoint(chain, signing_key)
    checkpoint["body"]["head_hash"] = "ef" * 32
    checkpoint["signature"] = sign_message(signing_key, checkpoint_module.body_bytes(checkpoint["body"]))

    assert "head hash" in _problem(checkpoint, _entries(chain), verifying_key)


@pytest.mark.parametrize(
    "broken",
    [
        {},
        {"body": {}, "signature": "00"},
        {"body": [], "signature": "00"},
        {"body": {"v": 1}, "signature": 5},
        {"body": {"v": 2, "size": 1}, "signature": "00"},
        [],
        "text",
        None,
    ],
)
def test_a_malformed_checkpoint_is_a_clear_problem_not_a_crash(broken):
    _, verifying_key = generate_keypair()

    assert "not a valid checkpoint" in _problem(broken, [], verifying_key)


# --- cli.py checkpoint and the verifier command ------------------------------------------------------------------------


@pytest.fixture
def case(tmp_path, monkeypatch):
    """A database with one registered file, a keypair, and four custody events."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "solo.bin").write_bytes(b"standalone")
    db_path = tmp_path / "vcoc.db"
    cli_module.cmd_add_evidence(
        argparse.Namespace(file=str(tmp_path / "solo.bin"), evidence_id="A-SOLO", db=str(db_path), private_key=None, actor=None)
    )
    signing_key, _ = generate_keypair()
    save_keypair(signing_key, tmp_path / "priv.pem", tmp_path / "pub.pem")
    for action in ("collected", "transferred", "analysed", "returned"):
        _log_event(db_path, tmp_path, action)
    return db_path


def _log_event(db_path, tmp_path, action):
    cli_module.cmd_log_event(
        argparse.Namespace(
            evidence_id=["A-SOLO"],
            actor="J. Doe",
            action=action,
            db=str(db_path),
            private_key=str(tmp_path / "priv.pem"),
            case_number=None,
            tag=None,
            notes=None,
        )
    )


def _run(tmp_path, *args):
    try:
        cli_module.main(list(args))
    except SystemExit as exc:
        return exc.code
    return None


def _checkpoint_args(case, tmp_path, *extra):
    return ["checkpoint", "--db", str(case), "--private-key", str(tmp_path / "priv.pem"), "--out", str(tmp_path / "cp.json"), *extra]


def _verify(tmp_path, *extra):
    cli_module.cmd_export(argparse.Namespace(db=str(tmp_path / "vcoc.db"), out_dir=str(tmp_path / "out")))
    return subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "verifier.py"),
            "--log",
            str(tmp_path / "out" / "custody_log.json"),
            "--public-key",
            str(tmp_path / "pub.pem"),
            "--checkpoint",
            str(tmp_path / "cp.json"),
            *extra,
        ],
        capture_output=True,
        text=True,
    )


def test_the_command_writes_a_signed_checkpoint_the_verifier_accepts(case, tmp_path, capsys):
    assert _run(tmp_path, *_checkpoint_args(case, tmp_path)) is None

    checkpoint = json.loads((tmp_path / "cp.json").read_text(encoding="utf-8"))
    assert checkpoint["body"]["size"] == 4
    assert checkpoint["body"]["evidence_root"] is not None  # one registered file
    out = capsys.readouterr().out
    assert "size 4" in out and checkpoint["body"]["root"] in out

    result = _verify(tmp_path)
    assert result.returncode == 0, result.stdout
    assert "OK: custody log matches the checkpoint (size 4" in result.stdout


def test_the_evidence_root_is_taken_from_the_database(case, tmp_path):
    _run(tmp_path, *_checkpoint_args(case, tmp_path))
    body = json.loads((tmp_path / "cp.json").read_text(encoding="utf-8"))["body"]

    conn = db.connect(case)
    leaves = [leaf for _, leaf, _ in db.group_leaves(conn, counts=False)]
    conn.close()

    assert body["evidence_root"] == MerkleTree(leaves).root


def test_a_log_that_grew_since_the_checkpoint_still_passes_and_says_how_much(case, tmp_path):
    _run(tmp_path, *_checkpoint_args(case, tmp_path))
    _log_event(case, tmp_path, "released")
    _log_event(case, tmp_path, "archived")

    result = _verify(tmp_path)

    assert result.returncode == 0, result.stdout
    assert "(2 entries added since the checkpoint)" in result.stdout


def test_an_edited_log_fails_the_verifier_command(case, tmp_path):
    _run(tmp_path, *_checkpoint_args(case, tmp_path))
    cli_module.cmd_export(argparse.Namespace(db=str(case), out_dir=str(tmp_path / "out")))
    log = tmp_path / "out" / "custody_log.json"
    entries = json.loads(log.read_text(encoding="utf-8"))
    entries[1]["entry_hash"] = "ab" * 32  # the chain check and the checkpoint check both object
    log.write_text(json.dumps(entries), encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "verifier.py"), "--log", str(log), "--public-key", str(tmp_path / "pub.pem"), "--checkpoint", str(tmp_path / "cp.json")],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "TAMPER DETECTED" in result.stdout and "do not match the checkpoint" in result.stdout


def test_the_evidence_root_in_a_checkpoint_is_compared_when_the_evidence_index_is_given(case, tmp_path):
    _run(tmp_path, *_checkpoint_args(case, tmp_path))
    index = str(tmp_path / "out" / "evidence_index.json")

    not_given = _verify(tmp_path)
    honest = _verify(tmp_path, "--evidence-index", index)

    assert not_given.returncode == 0 and "Evidence root not checked" in not_given.stdout
    assert honest.returncode == 0, honest.stdout
    assert "OK: evidence Merkle root matches the checkpoint" in honest.stdout

    (tmp_path / "second.bin").write_bytes(b"added after the checkpoint")  # the evidence set changes (and is logged)
    cli_module.cmd_add_evidence(
        argparse.Namespace(file=str(tmp_path / "second.bin"), evidence_id="B-SOLO", db=str(case), private_key=None, actor=None)
    )
    cli_module.cmd_log_event(
        argparse.Namespace(evidence_id=["B-SOLO"], actor="J. Doe", action="collected", db=str(case),
                           private_key=str(tmp_path / "priv.pem"), case_number=None, tag=None, notes=None)
    )  # fmt: skip
    changed = _verify(tmp_path, "--evidence-index", index)

    assert changed.returncode == 1
    assert "TAMPER DETECTED: the evidence Merkle root does not match the checkpoint" in changed.stdout
    assert "custody log matches the checkpoint" in changed.stdout  # the log itself is fine: only the evidence set moved


def test_a_truncated_log_fails_the_verifier_command(case, tmp_path):
    _run(tmp_path, *_checkpoint_args(case, tmp_path))
    cli_module.cmd_export(argparse.Namespace(db=str(case), out_dir=str(tmp_path / "out")))
    log = tmp_path / "out" / "custody_log.json"
    log.write_text(json.dumps(json.loads(log.read_text(encoding="utf-8"))[:2]), encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "verifier.py"), "--log", str(log), "--public-key", str(tmp_path / "pub.pem"), "--checkpoint", str(tmp_path / "cp.json")],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "has 2 entries" in result.stdout and "entries were removed" in result.stdout


def test_since_size_writes_a_consistency_proof_from_that_size(case, tmp_path):
    _run(tmp_path, *_checkpoint_args(case, tmp_path, "--since-size", "2", "--proof-out", str(tmp_path / "proof.json")))

    proof = json.loads((tmp_path / "proof.json").read_text(encoding="utf-8"))
    body = json.loads((tmp_path / "cp.json").read_text(encoding="utf-8"))["body"]
    conn = db.connect(case)
    hashes = [e.entry_hash for e in HashChain.load_db(conn).entries]
    conn.close()

    assert (proof["from_size"], proof["to_size"]) == (2, 4)
    assert verify_consistency(2, 4, MerkleTree(hashes[:2]).root, body["root"], proof["proof"])
    assert verifier.verify_consistency(2, 4, MerkleTree(hashes[:2]).root, body["root"], proof["proof"])


@pytest.mark.parametrize(
    "extra",
    [
        ["--since-size", "0", "--proof-out", "p.json"],
        ["--since-size", "9", "--proof-out", "p.json"],
        ["--since-size", "2"],
        ["--proof-out", "p.json"],
    ],
)
def test_bad_since_size_options_are_refused_before_anything_is_written(case, tmp_path, capsys, extra):
    code = _run(tmp_path, *_checkpoint_args(case, tmp_path, *extra))

    assert code == 1
    assert capsys.readouterr().out.strip() != ""
    assert not (tmp_path / "cp.json").exists() and not (tmp_path / "p.json").exists()


def test_a_missing_database_or_a_log_with_no_events_is_refused_with_a_message(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    signing_key, _ = generate_keypair()
    save_keypair(signing_key, tmp_path / "priv.pem", tmp_path / "pub.pem")

    assert _run(tmp_path, "checkpoint", "--db", str(tmp_path / "nope.db"), "--private-key", str(tmp_path / "priv.pem"), "--out", str(tmp_path / "cp.json")) == 1
    assert "does not exist" in capsys.readouterr().out
    assert not (tmp_path / "nope.db").exists()

    db.connect(tmp_path / "empty.db").close()
    assert _run(tmp_path, "checkpoint", "--db", str(tmp_path / "empty.db"), "--private-key", str(tmp_path / "priv.pem"), "--out", str(tmp_path / "cp.json")) == 1
    assert "no custody events" in capsys.readouterr().out
    assert not (tmp_path / "cp.json").exists()


def test_a_checkpoint_for_a_log_signed_by_another_key_fails_the_verifier_command(case, tmp_path):
    _run(tmp_path, *_checkpoint_args(case, tmp_path))
    other_key, _ = generate_keypair()
    save_keypair(other_key, tmp_path / "other.pem", tmp_path / "other_pub.pem")
    cli_module.cmd_export(argparse.Namespace(db=str(case), out_dir=str(tmp_path / "out")))

    result = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "verifier.py"),
            "--log",
            str(tmp_path / "out" / "custody_log.json"),
            "--public-key",
            str(tmp_path / "other_pub.pem"),
            "--checkpoint",
            str(tmp_path / "cp.json"),
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1  # the chain's own signatures already fail under this key; the checkpoint does too
    assert "signature" in result.stdout


def test_a_checkpoint_file_that_is_not_json_is_a_clear_exit_not_a_traceback(case, tmp_path):
    (tmp_path / "cp.json").write_text("{not json", encoding="utf-8")

    result = _verify(tmp_path)

    assert result.returncode == 1
    assert "Traceback" not in result.stderr and "checkpoint" in result.stdout
