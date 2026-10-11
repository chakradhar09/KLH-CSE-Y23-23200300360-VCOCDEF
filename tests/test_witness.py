"""witness.py: a standalone, file-based witness. It cosigns a custody-log checkpoint only if the checkpoint extends the last
one it cosigned for that log (consistency proof), so it cannot be talked into signing a rewritten or forked history."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import verifier
import witness
from ecdsa import VerifyingKey
from witness_support import Lab

from vcoc import checkpoint as checkpoint_module
from vcoc.ecdsa_signer import generate_keypair, save_keypair


def _run(*args: str) -> int | None:
    """Run witness.main in-process; the exit code, or None for a normal return."""
    try:
        witness.main(list(args))
    except SystemExit as exc:
        return exc.code
    return None


@pytest.fixture
def lab(tmp_path):
    return Lab(tmp_path, events=4)


@pytest.fixture
def keys(tmp_path):
    """A witness key pair in tmp_path: (private path, public path)."""
    private, public = tmp_path / "w1.pem", tmp_path / "w1.pub"
    assert _run("init-key", "--key", str(private), "--pub", str(public)) is None
    return private, public


def _cosign(lab, keys, state, checkpoint, out, *extra, log_key=True):
    args = ["cosign", "--checkpoint", str(checkpoint), "--state", str(state), "--key", str(keys[0]), "--out", str(out)]
    if log_key:
        args += ["--log-key", str(lab.pub)]
    return _run(*args, *extra)


def _witness_key(keys) -> VerifyingKey:
    return VerifyingKey.from_pem(keys[1].read_bytes())


def _valid_witnesses(out: Path, keys) -> list[str]:
    cosigned = json.loads(out.read_text(encoding="utf-8"))
    valid, _ = verifier.cosigning_witnesses(cosigned, [_witness_key(keys)])
    return valid


# --- keys --------------------------------------------------------------------------------------------------------------


def test_init_key_writes_a_key_pair_prints_the_witness_id_and_never_overwrites(tmp_path, capsys):
    private, public = tmp_path / "w.pem", tmp_path / "w.pub"

    assert _run("init-key", "--key", str(private), "--pub", str(public)) is None
    wid = verifier.checkpoint_log_id(VerifyingKey.from_pem(public.read_bytes()))
    assert wid in capsys.readouterr().out

    before = private.read_bytes()
    assert _run("init-key", "--key", str(private), "--pub", str(public)) == 1
    assert "already exists" in capsys.readouterr().out
    assert private.read_bytes() == before


# --- accepting ---------------------------------------------------------------------------------------------------------


def test_first_sight_is_trusted_and_remembered(lab, keys, tmp_path, capsys):
    cp, _ = lab.checkpoint()
    state, out = tmp_path / "state.json", tmp_path / "cosigned.json"

    assert _cosign(lab, keys, state, cp, out) is None

    assert _valid_witnesses(out, keys) == [verifier.checkpoint_log_id(_witness_key(keys))]
    saved = json.loads(state.read_text(encoding="utf-8"))["logs"]
    body = json.loads(cp.read_text(encoding="utf-8"))["body"]
    assert saved[body["log_id"]]["size"] == 4 and saved[body["log_id"]]["root"] == body["root"]
    capsys.readouterr()
    assert _run("show-state", "--state", str(state)) is None
    shown = capsys.readouterr().out
    assert body["log_id"] in shown and "size 4" in shown and body["root"] in shown


def test_the_same_checkpoint_can_be_cosigned_again(lab, keys, tmp_path):
    cp, _ = lab.checkpoint()
    state = tmp_path / "state.json"
    assert _cosign(lab, keys, state, cp, tmp_path / "a.json") is None
    before = state.read_text(encoding="utf-8")

    assert _cosign(lab, keys, state, cp, tmp_path / "b.json", log_key=False) is None

    assert _valid_witnesses(tmp_path / "b.json", keys)
    assert json.loads(state.read_text(encoding="utf-8")) == json.loads(before)


def test_valid_growth_is_cosigned_and_the_log_key_is_remembered(lab, keys, tmp_path):
    state = tmp_path / "state.json"
    first, _ = lab.checkpoint("cp1.json")
    assert _cosign(lab, keys, state, first, tmp_path / "c1.json") is None
    lab.add(3)
    second, proof = lab.checkpoint("cp2.json", since=4)

    assert _cosign(lab, keys, state, second, tmp_path / "c2.json", "--proof", str(proof), log_key=False) is None

    body = json.loads(second.read_text(encoding="utf-8"))["body"]
    assert json.loads(state.read_text(encoding="utf-8"))["logs"][body["log_id"]]["size"] == 7
    assert _valid_witnesses(tmp_path / "c2.json", keys)


def test_two_witnesses_can_cosign_the_same_file_and_a_repeat_replaces_the_earlier_signature(lab, keys, tmp_path):
    second_private, second_public = tmp_path / "w2.pem", tmp_path / "w2.pub"
    _run("init-key", "--key", str(second_private), "--pub", str(second_public))
    second = (second_private, second_public)
    cp, _ = lab.checkpoint()

    assert _cosign(lab, keys, tmp_path / "s1.json", cp, tmp_path / "one.json") is None
    assert _cosign(lab, second, tmp_path / "s2.json", tmp_path / "one.json", tmp_path / "two.json") is None
    assert _cosign(lab, keys, tmp_path / "s1.json", tmp_path / "two.json", tmp_path / "three.json", log_key=False) is None

    cosigned = json.loads((tmp_path / "three.json").read_text(encoding="utf-8"))
    assert len(cosigned["cosignatures"]) == 2
    valid, _ = verifier.cosigning_witnesses(cosigned, [_witness_key(keys), _witness_key(second)])
    assert len(valid) == 2


# --- refusing ----------------------------------------------------------------------------------------------------------


def _state_bytes(path: Path) -> bytes | None:
    return path.read_bytes() if path.exists() else None


def test_a_checkpoint_with_a_bad_signature_is_refused(lab, keys, tmp_path, capsys):
    cp, _ = lab.checkpoint()
    broken = json.loads(cp.read_text(encoding="utf-8"))
    broken["signature"] = ("0" if broken["signature"][0] != "0" else "1") + broken["signature"][1:]
    cp.write_text(json.dumps(broken), encoding="utf-8")
    capsys.readouterr()  # drop earlier output: pytest's temp folder is named after the test, and init-key printed its path

    assert _cosign(lab, keys, tmp_path / "state.json", cp, tmp_path / "out.json") == 1

    printed = capsys.readouterr().out
    assert printed.startswith("REFUSED:") and "signature does not verify" in printed
    assert not (tmp_path / "state.json").exists() and not (tmp_path / "out.json").exists()


def test_a_checkpoint_for_a_log_the_witness_was_not_told_about_is_refused(lab, keys, tmp_path, capsys):
    cp, _ = lab.checkpoint()
    capsys.readouterr()

    assert _cosign(lab, keys, tmp_path / "state.json", cp, tmp_path / "out.json", log_key=False) == 1

    printed = capsys.readouterr().out
    assert printed.startswith("REFUSED:") and "has not seen this log before" in printed and "--log-key" in printed
    assert not (tmp_path / "state.json").exists()


def test_a_log_key_that_does_not_match_the_checkpoint_is_refused(lab, keys, tmp_path, capsys):
    other, _ = generate_keypair()
    save_keypair(other, tmp_path / "other.pem", tmp_path / "other.pub")
    cp, _ = lab.checkpoint()
    capsys.readouterr()

    code = _run(
        "cosign", "--checkpoint", str(cp), "--state", str(tmp_path / "state.json"), "--key", str(keys[0]),
        "--out", str(tmp_path / "out.json"), "--log-key", str(tmp_path / "other.pub"),
    )  # fmt: skip

    assert code == 1
    printed = capsys.readouterr().out
    assert printed.startswith("REFUSED:") and "does not verify" in printed
    assert not (tmp_path / "state.json").exists()


def _seed(lab, keys, tmp_path) -> Path:
    """A witness state that has cosigned the log at size 4."""
    state = tmp_path / "state.json"
    cp, _ = lab.checkpoint("seed.json")
    assert _cosign(lab, keys, state, cp, tmp_path / "seed_out.json") is None
    return state


def test_a_rollback_is_refused(lab, keys, tmp_path, capsys):
    lab.add(3)
    state = tmp_path / "state.json"
    big, _ = lab.checkpoint("big.json")
    assert _cosign(lab, keys, state, big, tmp_path / "o1.json") is None
    lab.chain.entries = lab.chain.entries[:4]  # the custodian's log is cut back to 4 entries
    small, _ = lab.checkpoint("small.json")
    before = _state_bytes(state)
    capsys.readouterr()

    assert _cosign(lab, keys, state, small, tmp_path / "o2.json", log_key=False) == 1

    assert capsys.readouterr().out.startswith("REFUSED: rollback:")
    assert _state_bytes(state) == before and not (tmp_path / "o2.json").exists()


def test_a_fork_at_the_same_size_is_refused(lab, keys, tmp_path, capsys):
    state = _seed(lab, keys, tmp_path)
    lab.chain.entries = lab.chain.entries[:3]  # a different 4th entry on the same first 3
    lab.add(1)
    fork, _ = lab.checkpoint("fork.json")
    before = _state_bytes(state)
    capsys.readouterr()

    assert _cosign(lab, keys, state, fork, tmp_path / "o.json", log_key=False) == 1

    assert capsys.readouterr().out.startswith("REFUSED: fork:")
    assert _state_bytes(state) == before and not (tmp_path / "o.json").exists()


def test_growth_that_rewrites_history_is_refused_even_with_a_proof_from_the_new_log(lab, keys, tmp_path, capsys):
    state = _seed(lab, keys, tmp_path)
    lab.chain.entries = lab.chain.entries[:1]  # history is rewritten from entry 1 on, then the log grows
    lab.add(8)
    grown, proof = lab.checkpoint("grown.json", since=4)
    before = _state_bytes(state)

    capsys.readouterr()

    assert _cosign(lab, keys, state, grown, tmp_path / "o.json", "--proof", str(proof), log_key=False) == 1

    assert capsys.readouterr().out.startswith("REFUSED: the checkpoint does not extend")
    assert _state_bytes(state) == before and not (tmp_path / "o.json").exists()


def test_growth_without_a_proof_or_with_a_proof_for_other_sizes_is_refused(lab, keys, tmp_path, capsys):
    state = _seed(lab, keys, tmp_path)
    lab.add(3)
    grown, proof = lab.checkpoint("grown.json", since=4)
    wrong_start = json.loads(proof.read_text(encoding="utf-8"))
    wrong_start["from_size"] = 2
    bad = tmp_path / "bad_proof.json"
    bad.write_text(json.dumps(wrong_start), encoding="utf-8")
    before = _state_bytes(state)

    assert _cosign(lab, keys, state, grown, tmp_path / "o.json", log_key=False) == 1
    assert "consistency proof" in capsys.readouterr().out
    assert _cosign(lab, keys, state, grown, tmp_path / "o.json", "--proof", str(bad), log_key=False) == 1
    assert "from size 4" in capsys.readouterr().out
    assert _state_bytes(state) == before and not (tmp_path / "o.json").exists()


def test_a_tampered_proof_is_refused(lab, keys, tmp_path, capsys):
    state = _seed(lab, keys, tmp_path)
    lab.add(3)
    grown, proof = lab.checkpoint("grown.json", since=4)
    tampered = json.loads(proof.read_text(encoding="utf-8"))
    tampered["proof"][0] = "ab" * 32
    proof.write_text(json.dumps(tampered), encoding="utf-8")

    assert _cosign(lab, keys, state, grown, tmp_path / "o.json", "--proof", str(proof), log_key=False) == 1

    assert "does not extend" in capsys.readouterr().out


@pytest.mark.parametrize("content", ["{not json", "[]", '{"body": 5}', ""])
def test_a_malformed_checkpoint_file_is_refused_without_a_traceback(lab, keys, tmp_path, capsys, content):
    cp = tmp_path / "bad.json"
    cp.write_text(content, encoding="utf-8")
    capsys.readouterr()

    assert _cosign(lab, keys, tmp_path / "state.json", cp, tmp_path / "out.json") == 1

    captured = capsys.readouterr()
    assert captured.out.startswith("REFUSED:") and "Traceback" not in captured.err
    assert not (tmp_path / "state.json").exists()


@pytest.mark.parametrize(
    "content, message",
    [("{corrupt", "cannot read the state file"), ('{"v": 9, "logs": {}}', "is not a witness state file"), ("[]", "is not a witness state file")],
)
def test_a_corrupt_state_file_stops_the_witness_instead_of_starting_over(lab, keys, tmp_path, capsys, content, message):
    state = tmp_path / "state.json"
    state.write_text(content, encoding="utf-8")
    cp, _ = lab.checkpoint()
    capsys.readouterr()

    assert _cosign(lab, keys, state, cp, tmp_path / "out.json") == 1

    assert message in capsys.readouterr().out
    assert state.read_text(encoding="utf-8") == content and not (tmp_path / "out.json").exists()


# --- state is saved atomically and before the output is written --------------------------------------------------------


def test_a_failed_state_save_leaves_the_old_state_no_temp_file_and_no_output(lab, keys, tmp_path, monkeypatch, capsys):
    state = _seed(lab, keys, tmp_path)
    before = _state_bytes(state)
    lab.add(2)
    grown, proof = lab.checkpoint("grown.json", since=4)
    monkeypatch.setattr(os, "replace", lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")))

    assert _cosign(lab, keys, state, grown, tmp_path / "o.json", "--proof", str(proof), log_key=False) == 1

    assert "could not save" in capsys.readouterr().out
    assert _state_bytes(state) == before and not (tmp_path / "o.json").exists()
    assert [p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp")] == []


def test_show_state_on_a_missing_file_says_so(tmp_path, capsys):
    assert _run("show-state", "--state", str(tmp_path / "none.json")) is None
    assert "no logs" in capsys.readouterr().out.lower()


def test_witness_py_checks_checkpoints_with_the_independent_verifier_rules():
    """The witness imports verifier.py for its crypto, so there is no third copy of the consistency or signature rules."""
    assert witness.verifier is verifier
    assert checkpoint_module.CHECKPOINT_VERSION == 1
