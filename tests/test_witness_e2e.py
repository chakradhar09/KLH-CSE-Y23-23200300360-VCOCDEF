"""The verifier checks witness cosignatures against a set of trusted witness keys and a quorum, and the whole flow
(custodian checkpoint -> witnesses -> verifier) works across separate processes, including against a stolen-key rewrite."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import verifier
import witness
from witness_support import Lab

from vcoc import checkpoint as checkpoint_module
from vcoc.ecdsa_signer import generate_keypair, save_keypair
from vcoc.hash_chain import HashChain


# --- the quorum rules, in isolation ------------------------------------------------------------------------------------


def _cosigned(lab: Lab, witness_keys: list, count: int | None = None, when: str = "2026-10-08T10:00:00+00:00") -> dict:
    checkpoint = checkpoint_module.build_checkpoint(lab.chain, lab.signing_key)
    signers = witness_keys if count is None else witness_keys[:count]
    checkpoint["cosignatures"] = [witness.make_cosignature(sk, checkpoint["body"], when) for sk, _ in signers]
    return checkpoint


@pytest.fixture
def lab(tmp_path):
    return Lab(tmp_path, events=4)


@pytest.fixture
def witnesses():
    return [generate_keypair() for _ in range(3)]


def _vks(witnesses) -> list:
    return [vk for _, vk in witnesses]


def test_valid_cosignatures_from_trusted_witnesses_are_counted(lab, witnesses):
    cosigned = _cosigned(lab, witnesses)

    valid, rejected = verifier.cosigning_witnesses(cosigned, _vks(witnesses))

    assert sorted(valid) == sorted(verifier.checkpoint_log_id(vk) for vk in _vks(witnesses))
    assert rejected == []


def test_a_cosignature_by_an_unknown_key_is_not_counted(lab, witnesses):
    cosigned = _cosigned(lab, witnesses)

    valid, rejected = verifier.cosigning_witnesses(cosigned, _vks(witnesses)[:2])

    assert len(valid) == 2 and rejected == [verifier.checkpoint_log_id(witnesses[2][1])]


def test_a_forged_or_transplanted_cosignature_is_not_counted(lab, witnesses):
    cosigned = _cosigned(lab, witnesses, count=1)
    forged = copy.deepcopy(cosigned)
    forged["cosignatures"][0]["signature"] = ("0" if forged["cosignatures"][0]["signature"][0] != "0" else "1") + forged["cosignatures"][0]["signature"][1:]
    later = copy.deepcopy(cosigned)
    later["cosignatures"][0]["witnessed_at"] = "2030-01-01T00:00:00+00:00"  # the time is signed too
    lab.add(1)
    other_checkpoint = _cosigned(lab, witnesses, count=1)  # a genuine cosignature, but of a different checkpoint
    transplanted = copy.deepcopy(cosigned)
    transplanted["cosignatures"] = other_checkpoint["cosignatures"]

    for bad in (forged, later, transplanted):
        valid, rejected = verifier.cosigning_witnesses(bad, _vks(witnesses))
        assert valid == [] and len(rejected) == 1


def test_one_witness_signing_twice_counts_once(lab, witnesses):
    cosigned = _cosigned(lab, witnesses, count=1)
    cosigned["cosignatures"] = cosigned["cosignatures"] * 3

    valid, _ = verifier.cosigning_witnesses(cosigned, _vks(witnesses))

    assert len(valid) == 1


@pytest.mark.parametrize("junk", [None, "text", 5, [], {}, [None], [{"witness_id": 5}], [{}], {"a": 1}])
def test_junk_where_the_cosignatures_should_be_is_ignored_not_a_crash(lab, witnesses, junk):
    cosigned = _cosigned(lab, witnesses, count=0)
    cosigned["cosignatures"] = junk

    valid, _ = verifier.cosigning_witnesses(cosigned, _vks(witnesses))

    assert valid == []


def test_a_checkpoint_without_a_cosignatures_field_has_no_witnesses(lab, witnesses):
    checkpoint = checkpoint_module.build_checkpoint(lab.chain, lab.signing_key)

    assert verifier.cosigning_witnesses(checkpoint, _vks(witnesses)) == ([], [])


# --- the verifier command ----------------------------------------------------------------------------------------------


def _write(path: Path, data) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _save_witness_pubs(tmp_path: Path, witnesses) -> list[Path]:
    paths = []
    for i, (sk, _) in enumerate(witnesses):
        save_keypair(sk, tmp_path / f"w{i}.pem", tmp_path / f"w{i}.pub")
        paths.append(tmp_path / f"w{i}.pub")
    return paths


def _verifier(lab: Lab, checkpoint: Path, *extra: str, log: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable, str(REPO_ROOT / "verifier.py"),
            "--log", str(log or lab.write_log()), "--public-key", str(lab.pub), "--checkpoint", str(checkpoint), *extra,
        ],
        capture_output=True, text=True,
    )  # fmt: skip


def test_without_witness_keys_the_checkpoint_is_checked_and_reported_as_not_witnessed(lab, witnesses, tmp_path):
    cp = _write(tmp_path / "cp.json", _cosigned(lab, witnesses))

    result = _verifier(lab, cp)

    assert result.returncode == 0, result.stdout
    assert "OK: custody log matches the checkpoint" in result.stdout
    assert "not witnessed" in result.stdout


def test_a_quorum_of_trusted_witnesses_passes_and_a_shortfall_fails(lab, witnesses, tmp_path):
    keys = [x for p in _save_witness_pubs(tmp_path, witnesses) for x in ("--witness-key", str(p))]
    cp = _write(tmp_path / "cp.json", _cosigned(lab, witnesses, count=2))

    ok = _verifier(lab, cp, *keys, "--quorum", "2")
    short = _verifier(lab, cp, *keys, "--quorum", "3")
    default = _verifier(lab, cp, *keys)

    assert ok.returncode == 0, ok.stdout
    assert "cosigned by 2 of 3 trusted witnesses (quorum 2)" in ok.stdout
    assert short.returncode == 1 and "NOT WITNESSED" in short.stdout and "2 of the required 3" in short.stdout
    assert default.returncode == 0 and "quorum 1" in default.stdout


def test_a_forged_cosignature_and_an_unknown_witness_do_not_count_toward_the_quorum(lab, witnesses, tmp_path):
    pubs = _save_witness_pubs(tmp_path, witnesses)
    cosigned = _cosigned(lab, witnesses, count=2)
    cosigned["cosignatures"][0]["signature"] = "00" * 64
    cp = _write(tmp_path / "cp.json", cosigned)

    forged = _verifier(lab, cp, "--witness-key", str(pubs[0]), "--witness-key", str(pubs[1]), "--quorum", "2")
    unknown = _verifier(lab, cp, "--witness-key", str(pubs[0]), "--quorum", "1")  # only witness 0 is trusted; its signature is forged

    assert forged.returncode == 1 and "NOT WITNESSED" in forged.stdout and "1 of the required 2" in forged.stdout
    assert unknown.returncode == 1 and "NOT WITNESSED" in unknown.stdout and "0 of the required 1" in unknown.stdout


def test_a_quorum_needs_witness_keys_and_a_positive_number(lab, witnesses, tmp_path):
    cp = _write(tmp_path / "cp.json", _cosigned(lab, witnesses))
    pub = _save_witness_pubs(tmp_path, witnesses)[0]

    assert _verifier(lab, cp, "--quorum", "2").returncode == 1
    assert "--witness-key" in _verifier(lab, cp, "--quorum", "2").stdout
    assert _verifier(lab, cp, "--witness-key", str(pub), "--quorum", "0").returncode == 1


def test_a_cosigned_checkpoint_does_not_excuse_a_log_that_no_longer_matches_it(lab, witnesses, tmp_path):
    pubs = _save_witness_pubs(tmp_path, witnesses)
    cp = _write(tmp_path / "cp.json", _cosigned(lab, witnesses))
    entries = lab.entries
    entries[1]["entry_hash"] = "ab" * 32

    result = _verifier(lab, cp, "--witness-key", str(pubs[0]), log=lab.write_log("edited.json", entries))

    assert result.returncode == 1 and "do not match the checkpoint" in result.stdout


# --- the whole flow, across processes ----------------------------------------------------------------------------------


def _py(script: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(REPO_ROOT / script), *args], capture_output=True, text=True)


def test_end_to_end_two_witnesses_then_a_stolen_key_rewrite_is_caught_without_an_anchor(tmp_path):
    lab = Lab(tmp_path, events=4)
    for name in ("w1", "w2"):
        assert _py("witness.py", "init-key", "--key", str(tmp_path / f"{name}.pem"), "--pub", str(tmp_path / f"{name}.pub")).returncode == 0

    def cosign(witness_name: str, checkpoint: Path, out: Path, *extra: str, first_time: bool = False) -> subprocess.CompletedProcess:
        args = ["cosign", "--checkpoint", str(checkpoint), "--state", str(tmp_path / f"{witness_name}_state.json"),
                "--key", str(tmp_path / f"{witness_name}.pem"), "--out", str(out), *extra]  # fmt: skip
        return _py("witness.py", *args, *(["--log-key", str(lab.pub)] if first_time else []))

    def verify(checkpoint: Path, log: Path) -> subprocess.CompletedProcess:
        return _py("verifier.py", "--log", str(log), "--public-key", str(lab.pub), "--checkpoint", str(checkpoint),
                   "--witness-key", str(tmp_path / "w1.pub"), "--witness-key", str(tmp_path / "w2.pub"), "--quorum", "2")  # fmt: skip

    # 1. intake: the custodian checkpoints at size 4; both witnesses cosign (the second adds to the first's file)
    cp1, _ = lab.checkpoint("cp1.json")
    assert cosign("w1", cp1, tmp_path / "c1_w1.json", first_time=True).returncode == 0
    assert cosign("w2", tmp_path / "c1_w1.json", tmp_path / "c1.json", first_time=True).returncode == 0
    honest = verify(tmp_path / "c1.json", lab.write_log())
    assert honest.returncode == 0, honest.stdout
    assert "cosigned by 2 of 2 trusted witnesses (quorum 2)" in honest.stdout

    # 2. the case moves on: three more events, a second checkpoint with a proof from size 4, cosigned by both witnesses
    lab.add(3)
    cp2, proof2 = lab.checkpoint("cp2.json", since=4)
    assert cosign("w1", cp2, tmp_path / "c2_w1.json", "--proof", str(proof2)).returncode == 0
    assert cosign("w2", tmp_path / "c2_w1.json", tmp_path / "c2.json", "--proof", str(proof2)).returncode == 0
    assert verify(tmp_path / "c2.json", lab.write_log()).returncode == 0
    honest_log = lab.entries

    # 3. an attacker with the stolen signing key rewrites entry 1 and re-signs the rest: the chain itself is valid
    rewritten = HashChain()
    for i, entry in enumerate(honest_log):
        rewritten.add_event(
            actor="Mallory" if i == 1 else entry["actor"], action=entry["action"], signing_key=lab.signing_key,
            evidence_id=entry["evidence_id"], timestamp=entry["timestamp"],
        )  # fmt: skip
    forged_log = lab.write_log("forged.json", [e.to_dict() for e in rewritten.entries])
    assert verify(tmp_path / "c2.json", forged_log).returncode == 1  # the witnessed checkpoint no longer matches
    assert "do not match the checkpoint" in verify(tmp_path / "c2.json", forged_log).stdout

    # 4. ...and no witness will sign the rewritten history, even with a valid proof and a valid custodian signature
    lab.chain = rewritten
    lab.add(3)
    cp3, proof3 = lab.checkpoint("cp3.json", since=7)
    refused = cosign("w1", cp3, tmp_path / "c3.json", "--proof", str(proof3))
    assert refused.returncode == 1 and "does not extend" in refused.stdout
    assert not (tmp_path / "c3.json").exists()


def test_end_to_end_with_the_real_cli_commands(tmp_path, monkeypatch):
    """cli.py checkpoint -> witness.py -> verifier.py on a real database, no test helpers in between."""
    import argparse

    import cli as cli_module

    monkeypatch.chdir(tmp_path)
    (tmp_path / "solo.bin").write_bytes(b"standalone")
    db_path = tmp_path / "vcoc.db"
    cli_module.cmd_add_evidence(argparse.Namespace(file=str(tmp_path / "solo.bin"), evidence_id="A", db=str(db_path), private_key=None, actor=None))
    signing_key, _ = generate_keypair()
    save_keypair(signing_key, tmp_path / "priv.pem", tmp_path / "pub.pem")

    def log(action: str) -> None:
        cli_module.cmd_log_event(argparse.Namespace(evidence_id=["A"], actor="J. Doe", action=action, db=str(db_path),
                                                     private_key=str(tmp_path / "priv.pem"), case_number=None, tag=None, notes=None))  # fmt: skip

    for action in ("collected", "transferred"):
        log(action)
    cli_module.main(["checkpoint", "--db", str(db_path), "--private-key", str(tmp_path / "priv.pem"), "--out", str(tmp_path / "cp1.json")])
    assert _py("witness.py", "init-key", "--key", str(tmp_path / "w.pem"), "--pub", str(tmp_path / "w.pub")).returncode == 0
    state = str(tmp_path / "state.json")
    first = _py("witness.py", "cosign", "--checkpoint", str(tmp_path / "cp1.json"), "--state", state, "--key", str(tmp_path / "w.pem"),
                "--log-key", str(tmp_path / "pub.pem"), "--out", str(tmp_path / "c1.json"))  # fmt: skip
    assert first.returncode == 0, first.stdout

    log("analysed")
    cli_module.main(["checkpoint", "--db", str(db_path), "--private-key", str(tmp_path / "priv.pem"), "--out", str(tmp_path / "cp2.json"),
                     "--since-size", "2", "--proof-out", str(tmp_path / "p2.json")])  # fmt: skip
    second = _py("witness.py", "cosign", "--checkpoint", str(tmp_path / "cp2.json"), "--proof", str(tmp_path / "p2.json"), "--state", state,
                 "--key", str(tmp_path / "w.pem"), "--out", str(tmp_path / "c2.json"))  # fmt: skip
    assert second.returncode == 0, second.stdout

    cli_module.cmd_export(argparse.Namespace(db=str(db_path), out_dir=str(tmp_path / "out")))
    result = _py("verifier.py", "--log", str(tmp_path / "out" / "custody_log.json"), "--public-key", str(tmp_path / "pub.pem"),
                 "--checkpoint", str(tmp_path / "c2.json"), "--witness-key", str(tmp_path / "w.pub"))  # fmt: skip
    assert result.returncode == 0, result.stdout
    assert "cosigned by 1 of 1 trusted witnesses (quorum 1)" in result.stdout
