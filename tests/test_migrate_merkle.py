"""A database made under the old Merkle rules (schema version 1, folder roots without leaf/node prefixes) is never mixed
with the new rules: it is refused with a clear message until `cli.py migrate-merkle` converts it, and anchors and proofs
made under the old rules are reported as such, not as tampering."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import cli as cli_module
from vcoc import db
from vcoc.ecdsa_signer import generate_keypair, save_keypair
from vcoc.merkle import MERKLE_FORMAT, MerkleRootBuilder, MerkleTree


def _add(db_path, path, evidence_id):
    cli_module.cmd_add_evidence(
        argparse.Namespace(file=str(path), evidence_id=evidence_id, db=str(db_path), private_key=None, actor=None)
    )


@pytest.fixture
def case(tmp_path, monkeypatch):
    """Two folders (3 and 2 files) and one standalone file."""
    monkeypatch.chdir(tmp_path)
    for folder, names in (("bfolder", ["a.txt", "b.txt", "c.txt"]), ("dfolder", ["x.txt", "y.txt"])):
        for name in names:
            f = tmp_path / folder / name
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(f"{folder}/{name}".encode())
    (tmp_path / "solo.bin").write_bytes(b"standalone")
    path = tmp_path / "vcoc.db"
    _add(path, tmp_path / "solo.bin", "A-SOLO")
    _add(path, tmp_path / "bfolder", "B-BATCH")
    _add(path, tmp_path / "dfolder", "D-BATCH")
    return path


def _version(path) -> int:
    conn = db.connect(path)
    try:
        return conn.execute("PRAGMA user_version").fetchone()[0]
    finally:
        conn.close()


def _make_legacy(path) -> dict[str, str]:
    """Rewrite a current database as version 1 had it: old-rule folder roots and user_version 1. Returns those roots."""
    conn = db.connect(path)
    roots = {}
    for (folder_id,) in conn.execute("SELECT folder_id FROM folders").fetchall():
        leaves = [leaf for _, leaf in db.iter_member_leaves(conn, folder_id)]
        roots[folder_id] = db._legacy_root(leaves)
        conn.execute("UPDATE folders SET root = ? WHERE folder_id = ?", (roots[folder_id], folder_id))
    conn.commit()
    conn.execute("PRAGMA user_version = 1")
    conn.commit()
    conn.close()
    return roots


def _roots(path) -> dict[str, str]:
    conn = db.connect(path)
    try:
        return {r[0]: r[1] for r in conn.execute("SELECT folder_id, root FROM folders")}
    finally:
        conn.close()


def test_a_new_database_is_stamped_current_and_an_old_one_without_folders_is_stamped_on_first_use(tmp_path):
    fresh = tmp_path / "fresh.db"
    db.connect(fresh).close()
    assert _version(fresh) == db.SCHEMA_VERSION == 2

    old = tmp_path / "old.db"
    conn = db.connect(old)
    conn.execute("PRAGMA user_version = 1")
    conn.commit()
    conn.close()
    assert _version(old) == 2  # no folder roots stored, so nothing to convert


def test_a_database_with_folders_keeps_its_old_version_and_refuses_anything_that_would_mix_the_rules(case, tmp_path):
    _make_legacy(case)
    assert _version(case) == 1

    conn = db.connect(case)
    for call in (
        lambda: db.group_leaves(conn),
        lambda: list(db.iter_group_leaves(conn)),
        lambda: db.load_folder_index(conn),
        lambda: db.get_folder(conn, "B-BATCH"),
        lambda: db.put_folder(conn, "NEW", "00" * 32, []),
    ):
        with pytest.raises(db.LegacyMerkleFormat, match="migrate-merkle"):
            call()
    conn.close()

    (tmp_path / "newfolder").mkdir()
    (tmp_path / "newfolder" / "n.txt").write_bytes(b"n")
    with pytest.raises(db.LegacyMerkleFormat):
        _add(case, tmp_path / "newfolder", "N-BATCH")
    assert _version(case) == 1


def test_the_command_line_reports_a_legacy_database_and_exits_with_1(case, capsys):
    _make_legacy(case)

    for command in (["merkle-root"], ["export", "--out-dir", str(case.parent / "out")], ["merkle-proof", "--evidence-id", "A-SOLO"]):
        with pytest.raises(SystemExit) as exit_info:
            cli_module.main([*command, "--db", str(case)])
        assert exit_info.value.code == 1
        assert "migrate-merkle" in capsys.readouterr().out


def test_migration_converts_every_folder_root_stamps_the_database_and_leaves_the_rest_alone(case, capsys):
    current = _roots(case)
    _make_legacy(case)
    conn = db.connect(case)
    evidence_before = [tuple(r) for r in conn.execute("SELECT * FROM evidence ORDER BY evidence_id")]
    conn.close()

    cli_module.main(["migrate-merkle", "--db", str(case)])
    out = capsys.readouterr().out

    assert "Converted 2 folder root(s)" in out
    assert _version(case) == 2
    assert _roots(case) == current  # the same roots a fresh registration produces
    conn = db.connect(case)
    assert [tuple(r) for r in conn.execute("SELECT * FROM evidence ORDER BY evidence_id")] == evidence_before
    leaves = [leaf for _, leaf, _ in db.group_leaves(conn)]
    conn.close()
    builder = MerkleRootBuilder()
    for leaf in leaves:
        builder.add(leaf)
    assert builder.root() == MerkleTree(leaves).root

    cli_module.main(["migrate-merkle", "--db", str(case)])
    assert "already uses the current Merkle tree rules" in capsys.readouterr().out


def test_migration_stops_and_writes_nothing_when_a_stored_root_does_not_match_its_members(case, capsys):
    roots = _make_legacy(case)
    conn = db.connect(case)
    conn.execute("UPDATE folders SET root = ? WHERE folder_id = 'D-BATCH'", ("ab" * 32,))
    conn.commit()
    conn.close()

    with pytest.raises(SystemExit) as exit_info:
        cli_module.main(["migrate-merkle", "--db", str(case)])

    assert exit_info.value.code == 1
    assert "D-BATCH" in capsys.readouterr().out
    assert _version(case) == 1
    assert _roots(case) == {"B-BATCH": roots["B-BATCH"], "D-BATCH": "ab" * 32}  # not even the healthy folder was converted

    cli_module.main(["migrate-merkle", "--db", str(case), "--force"])
    assert _version(case) == 2


def test_migrating_a_missing_database_reports_it_and_creates_nothing(tmp_path, capsys):
    with pytest.raises(SystemExit) as exit_info:
        cli_module.main(["migrate-merkle", "--db", str(tmp_path / "nope.db")])

    assert exit_info.value.code == 1
    assert not (tmp_path / "nope.db").exists()


def test_export_writes_the_merkle_format_into_the_anchor(case, tmp_path):
    out = tmp_path / "out"
    cli_module.cmd_export(argparse.Namespace(db=str(case), out_dir=str(out)))

    assert json.loads((out / "anchor.json").read_text(encoding="utf-8"))["merkle_format"] == MERKLE_FORMAT


def _verifier(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(REPO_ROOT / "verifier.py"), *args], capture_output=True, text=True)


def _exported(case, tmp_path) -> dict[str, Path]:
    signing_key, _ = generate_keypair()
    save_keypair(signing_key, tmp_path / "priv.pem", tmp_path / "pub.pem")
    cli_module.cmd_log_event(
        argparse.Namespace(
            evidence_id=["A-SOLO", "B-BATCH", "D-BATCH"],
            actor="J. Doe",
            action="collected",
            db=str(case),
            private_key=str(tmp_path / "priv.pem"),
            case_number=None,
            tag=None,
            notes=None,
        )
    )
    out = tmp_path / "out"
    cli_module.cmd_export(argparse.Namespace(db=str(case), out_dir=str(out)))
    return {
        "log": out / "custody_log.json",
        "pub": tmp_path / "pub.pem",
        "index": out / "evidence_index.json",
        "folders": out / "folder_index.json",
        "anchor": out / "anchor.json",
    }


def test_the_verifier_compares_the_root_of_a_current_anchor_and_does_not_call_an_old_anchor_tampering(case, tmp_path):
    f = _exported(case, tmp_path)
    args = ["--log", str(f["log"]), "--public-key", str(f["pub"]), "--evidence-index", str(f["index"]),
            "--folder-index", str(f["folders"]), "--anchor", str(f["anchor"])]

    current = _verifier(*args)
    assert current.returncode == 0, current.stdout
    assert "OK: Merkle root matches the anchor" in current.stdout

    anchor = json.loads(f["anchor"].read_text(encoding="utf-8"))
    del anchor["merkle_format"]  # an anchor taken before the format field existed
    f["anchor"].write_text(json.dumps(anchor), encoding="utf-8")
    old = _verifier(*args)
    assert old.returncode == 0, old.stdout
    assert "Merkle root not compared" in old.stdout and "not a tamper finding" in old.stdout
    assert "TAMPER" not in old.stdout.replace("not a tamper finding", "")

    anchor["merkle_format"] = MERKLE_FORMAT
    anchor["merkle_root"] = "cd" * 32  # a current anchor whose root really differs is still tampering
    f["anchor"].write_text(json.dumps(anchor), encoding="utf-8")
    changed = _verifier(*args)
    assert changed.returncode == 1
    assert "TAMPER DETECTED: Merkle root does not match the anchor" in changed.stdout


def test_the_verifier_fails_closed_on_a_proof_made_under_the_old_rules(case, tmp_path):
    f = _exported(case, tmp_path)
    proof_path = tmp_path / "proof.json"
    cli_module.cmd_merkle_proof(argparse.Namespace(evidence_id="B-BATCH/a.txt", db=str(case), out=str(proof_path)))
    base = ["--log", str(f["log"]), "--public-key", str(f["pub"]), "--merkle-proof", str(proof_path)]

    assert _verifier(*base).returncode == 0

    proof = json.loads(proof_path.read_text(encoding="utf-8"))
    del proof["merkle_format"]
    proof_path.write_text(json.dumps(proof), encoding="utf-8")
    old = _verifier(*base)
    assert old.returncode == 1
    assert "CANNOT VERIFY" in old.stdout and "not a tamper finding" in old.stdout
