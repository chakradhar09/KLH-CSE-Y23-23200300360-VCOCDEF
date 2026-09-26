"""cmd_merkle_root / cmd_merkle_proof grouping folder batches into the main tree."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import cli as cli_module
from vcoc.merkle import MerkleTree, nested_proof_from_dict, verify_nested_proof


def _ns(**kwargs) -> argparse.Namespace:
    defaults = dict(
        evidence_index=cli_module.DEFAULT_EVIDENCE_INDEX,
        folder_index=cli_module.DEFAULT_FOLDER_INDEX,
        log=cli_module.DEFAULT_LOG,
        private_key=None,
        out=None,
    )
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def _register_folder(tmp_path: Path, folder_id: str, files: dict[str, bytes]) -> None:
    folder = tmp_path / folder_id
    for rel, content in files.items():
        p = folder / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content)
    cli_module.cmd_add_evidence(_ns(file=str(folder), evidence_id=folder_id))


def test_merkle_root_matches_hand_built_two_level_tree(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _register_folder(tmp_path, "BATCH1", {"a.txt": b"a", "b.txt": b"b"})
    (tmp_path / "solo.bin").write_bytes(b"solo")
    cli_module.cmd_add_evidence(_ns(file=str(tmp_path / "solo.bin"), evidence_id="SOLO1"))

    folder_index = json.loads(Path(cli_module.DEFAULT_FOLDER_INDEX).read_text(encoding="utf-8"))
    evidence_index = cli_module._load_evidence_index(cli_module.DEFAULT_EVIDENCE_INDEX)
    # Group ids ("BATCH1", "SOLO1") sort alphabetically -- leaves must follow
    # that same order, not be sorted by hash value.
    expected_leaves = [folder_index["BATCH1"]["root"], evidence_index["SOLO1"]["sha256"]]
    expected_root = MerkleTree(expected_leaves).root

    capsys.readouterr()
    cli_module.cmd_merkle_root(_ns())
    out = capsys.readouterr().out
    assert expected_root in out


def test_merkle_proof_for_folder_member_verifies_via_nested_proof(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _register_folder(tmp_path, "BATCH1", {"a.txt": b"a", "b.txt": b"b", "c.txt": b"c"})
    (tmp_path / "solo.bin").write_bytes(b"solo")
    cli_module.cmd_add_evidence(_ns(file=str(tmp_path / "solo.bin"), evidence_id="SOLO1"))

    capsys.readouterr()
    cli_module.cmd_merkle_proof(_ns(evidence_id="BATCH1/b.txt"))
    out = capsys.readouterr().out
    output = json.loads(out)

    proof = nested_proof_from_dict(output["proof"])
    assert verify_nested_proof(output["leaf"], proof, output["root"])


def test_merkle_proof_for_solo_file_still_verifies_degenerate(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "solo.bin").write_bytes(b"solo")
    cli_module.cmd_add_evidence(_ns(file=str(tmp_path / "solo.bin"), evidence_id="SOLO1"))
    (tmp_path / "solo2.bin").write_bytes(b"solo2")
    cli_module.cmd_add_evidence(_ns(file=str(tmp_path / "solo2.bin"), evidence_id="SOLO2"))

    capsys.readouterr()
    cli_module.cmd_merkle_proof(_ns(evidence_id="SOLO1"))
    out = capsys.readouterr().out
    output = json.loads(out)

    proof = nested_proof_from_dict(output["proof"])
    assert proof.folder_proof == []
    assert verify_nested_proof(output["leaf"], proof, output["root"])


def test_merkle_root_lists_every_leaf_with_hash_and_folder_count(tmp_path, monkeypatch, capsys):
    """Task 25: merkle-root shows more than just the final root -- every
    grouped leaf (solo file or folder batch) with its own hash, and file
    counts for folders."""
    monkeypatch.chdir(tmp_path)
    _register_folder(tmp_path, "BATCH1", {"a.txt": b"a", "b.txt": b"b", "c.txt": b"c"})
    (tmp_path / "solo.bin").write_bytes(b"solo")
    cli_module.cmd_add_evidence(_ns(file=str(tmp_path / "solo.bin"), evidence_id="SOLO1"))

    folder_index = json.loads(Path(cli_module.DEFAULT_FOLDER_INDEX).read_text(encoding="utf-8"))
    evidence_index = cli_module._load_evidence_index(cli_module.DEFAULT_EVIDENCE_INDEX)

    capsys.readouterr()
    cli_module.cmd_merkle_root(_ns())
    out = capsys.readouterr().out

    assert "BATCH1" in out
    assert folder_index["BATCH1"]["root"] in out
    assert "3 file" in out  # folder file count shown
    assert "SOLO1" in out
    assert evidence_index["SOLO1"]["sha256"] in out


def test_merkle_root_empty_index_unchanged(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    capsys.readouterr()
    try:
        cli_module.cmd_merkle_root(_ns())
    except SystemExit as exc:
        assert exc.code == 1
    else:
        raise AssertionError("expected SystemExit(1) for empty evidence index")
    out = capsys.readouterr().out
    assert "No evidence registered yet." in out
