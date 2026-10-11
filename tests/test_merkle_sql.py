"""Task 6e: `merkle-root` / `merkle-proof` answered with SQL instead of loading every evidence row.

Measured on the real 92,879-row DB: merkle-root 431 ms and merkle-proof 552 ms, ~290 ms of it just loading all rows
into dicts (plus the folder index, whose member_ids JSON holds 92,871 ids). The output must stay byte-identical, so the
index-based helpers (`_build_main_tree`, `build_tree_view`, the old proof logic) are used here as the reference.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

import cli as cli_module
from vcoc import db
from vcoc.merkle import MERKLE_FORMAT, MerkleTree, build_nested_proof, nested_proof_to_dict, verify_nested_proof
from vcoc.visualize import build_tree_view


def _add(db_path, path, evidence_id):
    with contextlib.redirect_stdout(io.StringIO()):
        cli_module.cmd_add_evidence(
            argparse.Namespace(file=str(path), evidence_id=evidence_id, db=str(db_path), private_key=None, actor=None)
        )


@pytest.fixture
def case_db(tmp_path, monkeypatch):
    """Two folders (3 and 2 files), two standalone files, ids chosen so the group order interleaves them."""
    monkeypatch.chdir(tmp_path)
    for folder, names in (("bfolder", ["a.txt", "sub/b.txt", "c.txt"]), ("dfolder", ["x.txt", "y.txt"])):
        for name in names:
            f = tmp_path / folder / name
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(f"{folder}/{name}".encode())
    (tmp_path / "s1.bin").write_bytes(b"standalone-1")
    (tmp_path / "s2.bin").write_bytes(b"standalone-2")
    db_path = tmp_path / "vcoc.db"
    _add(db_path, tmp_path / "s1.bin", "A-SOLO")
    _add(db_path, tmp_path / "bfolder", "B-BATCH")
    _add(db_path, tmp_path / "s2.bin", "C-SOLO")
    _add(db_path, tmp_path / "dfolder", "D-BATCH")
    return str(db_path)


def _reference_root_text(db_path: str) -> str:
    idx = cli_module._load_evidence_index(db_path)
    fidx = cli_module._load_folder_index(db_path)
    tree, grouped = cli_module._build_main_tree(idx, fidx)
    lines = [f"Merkle root over {len(grouped)} evidence file(s)/folder(s): {tree.root}", ""]
    for node in build_tree_view(idx, fidx)["nodes"]:
        if node["children"]:
            lines.append(f"  {node['id']}  {node['root']}  ({len(node['children'])} files)")
        else:
            lines.append(f"  {node['id']}  {node['sha256']}")
    return "\n".join(lines)


def _reference_proof(db_path: str, evidence_id: str) -> dict:
    idx = cli_module._load_evidence_index(db_path)
    fidx = cli_module._load_folder_index(db_path)
    main_tree, grouped_ids = cli_module._build_main_tree(idx, fidx)
    rec = idx[evidence_id]
    folder_id = rec.get("folder_id")
    if folder_id:
        member_ids = fidx[folder_id]["member_ids"]
        leaves = [idx[eid]["sha256"] for eid in member_ids]
        local = member_ids.index(evidence_id)
        proof = build_nested_proof(MerkleTree(leaves), local, main_tree, grouped_ids.index(folder_id))
        leaf = leaves[local]
    else:
        proof = build_nested_proof(main_tree, grouped_ids.index(evidence_id), None, None)
        leaf = rec["sha256"]
    return {
        "evidence_id": evidence_id,
        "merkle_format": MERKLE_FORMAT,
        "leaf": leaf,
        "root": main_tree.root,
        "proof": nested_proof_to_dict(proof),
    }


def _run(func, **kwargs) -> tuple[str, int | None]:
    buf, code = io.StringIO(), None
    with contextlib.redirect_stdout(buf):
        try:
            func(argparse.Namespace(**kwargs))
        except SystemExit as exc:
            code = exc.code
    return buf.getvalue(), code


def test_group_leaves_matches_the_index_based_grouping(case_db):
    idx = cli_module._load_evidence_index(case_db)
    fidx = cli_module._load_folder_index(case_db)
    tree, grouped = cli_module._build_main_tree(idx, fidx)

    conn = db.connect(case_db)
    groups = db.group_leaves(conn)
    conn.close()

    assert [g[0] for g in groups] == grouped == ["A-SOLO", "B-BATCH", "C-SOLO", "D-BATCH"]
    assert [g[1] for g in groups] == tree.leaves
    assert [g[2] for g in groups] == [None, 3, None, 2]  # member counts for folders, None for standalone files


def test_merkle_root_output_is_identical_to_the_index_based_output(case_db):
    out, code = _run(cli_module.cmd_merkle_root, db=case_db)

    assert code is None
    assert out.strip() == _reference_root_text(case_db)


def test_merkle_proof_is_identical_for_every_evidence_id_and_verifies(case_db):
    idx = cli_module._load_evidence_index(case_db)
    assert len(idx) == 2 + 3 + 2  # 2 standalone files + 3 + 2 folder members

    for evidence_id in sorted(idx):
        out, code = _run(cli_module.cmd_merkle_proof, evidence_id=evidence_id, db=case_db, out=None)
        assert code is None, evidence_id
        got = json.loads(out)
        assert got == _reference_proof(case_db, evidence_id), evidence_id

        from vcoc.merkle import nested_proof_from_dict

        assert verify_nested_proof(got["leaf"], nested_proof_from_dict(got["proof"]), got["root"]), evidence_id


def test_merkle_proof_written_to_a_file_prints_the_same_confirmation(case_db, tmp_path):
    out_file = tmp_path / "proof.json"

    out, code = _run(cli_module.cmd_merkle_proof, evidence_id="B-BATCH/sub/b.txt", db=case_db, out=str(out_file))

    assert code is None
    assert out.strip() == f"Wrote proof -> {out_file}"
    assert json.loads(out_file.read_text(encoding="utf-8")) == _reference_proof(case_db, "B-BATCH/sub/b.txt")


def test_empty_and_missing_databases_report_exactly_as_before(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    missing = str(tmp_path / "nope.db")

    assert _run(cli_module.cmd_merkle_root, db=missing) == ("No evidence registered yet.\n", 1)
    assert _run(cli_module.cmd_merkle_proof, evidence_id="X", db=missing, out=None) == ("Unknown evidence id: X\n", 1)
    assert not Path(missing).exists()  # reading must not create the database

    empty = str(tmp_path / "empty.db")
    db.connect(empty).close()
    assert _run(cli_module.cmd_merkle_root, db=empty) == ("No evidence registered yet.\n", 1)


def test_unknown_evidence_id_reports_exactly_as_before(case_db):
    assert _run(cli_module.cmd_merkle_proof, evidence_id="NOPE", db=case_db, out=None) == (
        "Unknown evidence id: NOPE\n",
        1,
    )


def test_merkle_commands_never_load_the_whole_evidence_or_folder_index(case_db, monkeypatch):
    def boom(conn):
        raise AssertionError("must not load every row: use group_leaves / get_evidence / get_folder")

    monkeypatch.setattr(db, "load_evidence_index", boom)
    monkeypatch.setattr(db, "load_folder_index", boom)

    out, code = _run(cli_module.cmd_merkle_root, db=case_db)
    assert code is None and "Merkle root over 4 evidence file(s)/folder(s)" in out

    for evidence_id in ("A-SOLO", "B-BATCH/sub/b.txt", "D-BATCH/y.txt"):
        out, code = _run(cli_module.cmd_merkle_proof, evidence_id=evidence_id, db=case_db, out=None)
        assert code is None, evidence_id
        assert json.loads(out)["evidence_id"] == evidence_id
