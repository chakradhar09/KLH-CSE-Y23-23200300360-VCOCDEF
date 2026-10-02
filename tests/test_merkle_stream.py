"""Task M4: `merkle-proof` for a very large folder without holding the tree in memory.

Measured on a copy of the real database (two folders of ~416,000 files): the old command peaked at ~291 MiB (the folder's
member_ids as a list, a dict of every member's hash, a list of leaves, and a MerkleTree of hex strings, ~113 bytes per node)
and took ~1.9 s. The proof and the root must stay byte-identical, so MerkleTree is the reference here.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import sqlite3
import sys
import tracemalloc
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

import cli as cli_module
from vcoc import db
from vcoc.hashing import hash_bytes
from vcoc.merkle import MerkleTree, build_nested_proof, merkle_proof_stream, nested_proof_to_dict, proof_to_dict
from vcoc.models import Evidence


def _leaves(n: int) -> list[str]:
    return [hash_bytes(f"leaf-{i}".encode()) for i in range(n)]


# --- the streaming proof equals MerkleTree for every shape ------------------------------------------------------


@pytest.mark.parametrize("n", [*range(1, 34), 63, 64, 65, 100, 127, 128, 129, 1000, 1023, 1024, 1025])
def test_stream_proof_equals_merkle_tree_for_every_leaf(n):
    leaves = _leaves(n)
    tree = MerkleTree(leaves)
    keys = range(n) if n <= 70 else sorted({0, 1, 2, n // 2, n // 3, n - 3, n - 2, n - 1})

    for k in keys:
        index, leaf, proof, root = merkle_proof_stream(((i, v) for i, v in enumerate(leaves)), k)
        assert index == k and leaf == leaves[k]
        assert root == tree.root
        assert proof_to_dict(proof) == proof_to_dict(tree.get_proof(k)), (n, k)


def test_stream_proof_uses_the_first_match_like_list_index():
    leaves = _leaves(5)
    items = [("a", leaves[0]), ("b", leaves[1]), ("a", leaves[2]), ("c", leaves[3]), ("d", leaves[4])]

    index, leaf, _, _ = merkle_proof_stream(iter(items), "a")

    assert index == 0 and leaf == leaves[0]


def test_stream_proof_unknown_key_and_empty_input():
    with pytest.raises(KeyError):
        merkle_proof_stream(iter([("a", _leaves(1)[0])]), "zzz")
    with pytest.raises(ValueError):
        merkle_proof_stream(iter([]), "a")


def test_stream_proof_keeps_only_raw_levels_in_memory():
    leaves = _leaves(20_000)
    items = [(i, v) for i, v in enumerate(leaves)]  # the input itself is outside the measurement
    tracemalloc.start()
    try:
        merkle_proof_stream(iter(items), 777)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()

    assert peak < 1_000_000  # a MerkleTree of 20,000 leaves holds ~40,000 hex strings = ~4.5 MB


# --- streaming the member ids out of the stored JSON ------------------------------------------------------------

SAMPLES = [
    [],
    ["a"],
    ["EV001/a.txt", "EV001/sub/b.txt", "EV001/z"],
    ["quote\"d", "back\\slash", "new\nline", "tab\t", "éè café", "\U0001f600 emoji", "中文"],
    [f"F/{i:05d}/file {i}.bin" for i in range(500)],
]


def _chunks(data: bytes, size: int):
    return (data[i : i + size] for i in range(0, len(data), size))


@pytest.mark.parametrize("values", SAMPLES)
@pytest.mark.parametrize("dumps", [
    lambda v: json.dumps(v),
    lambda v: json.dumps(v, ensure_ascii=False),
    lambda v: json.dumps(v, separators=(",", ":"), ensure_ascii=False),  # what SQLite's json_group_array writes
    lambda v: json.dumps(v, indent=2),
    lambda v: "  " + json.dumps(v).replace(", ", " ,  ") + "\n",
])
@pytest.mark.parametrize("size", [1, 2, 3, 7, 64, 4096])
def test_json_string_array_streams_the_same_values_as_json_loads_at_any_chunk_size(values, dumps, size):
    data = dumps(values).encode("utf-8")  # splits land inside multi-byte characters and escapes

    assert list(db.iter_json_strings(_chunks(data, size))) == values


def test_json_string_array_rejects_garbage():
    with pytest.raises(ValueError):
        list(db.iter_json_strings(iter([b'["a", "unterminated'])))
    with pytest.raises(ValueError):
        list(db.iter_json_strings(iter([b'{"not": "an array"}'])))


# --- member leaves and group leaves from the database ------------------------------------------------------------


def _folder_db(tmp_path: Path, members: list[str], extra_rows=(), folder_id="F1") -> sqlite3.Connection:
    conn = db.connect(tmp_path / "m.db")
    evs = [
        Evidence(m, Path(m).name, hash_bytes(m.encode()), 1, "2026-01-01T00:00:00Z", "", folder_id) for m in members
    ]
    db.put_folder(conn, folder_id, "ef" * 32, members, evs)
    for e in extra_rows:
        db.put_evidence(conn, e)
    return conn


def test_iter_member_leaves_equals_member_ids_with_hashes_in_member_order(tmp_path):
    members = sorted([f"F1/{n}" for n in ("a.txt", "b/c.txt", "b/d.txt", "café.txt", "z")])
    conn = _folder_db(tmp_path, members)

    assert list(db.iter_member_leaves(conn, "F1")) == [(m, hash_bytes(m.encode())) for m in members]


def test_iter_member_leaves_skips_stale_rows_and_uses_the_stored_member_order(tmp_path):
    """A re-registration after a file was removed leaves its old evidence row (folder_id F1) outside member_ids."""
    members = ["F1/a", "F1/c", "F1/e"]
    stale = [
        Evidence("F1/b", "b", "bb" * 32, 1, "t", "", "F1"),  # not a member, sorts between members
        Evidence("F1/f", "f", "ff" * 32, 1, "t", "", "F1"),  # not a member, sorts after them
    ]
    conn = _folder_db(tmp_path, members, extra_rows=stale)

    assert [m for m, _ in db.iter_member_leaves(conn, "F1")] == members


def test_iter_member_leaves_falls_back_to_a_lookup_for_a_member_whose_row_has_another_folder_id(tmp_path):
    members = ["F1/a", "F1/b", "F1/c"]
    conn = _folder_db(tmp_path, members)
    conn.execute("UPDATE evidence SET folder_id = 'OTHER' WHERE evidence_id = 'F1/b'")
    conn.commit()

    assert [(m, h) for m, h in db.iter_member_leaves(conn, "F1")][1] == ("F1/b", hash_bytes(b"F1/b"))


def test_iter_member_leaves_with_a_missing_folder_or_member_row_raises_keyerror(tmp_path):
    conn = _folder_db(tmp_path, ["F1/a"])
    with pytest.raises(KeyError):
        list(db.iter_member_leaves(conn, "NOPE"))
    conn.execute("DELETE FROM evidence WHERE evidence_id = 'F1/a'")
    conn.commit()
    with pytest.raises(KeyError):
        list(db.iter_member_leaves(conn, "F1"))


def test_iter_member_leaves_without_incremental_blob_io_gives_the_same_leaves(tmp_path, monkeypatch):
    """Python 3.10 has no Connection.blobopen: the whole JSON is read at once there (more memory, same result)."""
    members = [f"F1/{i:04d}" for i in range(50)]
    conn = _folder_db(tmp_path, members)
    want = list(db.iter_member_leaves(conn, "F1"))

    monkeypatch.setattr(db, "_HAS_BLOBOPEN", False)

    assert list(db.iter_member_leaves(conn, "F1")) == want


def test_iter_group_leaves_equals_group_leaves_without_counts(tmp_path):
    conn = _folder_db(tmp_path, ["F1/a", "F1/b"])
    db.put_evidence(conn, Evidence("A-SOLO", "s", "11" * 32, 1, "t", "", None))
    db.put_evidence(conn, Evidence("Z-SOLO", "s", "22" * 32, 1, "t", "", None))

    assert list(db.iter_group_leaves(conn)) == [(g, leaf) for g, leaf, _ in db.group_leaves(conn, counts=False)]


# --- the command ------------------------------------------------------------------------------------------------


def _run_proof(db_path: str, evidence_id: str, out=None) -> tuple[str, int | None]:
    buf, code = io.StringIO(), None
    with contextlib.redirect_stdout(buf):
        try:
            cli_module.cmd_merkle_proof(argparse.Namespace(evidence_id=evidence_id, db=db_path, out=out))
        except SystemExit as exc:
            code = exc.code
    return buf.getvalue(), code


def _reference(db_path: str, evidence_id: str) -> dict:
    idx = cli_module._load_evidence_index(db_path)
    fidx = cli_module._load_folder_index(db_path)
    main_tree, grouped = cli_module._build_main_tree(idx, fidx)
    rec = idx[evidence_id]
    folder_id = rec.get("folder_id")
    if folder_id:
        member_ids = fidx[folder_id]["member_ids"]
        leaves = [idx[m]["sha256"] for m in member_ids]
        local = member_ids.index(evidence_id)
        proof = build_nested_proof(MerkleTree(leaves), local, main_tree, grouped.index(folder_id))
        leaf = leaves[local]
    else:
        proof = build_nested_proof(main_tree, grouped.index(evidence_id), None, None)
        leaf = rec["sha256"]
    return {"evidence_id": evidence_id, "leaf": leaf, "root": main_tree.root, "proof": nested_proof_to_dict(proof)}


def test_the_proof_is_byte_identical_to_the_old_output_with_stale_rows_unicode_and_odd_sizes(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    members = sorted([f"F1/{n}" for n in ("a", "b", "c", "d/e", "d/f", "gé", "h", "i", "j", "k", "l")])  # 11: odd
    stale = [Evidence("F1/bb", "bb", "bb" * 32, 1, "t", "", "F1")]
    conn = _folder_db(tmp_path, members, extra_rows=stale)
    for sid in ("A-SOLO", "M-SOLO", "Z-SOLO"):
        db.put_evidence(conn, Evidence(sid, "s", hash_bytes(sid.encode()), 1, "t", "", None))
    conn.close()
    path = str(tmp_path / "m.db")

    for evidence_id in [*members, "A-SOLO", "M-SOLO", "Z-SOLO"]:
        out, code = _run_proof(path, evidence_id)
        assert code is None, evidence_id
        assert out == json.dumps(_reference(path, evidence_id), indent=2) + "\n", evidence_id


def test_the_command_never_loads_the_folder_json_or_a_hash_dict(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _folder_db(tmp_path, [f"F1/{i:03d}" for i in range(40)]).close()

    def boom(*a, **k):
        raise AssertionError("loads every member at once")

    monkeypatch.setattr(db, "get_folder", boom)
    monkeypatch.setattr(db, "member_hashes", boom)
    monkeypatch.setattr(db, "load_folder_index", boom)
    monkeypatch.setattr(db, "load_evidence_index", boom)

    out, code = _run_proof(str(tmp_path / "m.db"), "F1/017")

    assert code is None and json.loads(out)["evidence_id"] == "F1/017"


def test_peak_memory_of_a_proof_in_a_100k_file_folder_is_a_few_megabytes(tmp_path, monkeypatch):
    """Python-level allocations only (tracemalloc): the old logic held ~450 bytes per member here."""
    monkeypatch.chdir(tmp_path)
    members = [f"BIG/dir{i // 500:04d}/file_{i:06d}.bin" for i in range(100_000)]
    conn = db.connect(tmp_path / "big.db")
    with conn:
        conn.executemany(
            "INSERT INTO evidence (evidence_id, original_filename, sha256, size_bytes, added_at, source_path, folder_id)"
            " VALUES (?,?,?,?,?,?,?)",
            [(m, Path(m).name, hash_bytes(m.encode()), 1, "t", "", "BIG") for m in members],
        )
        conn.execute("INSERT INTO folders (folder_id, root, member_ids) VALUES (?,?,?)", ("BIG", "cd" * 32, json.dumps(members)))
    conn.close()
    target = members[73_333]

    tracemalloc.start()
    try:
        out, code = _run_proof(str(tmp_path / "big.db"), target)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()

    got = json.loads(out)
    assert code is None and got["leaf"] == hash_bytes(target.encode())
    assert got["proof"]["subtree_root"] == MerkleTree([hash_bytes(m.encode()) for m in members]).root
    assert peak < 8 * 1024 * 1024  # before: 42.8 MiB at this size (measured; ~291 MiB peak at 416,000 files)
