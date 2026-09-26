"""Pure-function tests for vcoc.visualize's data-shaping (chain view + tree
view) -- no HTML/SVG string building here, just the nested dict/list shapes
the renderer will template from."""

from __future__ import annotations

from vcoc.hash_chain import EntryVerification
from vcoc.visualize import build_chain_view, build_tree_view, format_entry_detail_lines, format_entry_summaries


def test_chain_view_empty_log_is_empty_list():
    assert build_chain_view([]) == []


def test_chain_view_legacy_entry_normalizes_to_single_element_list():
    entries = [
        {
            "index": 0,
            "evidence_id": "EV001",
            "actor": "J. Doe",
            "action": "collected",
            "timestamp": "2026-09-22T00:00:00+00:00",
            "prev_hash": "0" * 64,
            "entry_hash": "a" * 64,
        }
    ]
    view = build_chain_view(entries)
    assert len(view) == 1
    assert view[0]["evidence_ids"] == ["EV001"]
    assert view[0]["case_number"] is None
    assert view[0]["tag"] is None
    assert view[0]["notes"] is None
    assert view[0]["entry_hash"] == "a" * 64
    assert view[0]["prev_hash"] == "0" * 64


def test_chain_view_new_shape_entry_keeps_all_ids_and_fields():
    entries = [
        {
            "index": 0,
            "evidence_ids": ["EV001", "EV002"],
            "actor": "J. Doe",
            "action": "seized",
            "timestamp": "2026-09-22T00:00:00+00:00",
            "prev_hash": "0" * 64,
            "entry_hash": "a" * 64,
            "case_number": "C-001",
            "tag": "disk+memory",
            "notes": "seized together",
        }
    ]
    view = build_chain_view(entries)
    assert view[0]["evidence_ids"] == ["EV001", "EV002"]
    assert view[0]["case_number"] == "C-001"
    assert view[0]["tag"] == "disk+memory"
    assert view[0]["notes"] == "seized together"


def test_chain_view_preserves_order_for_multiple_entries():
    entries = [
        {
            "index": i,
            "evidence_id": f"EV{i:03d}",
            "actor": "J. Doe",
            "action": "collected",
            "timestamp": "2026-09-22T00:00:00+00:00",
            "prev_hash": "0" * 64,
            "entry_hash": "a" * 64,
        }
        for i in range(3)
    ]
    view = build_chain_view(entries)
    assert [v["index"] for v in view] == [0, 1, 2]


def test_format_entry_summaries_legacy_entry_no_clutter():
    view = build_chain_view(
        [
            {
                "index": 0,
                "evidence_id": "EV001",
                "actor": "J. Doe",
                "action": "collected",
                "timestamp": "t",
                "prev_hash": "0" * 64,
                "entry_hash": "a" * 64,
            }
        ]
    )
    lines = format_entry_summaries(view)
    assert lines == ["#0 collected on EV001 by J. Doe"]


def test_format_entry_summaries_multi_evidence_with_extras():
    view = build_chain_view(
        [
            {
                "index": 0,
                "evidence_ids": ["EV001", "EV002"],
                "actor": "J. Doe",
                "action": "seized",
                "timestamp": "t",
                "prev_hash": "0" * 64,
                "entry_hash": "a" * 64,
                "case_number": "C-001",
                "tag": "disk+memory",
            }
        ]
    )
    lines = format_entry_summaries(view)
    assert lines == ["#0 seized on [EV001, EV002] by J. Doe  (case_number=C-001, tag=disk+memory)"]


def test_format_entry_detail_lines_includes_both_hashes_and_truncated_signature():
    """Task 26: verify-chain's richer per-entry detail -- both hashes and a
    truncated signature, alongside the existing summary fields."""
    view = build_chain_view(
        [
            {
                "index": 0,
                "evidence_id": "EV001",
                "actor": "J. Doe",
                "action": "collected",
                "timestamp": "t",
                "prev_hash": "0" * 64,
                "entry_hash": "a" * 64,
                "signature": "b" * 128,
            }
        ]
    )
    lines = format_entry_detail_lines(view[0])
    joined = "\n".join(lines)
    assert "a" * 64 in joined  # entry_hash present in full
    assert "0" * 64 in joined  # prev_hash present in full
    assert "b" * 16 in joined  # truncated signature prefix present
    assert "b" * 128 not in joined  # but not the full untruncated signature


def test_format_entry_detail_lines_shows_ok_status_when_verification_passed():
    view = build_chain_view(
        [
            {
                "index": 0,
                "evidence_id": "EV001",
                "actor": "J. Doe",
                "action": "collected",
                "timestamp": "t",
                "prev_hash": "0" * 64,
                "entry_hash": "a" * 64,
                "signature": "b" * 128,
            }
        ]
    )
    lines = format_entry_detail_lines(view[0], verification=EntryVerification(index=0, ok=True, reason="ok"))
    joined = "\n".join(lines)
    assert "OK" in joined
    assert "TAMPER" not in joined


def test_format_entry_detail_lines_shows_tamper_status_and_reason_when_broken():
    view = build_chain_view(
        [
            {
                "index": 0,
                "evidence_id": "EV001",
                "actor": "J. Doe",
                "action": "collected",
                "timestamp": "t",
                "prev_hash": "0" * 64,
                "entry_hash": "a" * 64,
                "signature": "b" * 128,
            }
        ]
    )
    lines = format_entry_detail_lines(
        view[0],
        verification=EntryVerification(index=0, ok=False, reason="entry_hash does not match recomputed payload hash"),
    )
    joined = "\n".join(lines)
    assert "TAMPER" in joined
    assert "entry_hash does not match recomputed payload hash" in joined


def test_format_entry_detail_lines_no_verification_omits_status():
    view = build_chain_view(
        [
            {
                "index": 0,
                "evidence_id": "EV001",
                "actor": "J. Doe",
                "action": "collected",
                "timestamp": "t",
                "prev_hash": "0" * 64,
                "entry_hash": "a" * 64,
                "signature": "b" * 128,
            }
        ]
    )
    lines = format_entry_detail_lines(view[0])
    joined = "\n".join(lines)
    assert "OK" not in joined
    assert "TAMPER" not in joined


def test_tree_view_empty_index_is_empty_shape():
    tree = build_tree_view({}, {})
    assert tree == {"root": None, "nodes": []}


def test_tree_view_solo_files_no_folders():
    index = {
        "EV001": {"sha256": "a" * 64, "original_filename": "a.bin"},
        "EV002": {"sha256": "b" * 64, "original_filename": "b.bin"},
    }
    tree = build_tree_view(index, {})
    assert tree["root"] is not None
    assert len(tree["nodes"]) == 2
    ids = {n["id"] for n in tree["nodes"]}
    assert ids == {"EV001", "EV002"}
    for node in tree["nodes"]:
        assert node["children"] == []  # solo files: no fan-out


def test_tree_view_folder_batch_fans_out_to_member_files():
    index = {
        "BATCH1/a.txt": {"sha256": "a" * 64, "original_filename": "a.txt", "folder_id": "BATCH1"},
        "BATCH1/b.txt": {"sha256": "b" * 64, "original_filename": "b.txt", "folder_id": "BATCH1"},
        "EV001": {"sha256": "c" * 64, "original_filename": "c.bin"},
    }
    folder_index = {
        "BATCH1": {"root": "deadbeef" * 8, "member_ids": ["BATCH1/a.txt", "BATCH1/b.txt"]}
    }
    tree = build_tree_view(index, folder_index)

    node_ids = {n["id"] for n in tree["nodes"]}
    assert "BATCH1" in node_ids
    assert "EV001" in node_ids
    assert "BATCH1/a.txt" not in node_ids  # nested under BATCH1's children, not top-level

    batch_node = next(n for n in tree["nodes"] if n["id"] == "BATCH1")
    assert {c["id"] for c in batch_node["children"]} == {"BATCH1/a.txt", "BATCH1/b.txt"}
    assert batch_node["root"] == "deadbeef" * 8


def test_tree_view_matches_cli_grouped_root(tmp_path):
    """Cross-check: build_tree_view's root must equal cli.py's own
    _build_main_tree root over the same fixture data -- one mental model,
    no silent drift between what's verified and what's visualized."""
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    import cli as cli_module

    index = {
        "BATCH1/a.txt": {"sha256": "a" * 64, "original_filename": "a.txt", "folder_id": "BATCH1"},
        "BATCH1/b.txt": {"sha256": "b" * 64, "original_filename": "b.txt", "folder_id": "BATCH1"},
        "EV001": {"sha256": "c" * 64, "original_filename": "c.bin"},
    }
    from vcoc.merkle import MerkleTree

    subtree = MerkleTree(["a" * 64, "b" * 64])
    folder_index = {"BATCH1": {"root": subtree.root, "member_ids": ["BATCH1/a.txt", "BATCH1/b.txt"]}}

    cli_tree, _ = cli_module._build_main_tree(index, folder_index)
    tree = build_tree_view(index, folder_index)

    assert tree["root"] == cli_tree.root
