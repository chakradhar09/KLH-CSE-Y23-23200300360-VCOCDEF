"""Pure data-shaping shared by verify-chain's CLI output and the interactive
Verification screen.

Takes already-loaded evidence_index/folder_index/custody_log data (no file
I/O here -- callers load and pass in, same separation store_bridge.py uses)
and returns plain, normalized dict/list/text structures both display
surfaces render from, so they never drift apart.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .merkle import MerkleTree

if TYPE_CHECKING:
    from .hash_chain import EntryVerification


def build_chain_view(entries: list[dict]) -> list[dict]:
    """Normalize custody log entries (legacy or new-shape) into one
    consistent per-entry shape for the chain diagram: evidence_ids is
    always a list, case_number/tag/notes are always present (None if unset).
    """
    view = []
    for entry in entries:
        evidence_ids = entry["evidence_ids"] if "evidence_ids" in entry else [entry["evidence_id"]]
        view.append(
            {
                "index": entry["index"],
                "evidence_ids": evidence_ids,
                "actor": entry["actor"],
                "action": entry["action"],
                "timestamp": entry["timestamp"],
                "prev_hash": entry["prev_hash"],
                "entry_hash": entry["entry_hash"],
                "signature": entry.get("signature", ""),
                "case_number": entry.get("case_number"),
                "tag": entry.get("tag"),
                "notes": entry.get("notes"),
            }
        )
    return view


def format_entry_summaries(chain_view: list[dict]) -> list[str]:
    """One line per normalized chain-view entry (see build_chain_view): all
    evidence_ids it covers, plus case_number/tag/notes when present --
    legacy single-evidence_id entries stay a single plain line, no
    empty-field clutter. Shared by cli.py's verify-chain output and the
    interactive shell's Verification screen, so the two never drift apart.
    """
    lines = []
    for entry in chain_view:
        eids = ", ".join(entry["evidence_ids"])
        target = eids if len(entry["evidence_ids"]) > 1 else entry["evidence_ids"][0]
        if len(entry["evidence_ids"]) > 1:
            target = f"[{target}]"
        line = f"#{entry['index']} {entry['action']} on {target} by {entry['actor']}"
        extras = [
            f"{key}={entry[key]}" for key in ("case_number", "tag", "notes") if entry.get(key)
        ]
        if extras:
            line += "  (" + ", ".join(extras) + ")"
        lines.append(line)
    return lines


def format_entry_detail_lines(entry: dict, verification: "EntryVerification | None" = None) -> list[str]:
    """Multi-line rich detail for one chain-view entry: the summary line,
    both hashes in full, a truncated signature, and (when a per-entry
    HashChain.verify_each() result is supplied) an OK/TAMPER status line.
    Shared by cli.py's verify-chain output and the interactive shell's
    Verification screen Chain tab, so the two show identical detail.
    """
    lines = list(format_entry_summaries([entry]))
    lines.append(f"  entry_hash: {entry['entry_hash']}")
    lines.append(f"  prev_hash:  {entry['prev_hash']}")
    signature = entry.get("signature") or ""
    if signature:
        lines.append(f"  signature:  {signature[:16]}...")
    if verification is not None:
        status = "OK" if verification.ok else "TAMPER"
        lines.append(f"  status: {status} ({verification.reason})")
    return lines


def build_tree_view(evidence_index: dict, folder_index: dict) -> dict:
    """Group evidence_index records by folder_id (or their own id if solo)
    -- the same grouping cli.py's _build_main_tree performs -- and return a
    nested {root, nodes: [{id, root|sha256, children: [...]}]} shape. A
    folder batch's member files nest as children under one top-level node,
    matching the same fan-out mental model folder-batches and multi-evidence
    custody events share.
    """
    if not evidence_index:
        return {"root": None, "nodes": []}

    grouped_ids = sorted({rec.get("folder_id") or eid for eid, rec in evidence_index.items()})
    leaves = []
    nodes = []
    for gid in grouped_ids:
        if gid in folder_index:
            leaves.append(folder_index[gid]["root"])
            member_ids = folder_index[gid]["member_ids"]
            children = [
                {
                    "id": mid,
                    "sha256": evidence_index[mid]["sha256"],
                    "original_filename": evidence_index[mid].get("original_filename", ""),
                    "children": [],
                }
                for mid in member_ids
            ]
            nodes.append({"id": gid, "root": folder_index[gid]["root"], "children": children})
        else:
            leaves.append(evidence_index[gid]["sha256"])
            nodes.append(
                {
                    "id": gid,
                    "sha256": evidence_index[gid]["sha256"],
                    "original_filename": evidence_index[gid].get("original_filename", ""),
                    "children": [],
                }
            )

    tree = MerkleTree(leaves)
    return {"root": tree.root, "nodes": nodes}
