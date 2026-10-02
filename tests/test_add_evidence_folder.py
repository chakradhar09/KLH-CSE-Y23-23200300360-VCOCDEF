"""Folder-mode add-evidence: recursive registration + the folders table."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import cli as cli_module
from vcoc import db
from vcoc.ecdsa_signer import generate_keypair, save_keypair
from vcoc.hash_chain import HashChain


def _ns(**kwargs) -> argparse.Namespace:
    defaults = dict(
        db=cli_module.DEFAULT_DB,
        private_key=None,
    )
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def _make_folder(tmp_path: Path) -> Path:
    folder = tmp_path / "evidence_folder"
    (folder / "sub").mkdir(parents=True)
    (folder / "a.txt").write_bytes(b"file-a")
    (folder / "b.txt").write_bytes(b"file-b")
    (folder / "sub" / "c.txt").write_bytes(b"file-c")
    return folder


def test_folder_registers_every_file_with_correct_folder_id(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    folder = _make_folder(tmp_path)
    ns = _ns(file=str(folder), evidence_id="BATCH1")

    cli_module.cmd_add_evidence(ns)

    index = cli_module._load_evidence_index(ns.db)
    assert len(index) == 3
    for eid, rec in index.items():
        assert eid.startswith("BATCH1/")
        assert rec["folder_id"] == "BATCH1"
    assert set(index.keys()) == {
        "BATCH1/a.txt",
        "BATCH1/b.txt",
        "BATCH1/sub/c.txt",
    }


def test_folder_writes_folder_index_with_root_and_members(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    folder = _make_folder(tmp_path)
    ns = _ns(file=str(folder), evidence_id="BATCH1")

    cli_module.cmd_add_evidence(ns)

    folder_index = cli_module._load_folder_index(ns.db)
    assert "BATCH1" in folder_index
    assert "root" in folder_index["BATCH1"]
    assert folder_index["BATCH1"]["member_ids"] == [
        "BATCH1/a.txt",
        "BATCH1/b.txt",
        "BATCH1/sub/c.txt",
    ]


def test_folder_reregistration_is_deterministic(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    folder = _make_folder(tmp_path)
    ns1 = _ns(file=str(folder), evidence_id="BATCH1", db="one.db")
    ns2 = _ns(file=str(folder), evidence_id="BATCH1", db="two.db")

    cli_module.cmd_add_evidence(ns1)
    cli_module.cmd_add_evidence(ns2)

    root1 = cli_module._load_folder_index("one.db")["BATCH1"]["root"]
    root2 = cli_module._load_folder_index("two.db")["BATCH1"]["root"]
    assert root1 == root2


def test_folder_skips_symlinks(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    folder = _make_folder(tmp_path)
    target = tmp_path / "outside.txt"
    target.write_bytes(b"outside")
    link = folder / "link.txt"
    try:
        link.symlink_to(target)
    except OSError:
        import pytest

        pytest.skip("symlinks not supported on this platform/permission level")

    ns = _ns(file=str(folder), evidence_id="BATCH1")
    cli_module.cmd_add_evidence(ns)

    index = cli_module._load_evidence_index(ns.db)
    assert "BATCH1/link.txt" not in index
    assert len(index) == 3  # only the 3 real files, symlink skipped


def test_empty_folder_raises_clear_error(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    empty = tmp_path / "empty_folder"
    empty.mkdir()
    ns = _ns(file=str(empty), evidence_id="BATCH1")

    with pytest.raises(SystemExit):
        cli_module.cmd_add_evidence(ns)


def test_folder_batch_logs_custody_event_when_keys_given(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    folder = _make_folder(tmp_path)
    signing_key, verifying_key = generate_keypair()
    save_keypair(signing_key, "private_key.pem", "public_key.pem")

    ns = _ns(file=str(folder), evidence_id="BATCH1", private_key="private_key.pem")
    cli_module.cmd_add_evidence(ns)

    chain = HashChain.load_db(db.connect(ns.db))
    assert len(chain.entries) == 1
    assert chain.entries[0].evidence_id == "BATCH1"
    assert chain.entries[0].action == "batch-register"
    ok, break_index, reason = chain.verify(verifying_key)
    assert ok, reason


def test_folder_batch_no_event_logged_without_keys(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    folder = _make_folder(tmp_path)
    ns = _ns(file=str(folder), evidence_id="BATCH1")

    cli_module.cmd_add_evidence(ns)  # must not crash

    assert HashChain.load_db(db.connect(ns.db)).entries == []


def test_single_file_add_evidence_unchanged(tmp_path, monkeypatch):
    """Existing single-file behavior must be identical: no folder_id set."""
    monkeypatch.chdir(tmp_path)
    f = tmp_path / "solo.bin"
    f.write_bytes(b"solo-file-contents")
    ns = _ns(file=str(f), evidence_id="EV001")

    cli_module.cmd_add_evidence(ns)

    index = cli_module._load_evidence_index(ns.db)
    assert index["EV001"]["folder_id"] is None
    assert cli_module._load_folder_index(ns.db) == {}


# --- Task 4 characterization: pins today's walk/skip/order/source_path behavior so the scandir rewrite cannot drift ---

_ORDERED = ["B.txt", "a b.txt", "a.txt", "sub-x.txt", "sub/c.txt", "sub/deep/d.txt", "sub/z.txt"]  # sorted by posix path


def _make_ordered_folder(tmp_path: Path) -> Path:
    folder = tmp_path / "ev"
    (folder / "sub" / "deep").mkdir(parents=True)
    for rel in _ORDERED:
        (folder / rel).write_bytes(f"content of {rel}".encode())
    return folder


def _members(db_path: str) -> dict:
    return cli_module._load_evidence_index(db_path)


def test_folder_characterization_order_root_stdout_and_source_paths(tmp_path, monkeypatch, capsys):
    import hashlib

    from vcoc.merkle import MerkleTree

    monkeypatch.chdir(tmp_path)
    folder = _make_ordered_folder(tmp_path)
    ns = _ns(file=str(folder), evidence_id="B1")

    cli_module.cmd_add_evidence(ns)

    leaves = [hashlib.sha256(f"content of {rel}".encode()).hexdigest() for rel in _ORDERED]
    folder_rec = cli_module._load_folder_index(ns.db)["B1"]
    assert folder_rec["member_ids"] == [f"B1/{rel}" for rel in _ORDERED]
    assert folder_rec["root"] == MerkleTree(leaves).root

    total = sum(len(f"content of {rel}") for rel in _ORDERED)
    expected = [f"Found 7 file(s) ({total} bytes) under {folder}"]
    expected += [f"[{i}/7] hashing {rel}" for i, rel in enumerate(_ORDERED, 1)]
    expected += [f"Registered folder B1: 7 file(s), subtree root={folder_rec['root']}"]
    assert capsys.readouterr().out.splitlines() == expected

    index = _members(ns.db)
    for rel, leaf in zip(_ORDERED, leaves):
        rec = index[f"B1/{rel}"]
        assert rec["sha256"] == leaf
        assert rec["size_bytes"] == len(f"content of {rel}")
        assert rec["original_filename"] == Path(rel).name
        assert rec["source_path"] == str((folder / rel).resolve())


def test_folder_characterization_relative_folder_path_gives_absolute_source_paths(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _make_ordered_folder(tmp_path)
    ns = _ns(file="ev", evidence_id="B1")

    cli_module.cmd_add_evidence(ns)

    rec = _members(ns.db)["B1/sub/c.txt"]
    assert rec["source_path"] == str((tmp_path / "ev" / "sub" / "c.txt").resolve())


def test_folder_characterization_skips_links_and_counts_them(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    folder = _make_ordered_folder(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "o.txt").write_bytes(b"outside")
    try:
        (folder / "file_link").symlink_to(outside / "o.txt")
        (folder / "broken_link").symlink_to(outside / "missing")
        (folder / "dir_link").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks not supported on this platform/permission level")
    ns = _ns(file=str(folder), evidence_id="B1")

    cli_module.cmd_add_evidence(ns)

    out = capsys.readouterr().out
    assert "Skipped 2 symlink/special entries." in out  # file_link + broken_link; the dir link is ignored silently
    ids = cli_module._load_folder_index(ns.db)["B1"]["member_ids"]
    assert ids == [f"B1/{rel}" for rel in _ORDERED]  # nothing under the linked directory was registered


def test_folder_characterization_junction_is_walked_and_its_files_resolve_to_the_target(tmp_path, monkeypatch):
    import subprocess

    if sys.platform != "win32":
        pytest.skip("junctions are Windows-only")
    monkeypatch.chdir(tmp_path)
    folder = _make_ordered_folder(tmp_path)
    target = tmp_path / "elsewhere"
    target.mkdir()
    (target / "j.txt").write_bytes(b"through the junction")
    made = subprocess.run(["cmd", "/c", "mklink", "/J", str(folder / "jn"), str(target)], capture_output=True)
    if made.returncode != 0:
        pytest.skip("cannot create a junction here")
    ns = _ns(file=str(folder), evidence_id="B1")

    cli_module.cmd_add_evidence(ns)

    rec = _members(ns.db)["B1/jn/j.txt"]
    assert rec["source_path"] == str((target / "j.txt").resolve())  # per-file resolve() follows the junction
    ids = cli_module._load_folder_index(ns.db)["B1"]["member_ids"]
    assert ids == [f"B1/{rel}" for rel in sorted([*_ORDERED, "jn/j.txt"])]


def test_folder_characterization_unreadable_file_is_skipped_and_rest_registered(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    folder = _make_ordered_folder(tmp_path)
    real_hash = cli_module.hash_file

    def flaky(path, *a, **kw):
        if Path(path).name == "a.txt":
            raise PermissionError("denied")
        return real_hash(path, *a, **kw)

    monkeypatch.setattr(cli_module, "hash_file", flaky)
    ns = _ns(file=str(folder), evidence_id="B1")

    cli_module.cmd_add_evidence(ns)

    out = capsys.readouterr().out
    assert "[3/7] hashing a.txt\n  skipped (denied)" in out
    ids = cli_module._load_folder_index(ns.db)["B1"]["member_ids"]
    assert ids == [f"B1/{rel}" for rel in _ORDERED if rel != "a.txt"]


# --- Task 4b: progress hook (library side) ----------------------------------------------------------------------


def test_progress_hook_reports_file_index_count_and_monotonic_folder_bytes(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    folder = _make_ordered_folder(tmp_path)
    (folder / "big.bin").write_bytes(b"\x05" * (2 * 1024 * 1024 + 7))  # several chunks in one file
    calls = []
    ns = _ns(file=str(folder), evidence_id="B1", progress=lambda *a: calls.append(a))

    cli_module.cmd_add_evidence(ns)

    rels = sorted([*_ORDERED, "big.bin"])
    sizes = {rel: (folder / rel).stat().st_size for rel in rels}
    total = sum(sizes.values())
    assert {c[0] for c in calls} == set(range(1, len(rels) + 1))
    assert all(c[1] == len(rels) and c[5] == total for c in calls)
    for i, rel in enumerate(rels, 1):
        mine = [c for c in calls if c[0] == i]
        assert all(c[2] == rel and c[3] == sizes[rel] for c in mine)
    dones = [c[4] for c in calls]
    assert dones == sorted(dones)  # never goes backwards across the whole folder
    assert calls[0][4] == 0 and dones[-1] == total
    big = [c[4] for c in calls if c[2] == "big.bin"]
    assert len(big) > 3 and big == sorted(set(big))  # one big file still reports within itself


def test_a_raising_progress_hook_aborts_before_anything_is_written(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    folder = _make_ordered_folder(tmp_path)
    signing_key, _ = generate_keypair()
    save_keypair(signing_key, "private_key.pem", "public_key.pem")

    class Cancel(Exception):
        pass

    def hook(i, n, rel, size, done, total):
        if i == 3:
            raise Cancel

    ns = _ns(file=str(folder), evidence_id="B1", private_key="private_key.pem", progress=hook)
    with pytest.raises(Cancel):
        cli_module.cmd_add_evidence(ns)

    assert cli_module._load_evidence_index(ns.db) == {}
    assert cli_module._load_folder_index(ns.db) == {}
    assert HashChain.load_db(db.connect(ns.db)).entries == []


# --- Task M1: streaming ingest (batched inserts in ONE transaction, incremental root, member_ids built in SQLite) ---


def _snapshot(db_path: str) -> dict:
    """Everything the ingest stores, with the JSON column decoded (text formatting is not part of the contract)."""
    conn = db.connect(db_path)
    try:
        return {
            "evidence": [tuple(r) for r in conn.execute("SELECT evidence_id, original_filename, sha256, size_bytes, source_path, folder_id FROM evidence ORDER BY evidence_id")],
            "folders": {r["folder_id"]: (r["root"], __import__("json").loads(r["member_ids"])) for r in conn.execute("SELECT * FROM folders")},
        }
    finally:
        conn.close()


def test_batch_size_does_not_change_what_is_stored(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    folder = _make_ordered_folder(tmp_path)
    cli_module.cmd_add_evidence(_ns(file=str(folder), evidence_id="B1", db="big.db"))
    monkeypatch.setattr(cli_module, "INGEST_BATCH_SIZE", 2)  # 7 files -> 4 flushes

    cli_module.cmd_add_evidence(_ns(file=str(folder), evidence_id="B1", db="small.db"))

    assert _snapshot("small.db") == _snapshot("big.db")
    assert _snapshot("small.db")["folders"]["B1"][1] == [f"B1/{rel}" for rel in _ORDERED]


def test_reregistering_keeps_old_rows_but_member_ids_lists_only_the_current_files(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    folder = _make_ordered_folder(tmp_path)
    ns = _ns(file=str(folder), evidence_id="B1")
    cli_module.cmd_add_evidence(ns)
    (folder / "sub" / "z.txt").unlink()

    cli_module.cmd_add_evidence(ns)

    snap = _snapshot(ns.db)
    assert snap["folders"]["B1"][1] == [f"B1/{rel}" for rel in _ORDERED if rel != "sub/z.txt"]
    assert "B1/sub/z.txt" in {row[0] for row in snap["evidence"]}  # today's behavior: the stale row stays


def test_cancel_after_batches_were_flushed_still_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    folder = _make_ordered_folder(tmp_path)
    monkeypatch.setattr(cli_module, "INGEST_BATCH_SIZE", 2)

    class Cancel(Exception):
        pass

    def hook(i, n, rel, size, done, total):
        if i == 6:  # three batches (4 files) are already inside the open transaction
            raise Cancel

    ns = _ns(file=str(folder), evidence_id="B1", progress=hook)
    with pytest.raises(Cancel):
        cli_module.cmd_add_evidence(ns)

    assert _snapshot(ns.db) == {"evidence": [], "folders": {}}


def test_a_hard_crash_mid_ingest_leaves_nothing_behind(tmp_path):
    import subprocess

    folder = _make_ordered_folder(tmp_path)
    script = (
        "import os, sys, argparse\n"
        f"sys.path.insert(0, {str(Path(__file__).resolve().parent.parent)!r})\n"
        "import cli\n"
        "cli.INGEST_BATCH_SIZE = 2\n"
        "def hook(i, n, rel, size, done, total):\n"
        "    if i == 6: os._exit(3)\n"
        f"cli.cmd_add_evidence(argparse.Namespace(file={str(folder)!r}, evidence_id='B1', db='crash.db', private_key=None, progress=hook))\n"
    )
    proc = subprocess.run([sys.executable, "-c", script], cwd=tmp_path, capture_output=True, text=True)

    assert proc.returncode == 3, proc.stderr
    assert _snapshot(str(tmp_path / "crash.db")) == {"evidence": [], "folders": {}}


def test_with_a_progress_hook_there_are_no_per_file_lines_on_stdout(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    folder = _make_ordered_folder(tmp_path)

    cli_module.cmd_add_evidence(_ns(file=str(folder), evidence_id="B1", progress=lambda *a: None))

    out = capsys.readouterr().out
    assert "hashing" not in out
    assert "Registered folder B1: 7 file(s), subtree root=" in out


def test_ingest_memory_grows_little_per_file(tmp_path, monkeypatch):
    """Today ~2.3 KB of Python objects per file (members, ids, leaves, walk tuples); streaming keeps only the walk list."""
    import tracemalloc

    monkeypatch.chdir(tmp_path)

    def peak_for(count: int) -> int:
        folder = tmp_path / f"f{count}"
        folder.mkdir()
        for i in range(count):
            (folder / f"file_{i:05d}.bin").write_bytes(b"x")
        ns = _ns(file=str(folder), evidence_id="M", db=f"m{count}.db", progress=lambda *a: None)
        tracemalloc.start()
        try:
            cli_module.cmd_add_evidence(ns)
            return tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()

    small, large = peak_for(500), peak_for(3000)

    assert (large - small) / 2500 < 450  # bytes per extra file


def test_ingest_memory_is_flat_in_the_number_of_files(tmp_path, monkeypatch):
    """M1 (parked item): the sorted walk list was ~0.4 KB per file; the walk now lives in a temp database on disk."""
    import tracemalloc

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli_module, "INGEST_BATCH_SIZE", 100)  # both sizes must be well past the (bounded) batches
    monkeypatch.setattr(cli_module, "WALK_BATCH_SIZE", 100)

    def peak_for(count: int, attempt: int) -> int:
        folder = tmp_path / f"g{count}_{attempt}"
        folder.mkdir()
        for i in range(count):
            (folder / f"file_{i:05d}.bin").write_bytes(b"x")
        ns = _ns(file=str(folder), evidence_id="M", db=f"g{count}_{attempt}.db", progress=lambda *a: None)
        tracemalloc.start()
        try:
            cli_module.cmd_add_evidence(ns)
            return tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()

    peak_for(200, 0)  # warm-up: first-use allocations (lazy imports, caches) are not per-file growth
    # min of two runs: a run can also carry a fixed ~400 KB of cyclic garbage from elsewhere, unrelated to the file count
    small = min(peak_for(1000, a) for a in (1, 2))
    large = min(peak_for(6000, a) for a in (1, 2))

    assert (large - small) / 5000 < 60  # bytes of Python heap per extra file


def test_ingest_order_is_plain_code_point_order_of_the_relative_paths(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    folder = tmp_path / "mix"
    names = ["b.txt", "Q.txt", "a_b.txt", "a-b.txt", "a/b.txt", "a.txt", "é.txt", "zü.txt", "中.txt", "Z/x.txt"]
    for n in names:
        (folder / n).parent.mkdir(parents=True, exist_ok=True)
        (folder / n).write_bytes(n.encode())

    cli_module.cmd_add_evidence(_ns(file=str(folder), evidence_id="M", progress=lambda *a: None))

    assert cli_module._load_folder_index(cli_module.DEFAULT_DB)["M"]["member_ids"] == [f"M/{n}" for n in sorted(names)]
