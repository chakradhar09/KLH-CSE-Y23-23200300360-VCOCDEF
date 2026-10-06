"""Task 5 (opt-in): parallel hashing with a process pool. Off by default; results must equal the sequential ones."""

from __future__ import annotations

import argparse
import hashlib
import multiprocessing
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import cli as cli_module
import verifier
from vcoc import hashing


def _files(tmp_path: Path, n: int = 30) -> list[tuple[str, int]]:
    out = []
    for i in range(n):
        p = tmp_path / f"f{i:03d}.bin"
        p.write_bytes(bytes([i % 251]) * (i * 37))  # includes an empty file (i = 0)
        out.append((str(p), p.stat().st_size))
    return out


def _sha(path: str) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def test_default_jobs_is_one_and_follows_the_environment(monkeypatch):
    monkeypatch.delenv("VCOC_HASH_JOBS", raising=False)
    assert hashing.default_jobs() == 1
    monkeypatch.setenv("VCOC_HASH_JOBS", "4")
    assert hashing.default_jobs() == 4
    monkeypatch.setenv("VCOC_HASH_JOBS", "banana")
    assert hashing.default_jobs() == 1
    monkeypatch.setenv("VCOC_HASH_JOBS", "0")
    assert hashing.default_jobs() == 1


@pytest.mark.parametrize(
    "env, count, cpus, expected",
    [
        ("3", 10, 32, 3),  # an explicit value wins for any file count
        ("banana", 400_000, 32, 1),  # garbage -> 1, like default_jobs
        ("0", 400_000, 32, 1),
        ("1", 400_000, 32, 1),  # VCOC_HASH_JOBS=1 is the off switch
        (None, 1_999, 32, 1),  # below PARALLEL_MIN_FILES a pool costs more than it saves
        (None, 2_000, 32, 8),  # capped at 8 workers
        (None, 2_000, 64, 8),
        (None, 2_000, 16, 8),  # exactly at the cap
        (None, 2_000, 8, 4),  # half the CPUs
        (None, 2_000, 4, 2),
        (None, 2_000, 2, 1),
        (None, 2_000, None, 1),  # os.cpu_count() can be None
    ],
)
def test_auto_jobs_picks_a_pool_size_from_env_file_count_and_cpus(monkeypatch, env, count, cpus, expected):
    if env is None:
        monkeypatch.delenv("VCOC_HASH_JOBS", raising=False)
    else:
        monkeypatch.setenv("VCOC_HASH_JOBS", env)
    monkeypatch.setattr(verifier.os, "cpu_count", lambda: cpus)
    assert verifier.auto_jobs(count) == expected


def test_units_cut_batches_by_file_count_and_by_bytes_and_isolate_big_files(monkeypatch):
    monkeypatch.setattr(hashing, "BATCH_FILES", 3)
    monkeypatch.setattr(hashing, "BATCH_BYTES", 100)
    monkeypatch.setattr(hashing, "BIG_FILE", 1000)
    entries = [(f"p{i}", 10) for i in range(7)] + [("big", 5000), ("a", 60), ("b", 60), ("c", 5)]

    units = list(hashing._units(iter(entries)))

    assert units == [["p0", "p1", "p2"], ["p3", "p4", "p5"], ["p6"], None, ["a", "b"], ["c"]]


def test_hash_files_returns_the_sequential_digests_in_input_order(tmp_path, monkeypatch):
    monkeypatch.setattr(hashing, "BATCH_FILES", 4)  # many batches, so the order really depends on the merge
    entries = _files(tmp_path)

    got = list(hashing.hash_files(iter(entries), jobs=2))

    assert got == [_sha(p) for p, _ in entries]


def test_hash_files_reports_an_unreadable_file_in_place_and_keeps_going(tmp_path):
    entries = _files(tmp_path, 6)
    entries.insert(3, (str(tmp_path / "missing.bin"), 10))

    got = list(hashing.hash_files(iter(entries), jobs=2))

    assert isinstance(got[3], OSError)
    assert [g for i, g in enumerate(got) if i != 3] == [_sha(p) for i, (p, _) in enumerate(entries) if i != 3]


def test_hash_files_leaves_big_files_to_the_caller(tmp_path, monkeypatch):
    monkeypatch.setattr(hashing, "BIG_FILE", 500)
    entries = _files(tmp_path, 20)  # sizes 0, 37, ... : files from 14 on are >= 500 bytes

    got = list(hashing.hash_files(iter(entries), jobs=2))

    for (path, size), g in zip(entries, got):
        assert (g is None) if size >= 500 else (g == _sha(path))


def test_closing_the_generator_stops_the_workers(tmp_path, monkeypatch):
    monkeypatch.setattr(hashing, "BATCH_FILES", 2)
    gen = hashing.hash_files(iter(_files(tmp_path, 40)), jobs=2)
    next(gen)
    gen.close()
    for child in multiprocessing.active_children():
        child.join(10)
    assert multiprocessing.active_children() == []


# --- folder ingest -------------------------------------------------------------------------------------------------


def _ingest(tmp_path, name, jobs, monkeypatch, progress=None, min_files=1):
    folder = tmp_path / "case"
    if not folder.exists():
        for i in range(25):
            (folder / f"d{i % 3}").mkdir(parents=True, exist_ok=True)
            (folder / f"d{i % 3}" / f"f{i:02d}.bin").write_bytes(bytes([i]) * (i * 50))
    monkeypatch.setattr(hashing, "PARALLEL_MIN_FILES", min_files)
    monkeypatch.setattr(hashing, "BATCH_FILES", 4)
    ns = argparse.Namespace(
        file=str(folder), evidence_id="B1", db=str(tmp_path / f"{name}.db"), private_key=None, actor=None, jobs=jobs
    )
    if progress is not None:
        ns.progress = progress
    cli_module.cmd_add_evidence(ns)
    return ns.db


def _snapshot(db_path):
    idx = cli_module._load_evidence_index(db_path)
    for rec in idx.values():
        rec.pop("added_at")
    return idx, cli_module._load_folder_index(db_path)


def test_parallel_ingest_gives_exactly_the_sequential_result(tmp_path, monkeypatch):
    seq = _ingest(tmp_path, "seq", 1, monkeypatch)
    par = _ingest(tmp_path, "par", 2, monkeypatch)

    assert _snapshot(par) == _snapshot(seq)


def test_parallel_ingest_can_be_turned_off_with_vcoc_hash_jobs_1(tmp_path, monkeypatch):
    # (Folder ingest used to be single-process unless asked: it now sizes its pool itself, and =1 is the off switch.)
    monkeypatch.setenv("VCOC_HASH_JOBS", "1")

    def boom(*a, **k):
        raise AssertionError("the process pool must not start when VCOC_HASH_JOBS=1")

    monkeypatch.setattr(hashing, "hash_files", boom)
    _ingest(tmp_path, "default", None, monkeypatch)


# --- folder ingest picks its workers by itself (same rule as the verification re-hash) ----------------------------------


@pytest.mark.parametrize(
    "env, count, cpus, expected",
    [
        ("3", 10, 32, 3),
        ("banana", 400_000, 32, 1),
        ("1", 400_000, 32, 1),
        (None, 1_999, 32, 1),
        (None, 2_000, 32, 8),
        (None, 2_000, 16, 8),
        (None, 2_000, 8, 4),
        (None, 2_000, 4, 2),
        (None, 2_000, 2, 1),
        (None, 2_000, None, 1),
    ],
)
def test_hashing_auto_jobs_follows_the_same_rule_as_the_verifier_and_the_two_copies_agree(monkeypatch, env, count, cpus, expected):
    if env is None:
        monkeypatch.delenv("VCOC_HASH_JOBS", raising=False)
    else:
        monkeypatch.setenv("VCOC_HASH_JOBS", env)
    monkeypatch.setattr(os, "cpu_count", lambda: cpus)  # one os module: both copies see it

    assert hashing.auto_jobs(count) == expected == verifier.auto_jobs(count)


def _pool_sizes(monkeypatch):
    sizes = []
    real = hashing.hash_files
    monkeypatch.setattr(hashing, "hash_files", lambda entries, jobs: sizes.append(jobs) or real(entries, jobs))
    return sizes


def test_folder_ingest_uses_the_pool_by_default_sized_from_the_cpus(tmp_path, monkeypatch):
    monkeypatch.delenv("VCOC_HASH_JOBS", raising=False)
    monkeypatch.setattr(os, "cpu_count", lambda: 8)
    sizes = _pool_sizes(monkeypatch)

    _ingest(tmp_path, "auto", None, monkeypatch)

    assert sizes == [4]


def test_an_explicit_jobs_beats_the_automatic_size(tmp_path, monkeypatch):
    monkeypatch.delenv("VCOC_HASH_JOBS", raising=False)
    monkeypatch.setattr(os, "cpu_count", lambda: 32)
    sizes = _pool_sizes(monkeypatch)

    _ingest(tmp_path, "explicit", 2, monkeypatch)

    assert sizes == [2]


def test_a_small_folder_stays_single_process_without_any_setting(tmp_path, monkeypatch):
    monkeypatch.delenv("VCOC_HASH_JOBS", raising=False)
    monkeypatch.setattr(os, "cpu_count", lambda: 32)
    sizes = _pool_sizes(monkeypatch)

    _ingest(tmp_path, "small", None, monkeypatch, min_files=2_000)  # the 25-file folder is far below the minimum

    assert sizes == []


def test_the_automatic_pool_gives_exactly_the_sequential_result(tmp_path, monkeypatch):
    monkeypatch.delenv("VCOC_HASH_JOBS", raising=False)
    monkeypatch.setattr(os, "cpu_count", lambda: 8)
    seq = _ingest(tmp_path, "seq", 1, monkeypatch)
    auto = _ingest(tmp_path, "auto", None, monkeypatch)

    assert _snapshot(auto) == _snapshot(seq)


def _worker_counts(tmp_path, monkeypatch, jobs, **kwargs):
    seen = []

    def hook(*args):
        pass

    hook.set_workers = seen.append
    _ingest(tmp_path, f"w{jobs}", jobs, monkeypatch, progress=hook, **kwargs)
    return seen


def test_ingest_reports_the_workers_it_really_uses_to_the_progress_hook(tmp_path, monkeypatch):
    assert _worker_counts(tmp_path, monkeypatch, 2) == [2]


def test_ingest_reports_one_worker_when_it_ran_single_process(tmp_path, monkeypatch):
    assert _worker_counts(tmp_path, monkeypatch, 1) == [1]
    assert _worker_counts(tmp_path, monkeypatch, 4, min_files=2_000) == [1]  # asked for 4, but the folder is too small


def test_a_plain_progress_function_without_set_workers_still_works_in_a_pooled_ingest(tmp_path, monkeypatch):
    calls = []
    _ingest(tmp_path, "plain", 2, monkeypatch, progress=lambda *a: calls.append(a))
    assert calls


def test_a_progress_hook_that_raises_cancels_a_parallel_ingest_cleanly(tmp_path, monkeypatch):
    class Stop(Exception):
        pass

    def hook(i, *a):
        if i == 10:
            raise Stop

    with pytest.raises(Stop):
        _ingest(tmp_path, "cancel", 2, monkeypatch, progress=hook)

    for child in multiprocessing.active_children():
        child.join(10)
    assert multiprocessing.active_children() == []
    assert not (tmp_path / "cancel.db").exists() or cli_module._load_evidence_index(str(tmp_path / "cancel.db")) == {}


# --- standalone verifier -------------------------------------------------------------------------------------------


def _index(tmp_path):
    index = {}
    for i in range(24):
        p = tmp_path / f"v{i:02d}.bin"
        p.write_bytes(bytes([i]) * (i * 20))
        sha = hashlib.sha256(p.read_bytes()).hexdigest()
        index[f"EV{i:02d}"] = {
            "original_filename": p.name,
            "sha256": sha if i != 5 else "0" * 64,  # EV05 is tampered
            "source_path": str(p) if i != 7 else str(tmp_path / "gone.bin"),  # EV07 is missing
            "size_bytes": i * 20,
        }
    index["EV99"] = {"original_filename": "x", "sha256": "a" * 64, "source_path": "", "size_bytes": 0}
    return index


def test_verifier_parallel_rehash_equals_sequential(tmp_path, monkeypatch):
    monkeypatch.setattr(verifier, "PARALLEL_MIN_FILES", 1)
    monkeypatch.setattr(verifier, "BATCH_FILES", 4)
    index = _index(tmp_path)
    entries = [{"evidence_ids": list(index), "index": 0}]

    seq, root_seq = verifier.verify_evidence_index(index, entries, jobs=1)
    par, root_par = verifier.verify_evidence_index(index, entries, jobs=2)

    assert par == seq and root_par == root_seq
    statuses = {r.evidence_id: r.rehash_status for r in par}
    assert statuses["EV05"] == "MISMATCH"
    assert statuses["EV07"] == "not found"
    assert statuses["EV99"] == "no source_path recorded"
    assert statuses["EV01"] == "match"


def test_verifier_parallel_still_reports_progress_per_file(tmp_path, monkeypatch):
    monkeypatch.setattr(verifier, "PARALLEL_MIN_FILES", 1)
    index = _index(tmp_path)
    seen = []

    verifier.verify_evidence_index(
        index, [], jobs=2, progress=lambda i, n, eid, done, total: seen.append((eid, done == 0))
    )

    started = [eid for eid, first in seen if first]
    assert started == [e for e, r in sorted(index.items()) if r["source_path"] and not r["source_path"].endswith("gone.bin")]


def test_verifier_cli_has_a_jobs_flag_and_the_module_stays_standalone():
    import subprocess

    out = subprocess.run([sys.executable, str(Path(verifier.__file__)), "--help"], capture_output=True, text=True).stdout
    assert "--jobs" in out
