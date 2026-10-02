"""Tests for verifier.py's evidence-index verification (re-hash, custody-log
cross-check, Merkle root) -- the standalone verifier's independent checks."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import cli as cli_module
from vcoc.merkle import verify_nested_proof
from verifier import (
    EvidenceCheckResult,
    merkle_root,
    sha256_hex,
    verify_evidence_index,
    verify_merkle_proof,
    verify_nested_proof as verifier_verify_nested_proof,
)


def test_verify_evidence_index_match_and_logged(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"hello")
    digest = sha256_hex(b"hello")
    index = {
        "EV001": {
            "original_filename": "a.bin",
            "sha256": digest,
            "source_path": str(f),
        }
    }
    entries = [{"evidence_id": "EV001", "index": 0}]

    results, root = verify_evidence_index(index, entries)
    assert len(results) == 1
    r = results[0]
    assert r.rehash_status == "match"
    assert r.logged_status == "logged"
    assert r.ok
    assert root == digest  # single-leaf tree: root == the leaf itself


def test_verify_evidence_index_logged_via_multi_evidence_event(tmp_path):
    """An evidence record covered only by a new-shape (evidence_ids) custody
    entry must be recognized as logged, not flagged NOT LOGGED."""
    f = tmp_path / "a.bin"
    f.write_bytes(b"hello")
    digest = sha256_hex(b"hello")
    index = {
        "EV001": {
            "original_filename": "a.bin",
            "sha256": digest,
            "source_path": str(f),
        }
    }
    entries = [{"evidence_ids": ["EV001", "EV002"], "index": 0}]

    results, _ = verify_evidence_index(index, entries)
    assert results[0].logged_status == "logged"


def test_verify_evidence_index_mismatch_detected(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"hello")
    index = {
        "EV001": {
            "original_filename": "a.bin",
            "sha256": sha256_hex(b"different"),
            "source_path": str(f),
        }
    }
    results, _ = verify_evidence_index(index, [])
    assert results[0].rehash_status == "MISMATCH"
    assert not results[0].ok


def _index_for(path: Path, sha256: str) -> dict:
    return {"EV001": {"original_filename": path.name, "sha256": sha256, "source_path": str(path)}}


def test_verify_evidence_index_rehash_does_not_read_whole_file_into_memory(tmp_path, monkeypatch):
    f = tmp_path / "a.bin"
    f.write_bytes(b"hello")

    def boom(self):
        raise AssertionError("re-hash must stream, not Path.read_bytes()")

    monkeypatch.setattr(Path, "read_bytes", boom)

    results, _ = verify_evidence_index(_index_for(f, sha256_hex(b"hello")), [{"evidence_id": "EV001"}])
    assert results[0].rehash_status == "match"


def test_verify_evidence_index_rehash_memory_is_bounded_for_large_file(tmp_path):
    import tracemalloc

    f = tmp_path / "big.bin"
    data = b"\x00" * (24 * 1024 * 1024)
    f.write_bytes(data)
    digest = sha256_hex(data)
    del data
    index = _index_for(f, digest)
    entries = [{"evidence_id": "EV001"}]

    tracemalloc.start()
    try:
        results, _ = verify_evidence_index(index, entries)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()

    assert results[0].rehash_status == "match"
    assert peak < 8 * 1024 * 1024


def test_verify_evidence_index_multi_chunk_file_mismatch_still_detected(tmp_path):
    f = tmp_path / "multi.bin"
    content = bytes(range(256)) * (3 * 4096 + 7)  # > 3 MiB and not a chunk multiple
    f.write_bytes(content)

    ok, _ = verify_evidence_index(_index_for(f, sha256_hex(content)), [{"evidence_id": "EV001"}])
    bad, _ = verify_evidence_index(_index_for(f, sha256_hex(content + b"x")), [{"evidence_id": "EV001"}])

    assert ok[0].rehash_status == "match"
    assert bad[0].rehash_status == "MISMATCH"


def test_verifier_module_stays_standalone_and_imports_nothing_from_vcoc():
    import subprocess

    repo = Path(__file__).resolve().parent.parent
    code = (
        "import sys; sys.path.insert(0, sys.argv[1]); import verifier; "
        "bad = [m for m in sys.modules if m == 'vcoc' or m.startswith('vcoc.')]; "
        "sys.exit(1 if bad else 0)"
    )
    assert subprocess.run([sys.executable, "-c", code, str(repo)]).returncode == 0


def test_verify_evidence_index_not_logged_flagged():
    index = {
        "EV001": {"original_filename": "a.bin", "sha256": "a" * 64, "source_path": ""},
    }
    results, _ = verify_evidence_index(index, [])
    assert results[0].logged_status == "NOT LOGGED"
    assert results[0].rehash_status == "no source_path recorded"
    assert not results[0].ok  # not logged fails ok even though rehash is benign


def test_verify_evidence_index_missing_file_not_treated_as_tamper():
    index = {
        "EV001": {
            "original_filename": "a.bin",
            "sha256": "a" * 64,
            "source_path": "/nonexistent/path/a.bin",
        }
    }
    entries = [{"evidence_id": "EV001"}]
    results, _ = verify_evidence_index(index, entries)
    assert results[0].rehash_status == "not found"
    assert results[0].ok  # not found + logged is not itself tamper


def test_verify_evidence_index_empty_index_no_root():
    results, root = verify_evidence_index({}, [])
    assert results == []
    assert root is None


def test_merkle_root_matches_two_leaf_hash_pairing():
    leaves = [sha256_hex(b"a"), sha256_hex(b"b")]
    root = merkle_root(leaves)
    expected = sha256_hex(bytes.fromhex(leaves[0]) + bytes.fromhex(leaves[1]))
    assert root == expected


def test_merkle_root_rejects_empty():
    import pytest

    with pytest.raises(ValueError):
        merkle_root([])


def test_verifier_own_nested_proof_verifies_degenerate_case():
    """verifier.py's own verify_nested_proof, independent of vcoc.merkle,
    must accept the same degenerate (no-folder) proof shape cli.py emits."""
    from vcoc.merkle import build_nested_proof, MerkleTree, nested_proof_to_dict

    tree = MerkleTree([sha256_hex(b"a"), sha256_hex(b"b"), sha256_hex(b"c")])
    proof = build_nested_proof(tree, 1, None, None)
    proof_dict = nested_proof_to_dict(proof)

    assert verifier_verify_nested_proof(tree.leaves[1], proof_dict, tree.root)


def test_verifier_own_nested_proof_verifies_two_hop_case():
    from vcoc.merkle import build_nested_proof, MerkleTree, nested_proof_to_dict

    folder_tree = MerkleTree([sha256_hex(b"x"), sha256_hex(b"y")])
    main_tree = MerkleTree([folder_tree.root, sha256_hex(b"z")])
    proof = build_nested_proof(folder_tree, 0, main_tree, 0)
    proof_dict = nested_proof_to_dict(proof)

    assert verifier_verify_nested_proof(folder_tree.leaves[0], proof_dict, main_tree.root)


def test_verifier_own_nested_proof_rejects_tampered_leaf():
    from vcoc.merkle import build_nested_proof, MerkleTree, nested_proof_to_dict

    tree = MerkleTree([sha256_hex(b"a"), sha256_hex(b"b"), sha256_hex(b"c")])
    proof = build_nested_proof(tree, 1, None, None)
    proof_dict = nested_proof_to_dict(proof)

    assert not verifier_verify_nested_proof(sha256_hex(b"not-the-real-leaf"), proof_dict, tree.root)


def test_verify_evidence_index_groups_folder_batch_into_single_root(tmp_path):
    """A folder-registered evidence set must recompute the same grouped root
    verifier.py and cli.py's _build_main_tree independently agree on."""
    monkey_cwd = tmp_path
    import os

    old_cwd = os.getcwd()
    os.chdir(monkey_cwd)
    try:
        folder = monkey_cwd / "batchdir"
        folder.mkdir()
        (folder / "a.txt").write_bytes(b"a-content")
        (folder / "b.txt").write_bytes(b"b-content")
        (monkey_cwd / "solo.bin").write_bytes(b"solo-content")

        import argparse

        cli_module.cmd_add_evidence(
            argparse.Namespace(
                file=str(folder),
                evidence_id="BATCH1",
                db="vcoc.db",
                private_key=None,
                actor=None,
            )
        )
        cli_module.cmd_add_evidence(
            argparse.Namespace(
                file=str(monkey_cwd / "solo.bin"),
                evidence_id="SOLO1",
                db="vcoc.db",
                private_key=None,
                actor=None,
            )
        )

        evidence_index = cli_module._load_evidence_index("vcoc.db")
        folder_index = cli_module._load_folder_index("vcoc.db")
        cli_tree, _ = cli_module._build_main_tree(evidence_index, folder_index)

        _, verifier_root = verify_evidence_index(evidence_index, [], folder_index=folder_index)
    finally:
        os.chdir(old_cwd)

    assert verifier_root == cli_tree.root


def test_verify_evidence_index_progress_reports_bytes_within_a_file(tmp_path):
    f = tmp_path / "big.bin"
    content = b"\x01" * (3 * 1024 * 1024 + 5)  # 3 full 1 MiB chunks + a tail
    f.write_bytes(content)
    calls = []

    verify_evidence_index(
        _index_for(f, sha256_hex(content)), [{"evidence_id": "EV001"}], progress=lambda *a: calls.append(a)
    )

    size = len(content)
    assert calls[0] == (1, 1, "EV001", 0, size)
    assert calls[-1] == (1, 1, "EV001", size, size)
    dones = [c[3] for c in calls]
    assert dones == sorted(set(dones))  # strictly increasing
    assert len(calls) == 5  # start + 4 chunks
    assert all(c[:3] == (1, 1, "EV001") and c[4] == size for c in calls)


def test_verify_evidence_index_progress_counts_all_records_but_skips_unhashed_ones(tmp_path):
    f = tmp_path / "a.bin"
    f.write_bytes(b"hello")
    index = {
        "EV000": {"original_filename": "x", "sha256": "a" * 64, "source_path": "/nonexistent/x"},
        "EV001": {"original_filename": "a.bin", "sha256": sha256_hex(b"hello"), "source_path": str(f)},
        "EV002": {"original_filename": "y", "sha256": "b" * 64, "source_path": ""},
    }
    calls = []

    results, _ = verify_evidence_index(index, [], progress=lambda *a: calls.append(a))

    assert [c[:3] for c in calls] == [(2, 3, "EV001")] * len(calls) and calls
    assert [r.rehash_status for r in results] == ["not found", "match", "no source_path recorded"]


def test_verify_evidence_index_progress_callback_exception_propagates(tmp_path):
    import pytest

    f = tmp_path / "a.bin"
    f.write_bytes(b"hello")

    def stop(*args):
        raise RuntimeError("stop")

    with pytest.raises(RuntimeError, match="stop"):
        verify_evidence_index(_index_for(f, sha256_hex(b"hello")), [], progress=stop)


def test_verifier_cli_progress_goes_to_stderr_and_stdout_is_untouched(tmp_path):
    import json
    import subprocess

    from vcoc.ecdsa_signer import generate_keypair, save_keypair
    from vcoc.hash_chain import HashChain

    signing_key, _ = generate_keypair()
    save_keypair(signing_key, tmp_path / "priv.pem", tmp_path / "pub.pem")
    chain = HashChain()
    chain.add_event(evidence_id="EV001", actor="a", action="collected", signing_key=signing_key)
    chain.save(tmp_path / "log.json")
    f = tmp_path / "a.bin"
    f.write_bytes(b"hello")
    (tmp_path / "idx.json").write_text(json.dumps(_index_for(f, sha256_hex(b"hello"))), encoding="utf-8")
    repo = Path(__file__).resolve().parent.parent

    r = subprocess.run(
        [
            sys.executable, str(repo / "verifier.py"),
            "--log", str(tmp_path / "log.json"),
            "--public-key", str(tmp_path / "pub.pem"),
            "--evidence-index", str(tmp_path / "idx.json"),
        ],
        capture_output=True,
        text=True,
    )

    assert r.returncode == 0
    assert "re-hashing" not in r.stdout
    assert "[1/1] re-hashing EV001" in r.stderr


def test_stderr_progress_on_a_tty_throttles_updates_and_always_ends_the_line(monkeypatch):
    import io

    import verifier

    class TTY(io.StringIO):
        def isatty(self):
            return True

    now = [0.0]
    monkeypatch.setattr(verifier.time, "monotonic", lambda: now[0])
    stream = TTY()
    report = verifier._stderr_progress(stream)

    report(1, 1, "EV001", 0, 100)  # start: always shown
    for done, t in ((10, 0.1), (20, 0.2)):
        now[0] = t
        report(1, 1, "EV001", done, 100)  # inside the throttle window: suppressed
    now[0] = 0.7
    report(1, 1, "EV001", 30, 100)  # window elapsed: shown
    now[0] = 0.71
    report(1, 1, "EV001", 100, 100)  # completion: always shown, ends the line

    out = stream.getvalue()
    assert out.count("\r") == 3
    assert out.count("\n") == 1 and out.endswith("\n")
    assert "100%" in out.splitlines()[-1]


_BOUNDARY_SIZES = [0, 1, 65_535, 65_536, 65_537, 1_048_575, 1_048_576, 1_048_577, 5 * 1_048_576 + 3]


@pytest.mark.parametrize("size", _BOUNDARY_SIZES)
def test_sha256_file_hex_exact_and_progress_monotonic_at_read_size_boundaries(tmp_path, size):
    from verifier import sha256_file_hex

    content = bytes(range(256)) * (size // 256) + bytes(range(size % 256))
    f = tmp_path / "b.bin"
    f.write_bytes(content)
    dones = []

    assert sha256_file_hex(f, on_chunk=dones.append) == sha256_hex(content)

    assert dones == sorted(set(dones))  # strictly increasing
    assert (dones[-1] if dones else 0) == size


def test_sha256_file_hex_tiny_file_does_not_allocate_a_big_buffer(tmp_path):
    import tracemalloc

    from verifier import sha256_file_hex

    f = tmp_path / "tiny.bin"
    f.write_bytes(b"x" * 300)

    tracemalloc.start()
    try:
        sha256_file_hex(f)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()

    assert peak < 256 * 1024


# --- Task 1f: piped progress is a summary every few seconds, not one stderr line per file ---------------------------
# On the real data (832,300 files) a piped run wrote 832,300 stderr lines; a log file is not where that belongs.


def _piped_report(monkeypatch):
    import io

    import verifier

    now = [0.0]
    monkeypatch.setattr(verifier.time, "monotonic", lambda: now[0])
    stream = io.StringIO()  # StringIO.isatty() is False: a pipe / log file
    return verifier._stderr_progress(stream), stream, now


def test_piped_progress_for_many_small_files_prints_the_first_and_the_last_not_every_one(monkeypatch):
    report, stream, now = _piped_report(monkeypatch)

    for i in range(1, 1001):
        report(i, 1000, f"EV{i:04d}", 0, 100)  # start of each file, all within the same instant
        report(i, 1000, f"EV{i:04d}", 100, 100)  # and its last chunk

    assert stream.getvalue().splitlines() == [
        "[1/1000] re-hashing EV0001 (100 B)",
        "[1000/1000] re-hashing EV1000 (100 B)",
    ]


def test_piped_progress_prints_a_summary_line_every_few_seconds(monkeypatch):
    report, stream, now = _piped_report(monkeypatch)

    for i in range(1, 101):
        now[0] = i * 0.5  # 50 s of work, 2 files per second
        report(i, 1000, f"EV{i:04d}", 0, 100)

    lines = stream.getvalue().splitlines()
    assert lines[0].startswith("[1/1000] re-hashing EV0001")
    assert 8 <= len(lines) <= 12  # one every ~5 s over 50 s, not 100
    assert all(l.startswith("[") and "re-hashing" in l for l in lines)


def test_piped_progress_always_names_a_big_file_even_inside_the_quiet_period(monkeypatch):
    report, stream, now = _piped_report(monkeypatch)

    report(1, 10, "EV0001", 0, 100)
    report(2, 10, "EV0002", 0, 100)  # small, same instant: skipped
    report(3, 10, "DISK.img", 0, 5 * 2**30)  # 5 GiB: a minutes-long step the reader should see

    assert stream.getvalue().splitlines() == [
        "[1/10] re-hashing EV0001 (100 B)",
        "[3/10] re-hashing DISK.img (5.0 GB)",
    ]


def test_piped_progress_prints_nothing_for_the_chunks_of_a_file(monkeypatch):
    report, stream, now = _piped_report(monkeypatch)
    report(1, 5, "EV0001", 0, 3 * 2**30)
    before = stream.getvalue()

    for done in range(1, 50):
        now[0] += 10
        report(1, 5, "EV0001", done * 2**26, 3 * 2**30)

    assert stream.getvalue() == before


def test_verifier_cli_with_many_files_writes_only_a_few_progress_lines_and_the_same_stdout(tmp_path):
    import json
    import subprocess

    from vcoc.ecdsa_signer import generate_keypair, save_keypair
    from vcoc.hash_chain import HashChain

    signing_key, _ = generate_keypair()
    save_keypair(signing_key, tmp_path / "priv.pem", tmp_path / "pub.pem")
    chain = HashChain()
    chain.add_event(evidence_ids=[f"EV{i:03d}" for i in range(60)], actor="a", action="collected", signing_key=signing_key)
    chain.save(tmp_path / "log.json")
    index = {}
    for i in range(60):
        f = tmp_path / f"f{i}.bin"
        f.write_bytes(f"file {i}".encode())
        index[f"EV{i:03d}"] = {
            "evidence_id": f"EV{i:03d}", "original_filename": f.name, "sha256": sha256_hex(f"file {i}".encode()),
            "size_bytes": 7, "added_at": "t", "source_path": str(f), "folder_id": None,
        }
    (tmp_path / "idx.json").write_text(json.dumps(index), encoding="utf-8")
    repo = Path(__file__).resolve().parent.parent

    r = subprocess.run(
        [sys.executable, str(repo / "verifier.py"), "--log", str(tmp_path / "log.json"),
         "--public-key", str(tmp_path / "pub.pem"), "--evidence-index", str(tmp_path / "idx.json")],
        capture_output=True, text=True,
    )

    assert r.returncode == 0, r.stdout
    assert 1 <= len(r.stderr.splitlines()) <= 3  # the first and the last (and at most one timed line), not 60
    assert r.stderr.splitlines()[0].startswith("[1/60] re-hashing EV000")
    assert r.stderr.splitlines()[-1].startswith("[60/60] re-hashing EV059")
    assert "re-hashing" not in r.stdout


# --- Task 12: a folder's members count as logged when the folder id itself is logged (batch-register) -------------


def _folder_fixture(tmp_path):
    f = tmp_path / "m.bin"
    f.write_bytes(b"member")
    digest = sha256_hex(b"member")
    index = {
        "F1/m.bin": {"original_filename": "m.bin", "sha256": digest, "source_path": str(f), "folder_id": "F1"},
    }
    folder_index = {"F1": {"root": digest, "member_ids": ["F1/m.bin"]}}
    return index, folder_index


def test_folder_member_is_logged_when_its_folder_id_is_logged(tmp_path):
    index, folder_index = _folder_fixture(tmp_path)
    results, _ = verify_evidence_index(index, [{"evidence_id": "F1", "index": 0}], folder_index=folder_index)
    assert results[0].logged_status == "logged (via folder F1)"
    assert results[0].ok


def test_folder_member_is_not_logged_when_nothing_logs_it_or_its_folder(tmp_path):
    index, folder_index = _folder_fixture(tmp_path)
    results, _ = verify_evidence_index(index, [{"evidence_id": "OTHER", "index": 0}], folder_index=folder_index)
    assert results[0].logged_status == "NOT LOGGED"
    assert not results[0].ok


def test_folder_id_in_the_log_does_not_cover_a_member_whose_folder_is_unknown(tmp_path):
    index, _ = _folder_fixture(tmp_path)  # no folder_index: the claim "folder_id=F1" cannot be checked
    index["F1"] = dict(index["F1/m.bin"], folder_id=None)  # a standalone record that merely shares the id
    results, _ = verify_evidence_index(index, [{"evidence_id": "F1/m.bin_x", "index": 0}], folder_index={})
    assert {r.evidence_id: r.logged_status for r in results}["F1/m.bin"] == "NOT LOGGED"
    results, _ = verify_evidence_index(index, [{"evidence_id": "F1", "index": 0}], folder_index={})
    assert {r.evidence_id: r.logged_status for r in results}["F1/m.bin"] == "NOT LOGGED"


def test_own_log_entry_wins_over_the_folder_one(tmp_path):
    index, folder_index = _folder_fixture(tmp_path)
    entries = [{"evidence_id": "F1", "index": 0}, {"evidence_ids": ["F1/m.bin"], "index": 1}]
    results, _ = verify_evidence_index(index, entries, folder_index=folder_index)
    assert results[0].logged_status == "logged"
