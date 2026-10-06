"""Rehash-speed Tasks 3-4: the shell's Evidence re-hash may use the process pool. It must give EXACTLY the serial result."""

from __future__ import annotations

import hashlib
import multiprocessing
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import verifier
from vcoc import db
from vcoc.ecdsa_signer import generate_keypair
from vcoc.hash_chain import HashChain
from vcoc.interactive import verification_screen as vs
from vcoc.models import Evidence


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _mixed_rows(tmp_path: Path, n: int = 60) -> str:
    """n folder rows cycling through: match, MISMATCH, not found, no source_path, match, match; plus a standalone unlogged
    file. Two rows are logged (one directly, one via its folder id), the rest are not."""
    conn = db.connect(tmp_path / "vcoc.db")
    members = []
    for i in range(n):
        data = bytes([i % 251]) * (i * 13 + 1)
        path = tmp_path / f"f{i:03d}.bin"
        path.write_bytes(data)
        kind = i % 6
        recorded = _sha(data) if kind != 1 else "00" * 32  # kind 1 is tampered
        source = {2: str(tmp_path / f"gone{i}.bin"), 3: ""}.get(kind, str(path))
        members.append(Evidence(f"F1/m{i:03d}", path.name, recorded, len(data), "2026-01-01T00:00:00Z", source, "F1"))
    db.put_folder(conn, "F1", "ef" * 32, [m.evidence_id for m in members], members)
    solo = tmp_path / "solo.bin"
    solo.write_bytes(b"solo")
    db.put_evidence(conn, Evidence("SOLO", "solo.bin", _sha(b"solo"), 4, "2026-01-01T00:00:00Z", str(solo), None))
    signing_key, _ = generate_keypair()
    chain = HashChain()
    chain.add_event(evidence_id="SOLO", actor="a", action="collected", signing_key=signing_key)
    chain.add_event(evidence_ids=["F1/m001", "F1/m002"], actor="a", action="seen", signing_key=signing_key)
    chain.save_db(conn)
    conn.close()
    return str(tmp_path / "vcoc.db")


@pytest.fixture
def small_batches(monkeypatch):
    """Pool on for any size of database, in several small batches so batching and ordering are really exercised."""
    monkeypatch.setattr(verifier, "PARALLEL_MIN_FILES", 1)
    monkeypatch.setattr(verifier, "BATCH_FILES", 7)


@pytest.fixture
def pool_calls(monkeypatch):
    calls = []
    real = verifier._rehash_parallel

    def spy(entries, jobs):
        calls.append(jobs)
        return real(entries, jobs)

    monkeypatch.setattr(verifier, "_rehash_parallel", spy)
    return calls


def _materialise(result):
    rows, details = result
    return list(rows), [list(d) for d in details]


def test_pool_result_equals_serial_result_for_every_kind_of_row(tmp_path, small_batches, pool_calls):
    path = _mixed_rows(tmp_path)

    serial = _materialise(vs._run_evidence_check(db_path=path, jobs=1))
    assert pool_calls == []  # jobs=1 never starts a pool
    pooled = _materialise(vs._run_evidence_check(db_path=path, jobs=2))

    assert pool_calls == [2]
    assert pooled == serial
    shown = "\n".join(line for d in pooled[1] for line in d)
    for status in ("re-hash: match", "re-hash: MISMATCH", "re-hash: not found", "re-hash: no source_path recorded"):
        assert status in shown
    assert "custody log: NOT LOGGED" in shown and "custody log: logged" in shown


def test_pool_is_not_used_below_the_minimum_file_count(tmp_path, monkeypatch, pool_calls):
    path = _mixed_rows(tmp_path)  # 61 rows, and the real threshold is 2,000

    vs._run_evidence_check(db_path=path, jobs=4)

    assert pool_calls == []


def test_jobs_none_asks_auto_jobs_with_the_evidence_count(tmp_path, monkeypatch, small_batches, pool_calls):
    path = _mixed_rows(tmp_path)
    asked = []
    monkeypatch.setattr(verifier, "auto_jobs", lambda count: asked.append(count) or 2)

    vs._run_evidence_check(db_path=path)

    assert asked == [61] and pool_calls == [2]


def test_env_jobs_1_keeps_the_default_run_serial(tmp_path, monkeypatch, small_batches, pool_calls):
    path = _mixed_rows(tmp_path)
    monkeypatch.setenv("VCOC_HASH_JOBS", "1")

    vs._run_evidence_check(db_path=path)

    assert pool_calls == []


def test_pool_reports_progress_once_per_hashed_file_in_row_order_like_serial(tmp_path, small_batches):
    path = _mixed_rows(tmp_path)
    serial_starts, pool_seen = [], []

    def serial_progress(i, n, eid, done, total):
        if done == 0:  # serial reports the start of a file, then every chunk
            serial_starts.append((i, n, eid))

    vs._run_evidence_check(db_path=path, jobs=1, progress=serial_progress)
    vs._run_evidence_check(db_path=path, jobs=2, progress=lambda i, n, eid, done, total: pool_seen.append((i, n, eid, done, total)))

    assert len(serial_starts) == 41  # 4 of every 6 folder rows are real files (40 of 60), plus SOLO
    assert [(i, n, eid) for i, n, eid, _, _ in pool_seen] == serial_starts  # same files, same positions, same order
    assert all(done == total for _, _, _, done, total in pool_seen)  # one call at the end of each file


def test_pool_run_holds_no_read_lock_on_the_database_while_hashing(tmp_path, small_batches):
    path = _mixed_rows(tmp_path, n=120)
    paused, release = threading.Event(), threading.Event()

    def stall(i, n, evidence_id, done, total):
        if i >= 60:
            paused.set()
            release.wait(30)

    worker = threading.Thread(target=lambda: vs._run_evidence_check(db_path=path, jobs=2, progress=stall))
    worker.start()
    try:
        assert paused.wait(30), "the pooled check never reached the stall point"
        start = time.perf_counter()
        db.connect(path).close()
        rows, _ = vs._run_merkle_check(db_path=path)
        assert time.perf_counter() - start < 2.0
        assert rows[0].startswith("Root over")
    finally:
        release.set()
        worker.join(30)
    assert multiprocessing.active_children() == []


# --- Task 4: cancel, error and big-file behaviour must not change with the pool ----------------------------------------


def _no_workers_left(timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while multiprocessing.active_children() and time.monotonic() < deadline:
        time.sleep(0.05)
    return multiprocessing.active_children() == []


def test_a_progress_hook_that_raises_cancels_a_pooled_check_and_stops_every_worker(tmp_path, small_batches):
    path = _mixed_rows(tmp_path, n=120)
    calls = []

    def hook(*args):
        calls.append(args)
        if len(calls) == 3:
            raise vs._Cancelled

    with pytest.raises(vs._Cancelled):
        vs._run_evidence_check(db_path=path, jobs=2, progress=hook)

    assert len(calls) == 3  # nothing is reported after the cancel
    assert multiprocessing.active_children() == []  # stopped before the cancel left the call, not eventually by the GC


def test_cancelling_a_pooled_background_load_drops_its_result_and_stops_the_thread_and_workers(tmp_path, small_batches):
    path = _mixed_rows(tmp_path, n=120)
    started, proceed, published = threading.Event(), threading.Event(), []
    bg = vs._BackgroundLoad(lambda: None, published.append)

    def load(progress):
        def hook(*args):
            started.set()
            proceed.wait(30)  # hold the first file until the screen has been closed
            progress(*args)  # superseded by now: raises _Cancelled

        return vs._run_evidence_check(progress=hook, db_path=path, jobs=2)

    bg.start(load)
    assert started.wait(30)
    bg.cancel()
    proceed.set()
    deadline = time.monotonic() + 10
    while any(t.name == "vcoc-bgload" and t.is_alive() for t in threading.enumerate()) and time.monotonic() < deadline:
        time.sleep(0.05)

    assert not any(t.name == "vcoc-bgload" and t.is_alive() for t in threading.enumerate())
    assert published == [] and not bg.loading
    assert _no_workers_left()


def test_a_file_that_is_not_simply_missing_raises_the_same_error_with_and_without_the_pool(tmp_path, small_batches):
    path = _mixed_rows(tmp_path)
    conn = db.connect(path)
    with conn:
        conn.execute("UPDATE evidence SET source_path = ? WHERE evidence_id = 'F1/m030'", (str(tmp_path),))  # a directory
    conn.close()

    with pytest.raises(OSError) as serial:
        vs._run_evidence_check(db_path=path, jobs=1)
    with pytest.raises(OSError) as pooled:
        vs._run_evidence_check(db_path=path, jobs=2)

    assert type(pooled.value) is type(serial.value)
    assert _no_workers_left()


def test_a_pooled_load_turns_that_error_into_the_same_error_row_as_a_serial_one(tmp_path, small_batches):
    path = _mixed_rows(tmp_path)
    conn = db.connect(path)
    with conn:
        conn.execute("UPDATE evidence SET source_path = ? WHERE evidence_id = 'F1/m030'", (str(tmp_path),))
    conn.close()
    published = {}
    for jobs in (1, 2):
        done = threading.Event()
        bg = vs._BackgroundLoad(lambda: None, lambda result, jobs=jobs: published.update({jobs: result}) or done.set())
        bg.start(lambda progress, jobs=jobs: vs._run_evidence_check(progress=progress, db_path=path, jobs=jobs))
        assert done.wait(30)

    assert published[1][0][0].startswith("Error: ") and published[2] == published[1]


def test_big_files_are_hashed_by_the_caller_with_byte_level_progress_and_the_same_result(tmp_path, monkeypatch, small_batches):
    monkeypatch.setattr(verifier, "BIG_FILE", 300)  # rows 23+ (13 bytes per index) count as big
    path = _mixed_rows(tmp_path)
    starts = []

    def hook(i, n, eid, done, total):
        if done == 0:  # the pool only reports a file when it is finished; a start event means the caller hashed it
            starts.append(eid)

    pooled = _materialise(vs._run_evidence_check(db_path=path, jobs=2, progress=hook))
    serial = _materialise(vs._run_evidence_check(db_path=path, jobs=1))

    assert pooled == serial
    assert starts == [f"F1/m{i:03d}" for i in range(60) if i % 6 in (0, 1, 4, 5) and i * 13 + 1 >= 300]


def test_cancelling_a_big_pooled_check_returns_promptly(tmp_path, small_batches, monkeypatch):
    monkeypatch.setattr(verifier, "BATCH_FILES", 500)  # the real batch size
    conn = db.connect(tmp_path / "big.db")
    real = tmp_path / "one.bin"
    real.write_bytes(b"x" * 100)
    members = [Evidence(f"F/{i:05d}", "one.bin", _sha(b"x" * 100), 100, "2026-01-01T00:00:00Z", str(real), "F") for i in range(5000)]
    db.put_folder(conn, "F", "ef" * 32, [m.evidence_id for m in members], members)
    conn.close()
    cancelled_at = []

    def hook(*args):
        cancelled_at.append(time.perf_counter())
        raise vs._Cancelled

    with pytest.raises(vs._Cancelled):
        vs._run_evidence_check(db_path=str(tmp_path / "big.db"), jobs=2, progress=hook)

    assert time.perf_counter() - cancelled_at[0] < 2.0  # one in-flight batch of tiny files, not the whole 5,000
    assert multiprocessing.active_children() == []


# --- Task 8: the check tells the progress hook how many workers it really used ----------------------------------------


def _workers_reported(path, **kwargs):
    seen = []

    def hook(*args):
        pass

    hook.set_workers = seen.append
    vs._run_evidence_check(db_path=path, progress=hook, **kwargs)
    return seen


def test_the_check_reports_the_pool_size_it_used(tmp_path, small_batches):
    assert _workers_reported(_mixed_rows(tmp_path), jobs=3) == [3]


def test_the_check_reports_one_worker_when_it_ran_serially(tmp_path, small_batches):
    assert _workers_reported(_mixed_rows(tmp_path), jobs=1) == [1]


def test_the_check_reports_one_worker_below_the_minimum_file_count_even_if_more_were_asked_for(tmp_path):
    assert _workers_reported(_mixed_rows(tmp_path), jobs=4) == [1]  # 61 rows, and the real threshold is 2,000


def test_a_real_pooled_check_shows_its_worker_count_and_rate_in_the_loaders_sidebar_text(tmp_path, small_batches):
    path = _mixed_rows(tmp_path)
    held, release = threading.Event(), threading.Event()
    bg = vs._BackgroundLoad(lambda: None)

    def load(progress):
        def hook(*args):
            progress(*args)  # the loader's own hook: records the progress, and carries set_workers on its attribute
            held.set()
            release.wait(30)  # stay mid-run so the sidebar can be read

        hook.set_workers = progress.set_workers
        return vs._run_evidence_check(progress=hook, db_path=path, jobs=3)

    bg.start(load)
    try:
        assert held.wait(30)
        shown = ""
        for _ in range(100):  # the (coarse) clock must tick once before a rate exists
            shown = bg.screen_text()
            if "files/s" in shown:
                break
            threading.Event().wait(0.02)
        assert any(line.startswith("  3 workers  ") and line.endswith(" files/s") for line in shown.split("\n")), shown
    finally:
        release.set()
        bg.cancel()


def test_a_plain_progress_function_without_the_hook_still_works(tmp_path, small_batches):
    calls = []
    vs._run_evidence_check(db_path=_mixed_rows(tmp_path), jobs=2, progress=lambda *a: calls.append(a))
    assert calls  # no set_workers attribute: nothing to report to, nothing breaks


# --- Task 5: the interactive shell's Evidence tab picks the pool by itself ---------------------------------------------


def _open_evidence_tab_in_the_shell(monkeypatch, tmp_path):
    """Drives the real Verification screen headless: tab 2 (Evidence), waits for its re-hash to finish, then quits."""
    from test_interactive_verification_screen import _drive_verification_screen

    finished = threading.Event()
    real = vs._run_evidence_check

    def watched(**kwargs):
        try:
            return real(**kwargs)
        finally:
            finished.set()

    monkeypatch.setattr(vs, "_run_evidence_check", watched)
    _drive_verification_screen(
        monkeypatch, tmp_path, "2", followup=lambda pipe: (finished.wait(60), pipe.send_text("q"))
    )
    assert finished.is_set()


def test_the_shell_evidence_tab_uses_the_pool_by_default_on_a_big_enough_database(tmp_path, monkeypatch, small_batches, pool_calls):
    _mixed_rows(tmp_path)
    monkeypatch.delenv("VCOC_HASH_JOBS", raising=False)
    monkeypatch.setattr(verifier.os, "cpu_count", lambda: 32)

    _open_evidence_tab_in_the_shell(monkeypatch, tmp_path)

    assert pool_calls == [8]  # min(8, 32 // 2)


def test_the_shell_evidence_tab_stays_serial_when_vcoc_hash_jobs_is_1(tmp_path, monkeypatch, small_batches, pool_calls):
    _mixed_rows(tmp_path)
    monkeypatch.setenv("VCOC_HASH_JOBS", "1")
    monkeypatch.setattr(verifier.os, "cpu_count", lambda: 8)

    _open_evidence_tab_in_the_shell(monkeypatch, tmp_path)

    assert pool_calls == []


def test_the_shell_evidence_tab_stays_serial_on_a_small_database_without_any_setting(tmp_path, monkeypatch, pool_calls):
    _mixed_rows(tmp_path)  # 61 rows: far below PARALLEL_MIN_FILES
    monkeypatch.delenv("VCOC_HASH_JOBS", raising=False)
    monkeypatch.setattr(verifier.os, "cpu_count", lambda: 32)

    _open_evidence_tab_in_the_shell(monkeypatch, tmp_path)

    assert pool_calls == []
