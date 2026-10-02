"""Task 3: a reproducible folder-ingest benchmark in scripts/performance_scale.py.

Measured once by hand on the real 92,871-file folder (cProfile, 209.5 s): about half of the time was filesystem metadata
(6 stat calls per file, Path.resolve) rather than hashing. The benchmark makes that breakdown repeatable. The script's
existing output keys feed the research paper, so they are pinned here and must not change.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

import pytest

import performance_scale as ps

EXISTING_TRIAL_KEYS = {
    "evidence_count",
    "file_size_kb",
    "synthetic_data_generation_seconds",
    "hashing_seconds",
    "hashing_seconds_per_file",
    "merkle_build_seconds",
    "merkle_proof_generation_seconds",
    "merkle_proof_verification_seconds",
    "proof_verified",
    "proof_size_steps",
}


def test_existing_trial_output_keys_are_unchanged():
    assert set(ps.run_trial(3, 1)) == EXISTING_TRIAL_KEYS


def test_folder_ingest_trial_reports_where_the_time_goes():
    result = ps.run_folder_ingest_trial(20, 1)

    assert result["file_count"] == 20
    assert result["total_bytes"] == 20 * 1024
    for key in ("wall_seconds", "hash_seconds", "stat_seconds", "resolve_seconds", "db_write_seconds", "other_seconds"):
        assert result[key] >= 0, key
    assert result["hash_seconds"] > 0
    assert result["db_write_seconds"] > 0  # the streamed writes are timed (add_folder_members + finish_folder)
    assert result["stat_calls"] < 20  # Task 4: the scandir walk reuses cached stat, no Path.stat per file
    assert result["resolve_calls"] < 20  # ...and resolves the root once, not every path
    assert result["files_per_second"] > 0
    parts = sum(result[k] for k in ("hash_seconds", "stat_seconds", "resolve_seconds", "db_write_seconds"))
    assert result["other_seconds"] == pytest.approx(result["wall_seconds"] - parts, abs=1e-6)


def test_folder_ingest_trial_leaves_no_trace_and_restores_what_it_instrumented(tmp_path, monkeypatch):
    import cli
    from vcoc import db

    monkeypatch.chdir(tmp_path)
    originals = (Path.stat, Path.resolve, cli.hash_file, db.add_folder_members, db.finish_folder)

    ps.run_folder_ingest_trial(5, 1)

    assert (Path.stat, Path.resolve, cli.hash_file, db.add_folder_members, db.finish_folder) == originals
    assert list(tmp_path.iterdir()) == []  # temp directory only: nothing written to the cwd (e.g. no vcoc.db)


def test_folder_ingest_restores_the_instrumentation_even_when_the_ingest_fails(tmp_path):
    import cli

    original = cli.hash_file
    with pytest.raises(SystemExit):
        ps.run_folder_ingest(tmp_path)  # an empty folder: the ingest exits with status 1

    assert cli.hash_file is original


def test_folder_ingest_of_an_existing_folder_counts_its_files(tmp_path):
    (tmp_path / "a.bin").write_bytes(b"x" * 100)
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.bin").write_bytes(b"y" * 50)

    result = ps.run_folder_ingest(tmp_path)

    assert result["file_count"] == 2
    assert result["total_bytes"] == 150


def test_main_default_run_is_unchanged(capsys):
    ps.main(["--sizes", "3", "--file-size-kb", "1"])

    out = capsys.readouterr().out
    assert "Running trial: 3 evidence files x 1 KB" in out
    assert "file_count" not in out


def test_main_ingest_flag_runs_only_the_ingest_benchmark(capsys):
    ps.main(["--ingest", "5x1"])

    out = capsys.readouterr().out
    assert "Running trial" not in out  # the default hashing/Merkle trials are not run
    assert "5 files" in out and "hash" in out


def test_timers_do_not_double_count_a_timed_call_made_inside_another_timed_call():
    """Path.resolve() calls Path.stat() internally (Python 3.11): that time belongs to resolve, not to both."""
    import time

    class Owner:
        def inner(self):
            time.sleep(0.02)

        def outer(self):
            self.inner()

    outer_acc = {"seconds": 0.0, "calls": 0}
    inner_acc = {"seconds": 0.0, "calls": 0}
    with ps._timed(Owner, "outer", outer_acc), ps._timed(Owner, "inner", inner_acc):
        Owner().outer()

    assert outer_acc["seconds"] >= 0.02
    assert inner_acc["calls"] == 1  # still counted as a call...
    assert inner_acc["seconds"] == 0.0  # ...but its time is already inside the outer timer


def test_folder_ingest_phases_never_add_up_to_more_than_the_wall_time():
    result = ps.run_folder_ingest_trial(200, 1)

    assert result["other_seconds"] >= 0


# --- Task M0: peak memory in every ingest result, and a cap that emulates a small address space -----------------


def test_peak_mib_reports_the_process_peak_and_grows_with_real_allocations():
    before = ps.peak_mib()
    block = bytearray(96 * 2**20)
    block[::4096] = b"\x01" * len(block[::4096])  # touch every page so it is really resident
    after = ps.peak_mib()
    del block

    assert before > 0
    assert after >= before + 64


def test_folder_ingest_result_and_printout_carry_the_peak_memory(capsys):
    result = ps.run_folder_ingest_trial(5, 1)

    assert result["peak_mib"] > 0
    ps.print_ingest_result("t", result)
    assert "peak" in capsys.readouterr().out


def _run_script(*args):
    import subprocess

    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "performance_scale.py"), *args],
        capture_output=True, text=True, timeout=120,
    )


def test_cap_mib_makes_a_run_under_a_tiny_cap_fail_and_a_roomy_cap_pass():
    # one 128 MiB synthetic file: needs far more than the tiny cap, nowhere near the roomy one
    roomy = _run_script("--cap-mib", "4000", "--ingest", "1x131072")
    tiny = _run_script("--cap-mib", "100", "--ingest", "1x131072")

    assert roomy.returncode == 0, roomy.stderr
    assert "peak" in roomy.stdout
    assert tiny.returncode != 0
    assert "MemoryError" in tiny.stderr


# --- Task M2: a verification benchmark so the RAM claim of the Evidence tab is a number ---------------------------


def test_verification_benchmark_reports_rows_time_redraw_and_peak_and_leaves_the_original_alone(tmp_path):
    from vcoc import db
    from vcoc.models import Evidence

    path = tmp_path / "v.db"
    conn = db.connect(path)
    members = [Evidence(f"F/{i:03d}", f"f{i}.bin", "ab" * 32, 1, "2026-01-01T00:00:00Z", "", "F") for i in range(40)]
    db.put_folder(conn, "F", "ef" * 32, [m.evidence_id for m in members], members)
    conn.close()
    before = path.read_bytes()

    result = ps.run_verification(path)

    assert result["rows"] == 41  # 40 evidence rows + the Merkle root row
    assert result["wall_seconds"] > 0 and result["peak_mib"] > 0 and result["redraw_ms_max"] >= 0
    assert path.read_bytes() == before


def test_main_verify_db_flag_runs_only_the_verification_benchmark(tmp_path, capsys):
    from vcoc import db

    path = tmp_path / "v.db"
    db.connect(path).close()

    try:
        ps.main(["--verify-db", str(path)])
    except Exception:
        pass  # an empty database has nothing to verify: only the dispatch matters here

    out = capsys.readouterr().out
    assert "Running the Evidence verification" in out and "Running trial" not in out
