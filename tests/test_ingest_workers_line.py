"""The Add evidence loading screen shows how many workers hash and how many files per second, once the ingest has said so."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

import cli as cli_module
from vcoc import hashing
from vcoc.interactive import theme
from vcoc.interactive.menu import _IngestProgress

MB = 1024 * 1024


@pytest.fixture(autouse=True)
def _dark_theme():
    theme.set_current(theme.make_theme("dark"))
    yield
    theme.set_current(None)


def running(i, n=420_000, *, elapsed=10.0, workers=None, total=1000 * MB, done=1 * MB) -> _IngestProgress:
    """An ingest that reported file 1 at t=100 and file `i` (of n) `elapsed` seconds later."""
    now = [100.0]
    progress = _IngestProgress(clock=lambda: now[0])
    progress(1, n, "a.bin", 10, 0, total)
    now[0] = 100.0 + elapsed
    progress(i, n, "b.bin", 10, done, total)
    if workers is not None:
        progress.set_workers(workers)
    return progress


def test_the_workers_and_files_per_second_sit_between_the_status_and_the_bar():
    progress = running(50_001, workers=8)  # 50,000 files finished in 10 s
    lines = progress.screen_text().split("\n")

    assert "8 workers  5,000 files/s" in lines
    at = lines.index("8 workers  5,000 files/s")
    assert lines[at - 1].endswith("left") or "%" in lines[at - 1]  # right under the byte/percent line
    assert lines[at + 1] == "" and lines[at + 2] == theme.progress_bar(progress.fraction())


def test_one_worker_is_singular():
    assert "1 worker  100 files/s" in running(1_001, workers=1).screen_text().split("\n")


def test_a_slow_rate_keeps_one_decimal_so_it_never_reads_as_zero():
    assert "4 workers  0.4 files/s" in running(6, elapsed=12.5, workers=4).screen_text().split("\n")


def test_nothing_changes_until_the_ingest_has_reported_its_workers():
    progress = running(50_001)
    assert progress.screen_text() == f"{progress.text()}\n\n{theme.progress_bar(progress.fraction())}"


def test_the_status_text_itself_never_changes():
    plain, counted = running(50_001), running(50_001, workers=8)
    assert plain.text() == counted.text()


def test_no_speed_line_before_a_file_has_finished_or_before_any_time_has_passed():
    assert "files/s" not in running(1, workers=8).screen_text()  # file 1 is still being hashed: nothing finished yet
    assert "files/s" not in running(500, elapsed=0.0, workers=8).screen_text()  # a coarse clock can read the same instant


def test_nothing_is_said_before_the_first_report_or_once_every_file_is_hashed_and_rows_are_being_written():
    fresh = _IngestProgress(clock=lambda: 0.0)
    fresh.set_workers(8)
    assert fresh.screen_text() == "Scanning the folder..."
    last = running(420_000, n=420_000, workers=8, done=1000 * MB)  # every file hashed
    assert "files/s" not in last.screen_text() and "Recording to the database" in last.screen_text()


# ---- from a real ingest ----------------------------------------------------------------------------------------------


def _folder(tmp_path, n=25):
    folder = tmp_path / "case"
    folder.mkdir()
    for i in range(n):
        (folder / f"f{i:02d}.bin").write_bytes(bytes([i]) * (i * 50 + 1))
    return folder


def _ingest_with_progress(tmp_path, monkeypatch, jobs):
    monkeypatch.setattr(hashing, "PARALLEL_MIN_FILES", 1)
    monkeypatch.setattr(hashing, "BATCH_FILES", 4)
    progress = _IngestProgress()
    shown = []

    def hook(*args):
        progress(*args)
        shown.append(progress.screen_text())

    hook.set_workers = progress.set_workers
    ns = argparse.Namespace(
        file=str(_folder(tmp_path)), evidence_id="B1", db=str(tmp_path / "x.db"), private_key=None, actor=None,
        jobs=jobs, progress=hook,
    )
    cli_module.cmd_add_evidence(ns)
    return progress, shown


def test_a_real_pooled_ingest_tells_the_loading_screen_its_worker_count(tmp_path, monkeypatch):
    progress, shown = _ingest_with_progress(tmp_path, monkeypatch, jobs=2)

    assert progress.workers == 2
    assert any("2 workers  " in text and " files/s" in text for text in shown), shown[-1]


def test_a_real_single_process_ingest_says_one_worker(tmp_path, monkeypatch):
    progress, _ = _ingest_with_progress(tmp_path, monkeypatch, jobs=1)

    assert progress.workers == 1
