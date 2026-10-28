"""The Evidence check sorts every file into categories (all green, logged, not logged, tampered, unverifiable) and
remembers the verdict for the main menu's header.

_mixed_rows(tmp_path, 6) builds seven files:
  F1/m000 match, not logged        F1/m003 no source_path, not logged   F1/m005 match, not logged
  F1/m001 MISMATCH, logged         F1/m004 match, not logged            SOLO    match, logged
  F1/m002 file not found, logged
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from vcoc import db
from vcoc.interactive import status
from vcoc.interactive import verification_screen as vs

from test_evidence_check_parallel import _mixed_rows

EXPECTED = {
    "tampered": {"F1/m001"},
    "unverifiable": {"F1/m002", "F1/m003"},
    "not_logged": {"F1/m000", "F1/m003", "F1/m004", "F1/m005"},
    "logged": {"SOLO", "F1/m001", "F1/m002"},
    "green": {"SOLO"},
}


def ids(seq) -> set[str]:
    """The evidence ids a (lazy) list of row texts shows; the Merkle row has none."""
    return {row.split()[1] for row in seq if not row.startswith("--")}


@pytest.fixture
def check(tmp_path):
    path = _mixed_rows(tmp_path, n=6)
    rows, details = vs._run_evidence_check(db_path=path, jobs=1)
    return path, rows._results


def test_the_summary_counts_every_category(check):
    _, results = check
    assert results.summary() == {
        "all": 7, "tampered": 1, "not_logged": 4, "unverifiable": 2, "logged": 3, "green": 1,
    }


@pytest.mark.parametrize("name", list(EXPECTED))
def test_each_view_lists_exactly_the_files_of_its_category(check, name):
    _, results = check
    rows, _ = results.view(name)
    assert ids(rows) == EXPECTED[name] and len(rows) == len(EXPECTED[name])


def test_the_all_view_is_the_whole_list_with_the_merkle_row(check):
    _, results = check
    rows, details = results.view("all")
    assert len(rows) == 8 and rows[-1].startswith("--  Merkle root") and len(details) == 8


def test_a_filtered_detail_belongs_to_the_same_file_as_its_row(check):
    _, results = check
    rows, details = results.view("not_logged")
    for i in range(len(rows)):
        assert details[i][0] == f"evidence_id: {rows[i].split()[1]}"
        assert "custody log: NOT LOGGED" in details[i]


def test_a_view_name_that_does_not_exist_is_refused(check):
    _, results = check
    with pytest.raises(KeyError):
        results.view("nonsense")


# ---- the verdict is remembered for the header ---------------------------------------------------------------------------

def test_a_finished_check_is_recorded_for_the_header(tmp_path, monkeypatch):
    path = _mixed_rows(tmp_path, n=6)
    monkeypatch.chdir(tmp_path)
    shell_config: dict = {}
    vs._run_evidence_check(db_path=path, jobs=1, shell_config=shell_config)
    record = shell_config["last_evidence_check"]
    assert (record["total"], record["tampered"], record["not_logged"], record["unverifiable"]) == (7, 1, 4, 2)
    assert json.loads((tmp_path / "shell_config.json").read_text(encoding="utf-8"))["last_evidence_check"] == record
    assert status.current_status(shell_config, path).files == "tamper"


def test_the_record_holds_what_the_database_held_when_the_check_began(tmp_path, monkeypatch):
    """Evidence added while the files re-hash was never checked, so it must show as new, not as checked."""
    path = _mixed_rows(tmp_path, n=6)
    monkeypatch.chdir(tmp_path)

    def add_evidence_once(i, n, evidence_id, done, total, _added=[]):
        if not _added:
            _added.append(1)
            conn = db.connect(path)
            with conn:
                conn.execute("INSERT INTO evidence (evidence_id, original_filename, sha256, size_bytes, added_at) VALUES ('ZNEW','n','ab',1,'t')")
            conn.close()

    shell_config: dict = {}
    vs._run_evidence_check(progress=add_evidence_once, db_path=path, jobs=1, shell_config=shell_config)
    assert status.current_status(shell_config, path).files == "tamper"  # the tamper verdict outlives anything added
    shell_config["last_evidence_check"]["tampered"] = 0
    result = status.current_status(shell_config, path)
    assert (result.files, result.files_n) == ("stale", 1)


def test_a_cancelled_check_records_nothing(tmp_path, monkeypatch):
    path = _mixed_rows(tmp_path, n=6)
    monkeypatch.chdir(tmp_path)

    def cancel(*args):
        raise vs._Cancelled

    shell_config: dict = {}
    with pytest.raises(vs._Cancelled):
        vs._run_evidence_check(progress=cancel, db_path=path, jobs=1, shell_config=shell_config)
    assert "last_evidence_check" not in shell_config and not (tmp_path / "shell_config.json").exists()


def test_without_a_shell_config_nothing_is_recorded(tmp_path, monkeypatch):
    path = _mixed_rows(tmp_path, n=6)
    monkeypatch.chdir(tmp_path)
    vs._run_evidence_check(db_path=path, jobs=1)
    assert not (tmp_path / "shell_config.json").exists()


def test_an_empty_database_records_nothing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    conn = db.connect(tmp_path / "vcoc.db")
    conn.close()
    shell_config: dict = {}
    vs._run_evidence_check(db_path=str(tmp_path / "vcoc.db"), jobs=1, shell_config=shell_config)
    assert "last_evidence_check" not in shell_config


def test_the_verification_screen_hands_its_shell_config_to_the_evidence_tab(monkeypatch):
    captured = {}
    monkeypatch.setattr(vs, "_run_sidebar_detail_app", lambda title, load, **kwargs: captured.update(kwargs))
    seen = {}
    monkeypatch.setattr(vs, "_run_evidence_check", lambda **kwargs: seen.update(kwargs) or ([], []))
    shell_config = {"x": 1}
    vs.run_verification_screen(shell_config)
    captured["slow_load"][1]["Evidence"](None)
    assert seen["shell_config"] is shell_config
