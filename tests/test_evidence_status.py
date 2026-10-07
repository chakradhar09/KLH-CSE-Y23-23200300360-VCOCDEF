"""The main menu's header also reports the last known evidence check (files re-hashed against their recorded sha256).

Like the chain result it is a hint saved in shell_config.json: the header never re-hashes anything, and anything added
to the database after the check shows as stale instead of leaving an old "all green" on screen.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from vcoc import db
from vcoc.interactive import app, config, status

from test_last_verify import NOW, at, make_db, record, status_of


def evidence_record(**overrides) -> dict:
    base = {
        "at": at(2, 14, 2), "db": "DB", "total": 3, "tampered": 0, "not_logged": 0, "unverifiable": 0,
        "events": 2, "evidence_max": 3,
    }
    return {**base, **overrides}


# ---- config: record and read back ------------------------------------------------------------------------------------

def test_the_evidence_check_is_saved_beside_the_chain_result_and_never_replaces_it(tmp_path):
    path = tmp_path / "shell_config.json"
    shell_config = {"last_verify": record(db="D")}
    config.record_evidence_check(shell_config, evidence_record(db="D"), str(path))
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    assert on_disk["last_verify"]["db"] == "D" and on_disk["last_evidence_check"]["total"] == 3
    assert shell_config["last_evidence_check"] == on_disk["last_evidence_check"]  # the running shell sees it too


def test_a_failed_write_is_not_an_error(tmp_path):
    shell_config: dict = {}
    config.record_evidence_check(shell_config, evidence_record(), str(tmp_path / "missing_dir" / "shell_config.json"))
    assert shell_config["last_evidence_check"]["total"] == 3


def test_the_two_records_are_written_under_one_lock(tmp_path, monkeypatch):
    """The chain check writes from the screen's thread and the evidence check from its background thread; both save the
    same dict, so a write must never run while the other is saving it."""
    held = []
    monkeypatch.setattr(config, "_save_atomic", lambda path, data: held.append(config._write_lock.locked()))
    config.record_last_verify({}, record(), str(tmp_path / "a.json"))
    config.record_evidence_check({}, evidence_record(), str(tmp_path / "b.json"))
    assert held == [True, True]


def test_last_evidence_check_returns_the_record_of_this_database_only():
    shell_config = {"last_evidence_check": evidence_record(db="D")}
    assert config.last_evidence_check(shell_config, "D")["total"] == 3
    assert config.last_evidence_check(shell_config, "OTHER") is None
    assert config.last_evidence_check({}, "D") is None


@pytest.mark.parametrize(
    "bad",
    [
        {"tampered": -1}, {"not_logged": "2"}, {"unverifiable": None}, {"total": True}, {"events": 1.5},
        {"evidence_max": -3}, {"at": "yesterday"}, {"at": True},
    ],
)
def test_a_malformed_evidence_record_is_ignored(bad):
    assert config.last_evidence_check({"last_evidence_check": evidence_record(db="D", **bad)}, "D") is None


# ---- status: the files states ----------------------------------------------------------------------------------------

def current(tmp_path, rec=None, **db_kwargs):
    path = make_db(tmp_path / "vcoc.db", **db_kwargs)
    shell_config = {} if rec is None else {"last_evidence_check": {**rec, "db": path}}
    return path, status.current_status(shell_config, path)


def test_files_are_unchecked_until_an_evidence_check_has_run(tmp_path):
    _, result = current(tmp_path)
    assert result.files == "unchecked"


def test_an_empty_database_has_no_files_to_report(tmp_path):
    _, result = current(tmp_path, evidence=0, events=0)
    assert result.files == "none"


@pytest.mark.parametrize("state", ["nodb", "unavailable"])
def test_no_files_segment_without_a_readable_database(tmp_path, state):
    path = tmp_path / "vcoc.db"
    if state == "unavailable":
        path.write_bytes(b"junk" * 100)
    assert status.current_status({}, str(path)).files == "none"


def test_all_green_when_every_file_matched_and_is_logged_and_nothing_changed(tmp_path):
    _, result = current(tmp_path, evidence_record())
    assert (result.files, result.files_n, result.files_at) == ("clean", 0, at(2, 14, 2))


def test_tampered_files_are_reported_with_their_count(tmp_path):
    _, result = current(tmp_path, evidence_record(tampered=3))
    assert (result.files, result.files_n, result.files_kind) == ("tamper", 3, "TAMPERED")


def test_a_tampered_verdict_outlives_anything_added_later(tmp_path):
    path, _ = current(tmp_path, evidence_record(tampered=1, events=0, evidence_max=0))
    result = status.current_status({"last_evidence_check": evidence_record(tampered=1, events=0, evidence_max=0, db=path)}, path)
    assert result.files == "tamper"


def test_not_logged_is_reported_before_unverifiable_when_nothing_is_tampered(tmp_path):
    _, result = current(tmp_path, evidence_record(not_logged=12, unverifiable=5))
    assert (result.files, result.files_n, result.files_kind) == ("issues", 12, "NOT LOGGED")


def test_unverifiable_files_are_reported_when_nothing_else_is_wrong(tmp_path):
    _, result = current(tmp_path, evidence_record(unverifiable=5))
    assert (result.files, result.files_n, result.files_kind) == ("issues", 5, "UNVERIFIABLE")


def test_stale_when_evidence_was_added_after_the_check(tmp_path):
    path, _ = current(tmp_path, evidence_record())
    conn = db.connect(path)
    with conn:
        conn.execute("INSERT INTO evidence (evidence_id, original_filename, sha256, size_bytes, added_at) VALUES ('EVNEW','n','ab',1,'t')")
    conn.close()
    result = status.current_status({"last_evidence_check": evidence_record(db=path)}, path)
    assert (result.files, result.files_n) == ("stale", 1)


def test_stale_when_events_were_logged_after_the_check_because_not_logged_may_have_changed(tmp_path):
    path, _ = current(tmp_path, evidence_record(not_logged=1, events=1))  # the database has 2 events
    result = status.current_status({"last_evidence_check": evidence_record(not_logged=1, events=1, db=path)}, path)
    assert (result.files, result.files_n) == ("stale", 1)


# ---- recording a finished check ---------------------------------------------------------------------------------------

def test_record_evidence_check_stores_what_the_database_held_when_the_check_began(tmp_path):
    path = make_db(tmp_path / "vcoc.db", evidence=3, events=2)
    shell_config: dict = {}
    counts = status.read_counts(path)
    status.record_evidence_check(
        shell_config, path, counts, total=3, tampered=1, not_logged=2, unverifiable=0, now=at(2, 15, 0),
        config_path=str(tmp_path / "shell_config.json"),
    )
    assert shell_config["last_evidence_check"] == {
        "at": at(2, 15, 0), "db": path, "total": 3, "tampered": 1, "not_logged": 2, "unverifiable": 0,
        "events": 2, "evidence_max": 3,
    }
    assert status.current_status(shell_config, path).files == "tamper"


def test_record_evidence_check_without_a_shell_config_does_nothing(tmp_path):
    path = make_db(tmp_path / "vcoc.db")
    status.record_evidence_check(None, path, status.read_counts(path), 3, 0, 0, 0)  # no error


# ---- the header text ---------------------------------------------------------------------------------------------------

@pytest.mark.parametrize(
    "files, n, kind, expected_tail",
    [
        ("clean", 0, "", "files ● ALL GREEN"),
        ("stale", 4, "", "files ◐ STALE · 4 new"),
        ("tamper", 3, "TAMPERED", "files ✖ 3 TAMPERED"),
        ("issues", 12, "NOT LOGGED", "files ◐ 12 NOT LOGGED"),
        ("issues", 5, "UNVERIFIABLE", "files ◐ 5 UNVERIFIABLE"),
        ("unchecked", 0, "", "files ○ unchecked"),
    ],
)
def test_header_text_has_a_files_segment_for_every_state(files, n, kind, expected_tail):
    text = status.header_text(status_of("clean", files=files, files_n=n, files_kind=kind, files_at=at(2, 14, 2)), now=NOW)
    assert expected_tail in text and text.startswith(" DB vcoc.db")
    assert len(text) <= 78


@pytest.mark.parametrize("chain", ["clean", "stale", "tamper", "unverified"])
@pytest.mark.parametrize("files", ["clean", "stale", "tamper", "issues", "unchecked"])
@pytest.mark.parametrize("name", ["vcoc.db", "a_much_longer_case_database_name_2026.db"])
def test_the_header_with_a_files_segment_always_fits_78_columns(chain, files, name):
    result = status_of(chain, db_name=name, new=12_345, bad_event=987_654, files=files, files_n=123_456, files_kind="UNVERIFIABLE", files_at=at(2, 14, 2))
    text = status.header_text(result, now=NOW)
    assert len(text) <= 78 and "files" in text


def test_the_chain_verdict_stays_beside_the_files_segment():
    text = status.header_text(status_of("clean", files="clean", files_at=at(2, 14, 2)), now=NOW)
    assert "chain ● CLEAN" in text and "files ● ALL GREEN" in text


def test_without_a_files_segment_the_header_is_exactly_what_it_was():
    assert status.header_text(status_of("clean"), now=NOW) == " DB vcoc.db  │  92,879 items  │  chain ● CLEAN · verified 14:02"


# ---- the menu frame follows the worse of the two --------------------------------------------------------------------

@pytest.mark.parametrize(
    "chain, files, expected",
    [
        ("clean", "clean", ""), ("clean", "tamper", "class:state-tamper"), ("clean", "stale", "class:state-stale"),
        ("stale", "clean", "class:state-stale"), ("tamper", "stale", "class:state-tamper"),
        ("stale", "tamper", "class:state-tamper"), ("clean", "issues", ""), ("clean", "unchecked", ""),
    ],
)
def test_the_menu_frame_shows_the_worse_of_the_chain_and_the_files(chain, files, expected):
    assert app._frame_style(status_of(chain, files=files)) == expected
