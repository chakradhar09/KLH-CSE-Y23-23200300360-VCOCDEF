"""T12 + T13 data: the shell remembers the last chain verification and reports it honestly.

The result lives in shell_config.json (a hint about this machine's last run, not evidence), the database is only ever
read through a read-only connection, and `custody_log` is never touched.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

import cli as cli_module
from vcoc import db
from vcoc.ecdsa_signer import generate_keypair, save_keypair
from vcoc.hash_chain import HashChain
from vcoc.interactive import config, status, verification_screen


def at(day: int, hour: int, minute: int) -> float:
    return time.mktime((2026, 10, day, hour, minute, 0, 0, 0, -1))


NOW = at(2, 16, 30)


def record(**overrides) -> dict:
    base = {"at": at(2, 14, 2), "ok": True, "events": 2, "bad_event": None, "evidence_max": 3, "db": "DB"}
    return {**base, **overrides}


def make_db(path: Path, evidence: int = 3, events: int = 2) -> str:
    conn = db.connect(path)
    with conn:
        for i in range(evidence):
            conn.execute(
                "INSERT INTO evidence (evidence_id, original_filename, sha256, size_bytes, added_at) VALUES (?,?,?,?,?)",
                (f"EV{i:03d}", f"f{i}.bin", "ab" * 32, 10, "2026-10-01T00:00:00Z"),
            )
        for i in range(events):
            conn.execute(
                "INSERT INTO custody_log (idx, evidence_id, actor, action, timestamp, prev_hash, entry_hash, signature) VALUES (?,?,?,?,?,?,?,?)",
                (i, "EV000", "t", "a", "2026-10-01T00:00:00Z", "0" * 64, "ab" * 32, "cd" * 32),
            )
    conn.close()
    return str(path)


# ---- config: record and read back ------------------------------------------------------------------------------------

def test_record_last_verify_writes_the_record_and_keeps_every_other_key(tmp_path):
    path = tmp_path / "shell_config.json"
    shell_config = {"private_key": "k.pem", "public_key": "p.pem"}
    config.record_last_verify(shell_config, record(db=str(tmp_path / "vcoc.db")), str(path))
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    assert on_disk["private_key"] == "k.pem" and on_disk["last_verify"]["ok"] is True
    assert shell_config["last_verify"] == on_disk["last_verify"]  # the running shell sees it too


def test_record_last_verify_is_atomic_and_leaves_no_temporary_file(tmp_path):
    path = tmp_path / "shell_config.json"
    config.record_last_verify({}, record(), str(path))
    assert sorted(p.name for p in tmp_path.iterdir()) == ["shell_config.json"]


def test_record_last_verify_never_raises_when_the_write_fails(tmp_path):
    shell_config: dict = {}
    config.record_last_verify(shell_config, record(), str(tmp_path / "missing_dir" / "shell_config.json"))
    assert shell_config["last_verify"]["ok"] is True  # still remembered for this session


def test_last_verify_returns_the_record_for_the_same_database_only():
    rec = record(db="/a/vcoc.db")
    assert config.last_verify({"last_verify": rec}, "/a/vcoc.db") == rec
    assert config.last_verify({"last_verify": rec}, "/b/vcoc.db") is None
    assert config.last_verify({}, "/a/vcoc.db") is None


@pytest.mark.parametrize(
    "bad",
    [
        "not a dict", None, 5, [],
        {"at": "yesterday", "ok": True, "events": 1, "bad_event": None, "evidence_max": 1, "db": "D"},
        {"at": 1.0, "ok": "yes", "events": 1, "bad_event": None, "evidence_max": 1, "db": "D"},
        {"at": 1.0, "ok": True, "events": -1, "bad_event": None, "evidence_max": 1, "db": "D"},
        {"at": 1.0, "ok": True, "events": 1, "bad_event": "x", "evidence_max": 1, "db": "D"},
        {"at": 1.0, "ok": True, "events": 1, "bad_event": None, "evidence_max": True, "db": "D"},
        {"ok": True},
    ],
)
def test_a_malformed_record_reads_as_never_verified(bad):
    assert config.last_verify({"last_verify": bad}, "D") is None


# ---- status: read-only counts ----------------------------------------------------------------------------------------

def test_read_counts_reports_items_events_and_the_evidence_marker(tmp_path):
    path = make_db(tmp_path / "vcoc.db", evidence=3, events=2)
    assert status.read_counts(path) == status.Counts(items=3, events=2, evidence_max=3)


def test_the_item_count_is_reused_until_evidence_is_added(tmp_path, monkeypatch):
    """COUNT(*) over 92,879 rows is the header's only real cost (1.7 ms); the highest evidence rowid tells when it is stale."""
    path = make_db(tmp_path / "vcoc.db", evidence=3)
    scans = []
    real = status._count_items
    monkeypatch.setattr(status, "_count_items", lambda conn: scans.append(1) or real(conn))
    assert status.read_counts(path).items == 3 and len(scans) == 1
    assert status.read_counts(path).items == 3 and len(scans) == 1  # nothing was added: no scan
    conn = db.connect(path)
    with conn:
        conn.execute("INSERT INTO evidence (evidence_id, original_filename, sha256, size_bytes, added_at) VALUES ('EVNEW','n','ab',1,'t')")
    conn.close()
    assert status.read_counts(path).items == 4 and len(scans) == 2  # added: counted again


def test_the_cached_item_count_is_kept_per_database(tmp_path):
    first = make_db(tmp_path / "one.db", evidence=3)
    second = make_db(tmp_path / "two.db", evidence=5)
    assert status.read_counts(first).items == 3 and status.read_counts(second).items == 5
    assert status.read_counts(first).items == 3


def test_the_event_count_comes_from_the_index_so_a_long_log_costs_nothing(tmp_path):
    path = make_db(tmp_path / "vcoc.db", evidence=1, events=5)
    assert status.read_counts(path).events == 5
    assert status.read_counts(make_db(tmp_path / "empty.db", evidence=1, events=0)).events == 0


def test_read_counts_never_creates_a_database(tmp_path):
    missing = tmp_path / "vcoc.db"
    assert status.read_counts(str(missing)) is None
    assert not missing.exists()


def test_read_counts_returns_none_for_a_file_that_is_not_a_database_or_has_no_tables(tmp_path):
    junk = tmp_path / "junk.db"
    junk.write_bytes(b"this is not sqlite" * 50)
    assert status.read_counts(str(junk)) is None
    empty = tmp_path / "empty.db"
    sqlite3.connect(empty).close()
    assert status.read_counts(str(empty)) is None


def test_read_counts_does_not_write_to_the_database(tmp_path):
    path = make_db(tmp_path / "vcoc.db")
    before = Path(path).read_bytes()
    status.read_counts(path)
    assert Path(path).read_bytes() == before
    os.chmod(path, 0o444)  # even a read-only file works
    try:
        assert status.read_counts(path) is not None
    finally:
        os.chmod(path, 0o666)


# ---- status: the states the header can show --------------------------------------------------------------------------

def current(tmp_path, rec=None, **db_kwargs):
    path = make_db(tmp_path / "vcoc.db", **db_kwargs)
    shell_config = {} if rec is None else {"last_verify": {**rec, "db": path}}
    return path, status.current_status(shell_config, path)


def test_no_database_yet(tmp_path):
    result = status.current_status({}, str(tmp_path / "vcoc.db"))
    assert result.state == "nodb" and result.db_name == "vcoc.db"


def test_an_unreadable_database_is_reported_as_unavailable(tmp_path):
    junk = tmp_path / "vcoc.db"
    junk.write_bytes(b"junk" * 100)
    assert status.current_status({}, str(junk)).state == "unavailable"


def test_never_verified(tmp_path):
    _, result = current(tmp_path)
    assert result.state == "unverified" and result.items == 3


def test_clean_when_nothing_changed_since_the_verification(tmp_path):
    _, result = current(tmp_path, record())
    assert result.state == "clean" and result.new == 0 and result.verified_at == at(2, 14, 2)


def test_stale_when_evidence_was_added_after_the_verification(tmp_path):
    path, _ = current(tmp_path, record())
    conn = db.connect(path)
    with conn:
        conn.execute("INSERT INTO evidence (evidence_id, original_filename, sha256, size_bytes, added_at) VALUES ('EVNEW','n','ab',1,'t')")
    conn.close()
    result = status.current_status({"last_verify": record(db=path)}, path)
    assert result.state == "stale" and result.new == 1


def test_stale_when_custody_events_were_logged_after_the_verification(tmp_path):
    path, _ = current(tmp_path, record())
    conn = db.connect(path)
    with conn:
        for idx in (2, 3):
            conn.execute(
                "INSERT INTO custody_log (idx, evidence_id, actor, action, timestamp, prev_hash, entry_hash, signature) VALUES (?,?,?,?,?,?,?,?)",
                (idx, "EV000", "t", "a", "t", "0", "ab", "cd"),
            )
    conn.close()
    result = status.current_status({"last_verify": record(db=path)}, path)
    assert result.state == "stale" and result.new == 2


def test_new_evidence_and_new_events_are_counted_together(tmp_path):
    path, _ = current(tmp_path, record(events=1, evidence_max=1))  # the database has 2 events and 3 evidence rows
    result = status.current_status({"last_verify": record(events=1, evidence_max=1, db=path)}, path)
    assert result.state == "stale" and result.new == (2 - 1) + (3 - 1)


def test_tamper_stays_tamper_even_when_things_were_added_afterwards(tmp_path):
    path, _ = current(tmp_path, record(ok=False, bad_event=4, events=1, evidence_max=1))
    result = status.current_status({"last_verify": record(ok=False, bad_event=4, events=1, evidence_max=1, db=path)}, path)
    assert result.state == "tamper" and result.bad_event == 4


def test_a_record_for_another_database_is_ignored(tmp_path):
    path = make_db(tmp_path / "vcoc.db")
    assert status.current_status({"last_verify": record(db="/elsewhere/vcoc.db")}, path).state == "unverified"


# ---- the header text ---------------------------------------------------------------------------------------------------

def status_of(state, **kw):
    base = dict(state=state, db_name="vcoc.db", items=92879, verified_at=at(2, 14, 2), new=0, bad_event=None)
    return status.ChainStatus(**{**base, **kw})


@pytest.mark.parametrize(
    "result, expected",
    [
        (status_of("clean"), " DB vcoc.db  │  92,879 items  │  chain ● CLEAN · verified 14:02"),
        (status_of("stale", new=3), " DB vcoc.db  │  92,879 items  │  chain ◐ STALE · 3 new since 14:02"),
        (status_of("tamper", bad_event=4), " DB vcoc.db  │  92,879 items  │  chain ✖ TAMPER · event #4 · 14:02"),
        (status_of("unverified"), " DB vcoc.db  │  92,879 items  │  chain ○ not verified yet"),
        (status_of("nodb", items=0), " DB vcoc.db  │  not created yet"),
        (status_of("unavailable", items=0), " DB vcoc.db  │  status unavailable"),
    ],
)
def test_header_text_for_every_state(result, expected):
    assert status.header_text(result, now=NOW) == expected


def test_a_verification_from_another_day_shows_its_date():
    text = status.header_text(status_of("clean", verified_at=at(1, 9, 5)), now=NOW)
    assert text.endswith("verified 10-01 09:05")


def test_header_text_fits_an_80_column_frame_even_with_a_long_database_name_and_a_huge_count():
    for state in ("clean", "stale", "tamper", "unverified"):
        text = status.header_text(status_of(state, db_name="x" * 80, items=123_456_789, new=12_345, bad_event=12_345), now=NOW)
        assert len(text) <= 78, (state, len(text))


# ---- recording from the real chain check ---------------------------------------------------------------------------------

def signed_db(tmp_path, tamper: bool = False):
    signing_key, _ = generate_keypair()
    save_keypair(signing_key, "private_key.pem", "public_key.pem")
    chain = HashChain()
    chain.add_event(evidence_id="EV001", actor="tester", action="collected", signing_key=signing_key)
    chain.add_event(evidence_id="EV001", actor="tester", action="analyzed", signing_key=signing_key)
    path = tmp_path / "vcoc.db"
    chain.save_db(db.connect(path))
    if tamper:
        conn = sqlite3.connect(path)
        conn.execute("DROP TRIGGER custody_log_no_update")
        conn.execute("UPDATE custody_log SET actor = 'mallory' WHERE idx = 1")
        conn.commit()
        conn.close()
    return str(path)


def test_a_clean_chain_check_records_ok_and_the_counts_it_saw(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = signed_db(tmp_path)
    shell_config: dict = {}
    verification_screen._run_chain_check(shell_config)
    saved = shell_config["last_verify"]
    assert saved["ok"] is True and saved["bad_event"] is None and saved["events"] == 2
    assert saved["db"] == os.path.abspath(path)
    assert json.loads((tmp_path / "shell_config.json").read_text(encoding="utf-8"))["last_verify"]["ok"] is True


def test_a_tampered_chain_check_records_the_first_bad_event(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    signed_db(tmp_path, tamper=True)
    shell_config: dict = {}
    verification_screen._run_chain_check(shell_config)
    assert shell_config["last_verify"]["ok"] is False and shell_config["last_verify"]["bad_event"] == 1


def test_a_chain_check_without_a_shell_config_records_nothing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    signed_db(tmp_path)
    verification_screen._run_chain_check(None)
    assert not (tmp_path / "shell_config.json").exists()


def test_a_check_that_could_not_run_records_nothing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    shell_config: dict = {}
    verification_screen._run_chain_check(shell_config)  # no database at all
    make_db(tmp_path / "vcoc.db", evidence=0, events=0)
    verification_screen._run_chain_check({"public_key": "missing.pem"})  # no public key
    assert "last_verify" not in shell_config and not (tmp_path / "shell_config.json").exists()


def test_a_failing_write_never_breaks_the_chain_check(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    signed_db(tmp_path)
    monkeypatch.setattr(config, "DEFAULT_CONFIG_PATH", str(tmp_path / "no" / "such" / "dir" / "shell_config.json"))
    rows, _ = verification_screen._run_chain_check({})
    assert rows == ["OK  #0 collected on EV001", "OK  #1 analyzed on EV001"]


def test_the_custody_log_is_untouched_by_recording(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = signed_db(tmp_path)
    before = Path(path).read_bytes()
    verification_screen._run_chain_check({})
    assert Path(path).read_bytes() == before
