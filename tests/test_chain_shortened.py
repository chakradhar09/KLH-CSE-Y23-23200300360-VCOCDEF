"""A custody log that has FEWER events than the last verification saw was cut short: the remaining events still verify, so the
chain check alone cannot see it. The shell remembers the most events it ever verified (a high-water mark) and warns.

Deleting the newest events needs the append-only triggers dropped first (they only guard against accidents); the signatures
and links cannot catch a cut at the end, which is why this comparison exists.
"""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from vcoc import db
from vcoc.ecdsa_signer import generate_keypair, save_keypair
from vcoc.hash_chain import HashChain
from vcoc.interactive import app, config, status
from vcoc.interactive import verification_screen as vs

from test_last_verify import NOW, make_db, record, status_of


# ---- the record keeps a high-water mark -------------------------------------------------------------------------------------

def test_a_verification_records_the_most_events_it_has_ever_seen(tmp_path):
    path = make_db(tmp_path / "vcoc.db", evidence=1, events=5)
    shell_config: dict = {}
    cfg = str(tmp_path / "shell_config.json")
    status.record_chain_check(shell_config, path, [True] * 5, list(range(5)), config_path=cfg)
    assert shell_config["last_verify"]["high_water"] == 5
    status.record_chain_check(shell_config, path, [True] * 3, list(range(3)), config_path=cfg)  # a shorter log is verified later
    assert shell_config["last_verify"]["events"] == 3 and shell_config["last_verify"]["high_water"] == 5  # the mark never drops


def test_the_high_water_mark_is_kept_per_database(tmp_path):
    first = make_db(tmp_path / "one.db", evidence=1, events=5)
    second = make_db(tmp_path / "two.db", evidence=1, events=2)
    shell_config: dict = {}
    cfg = str(tmp_path / "shell_config.json")
    status.record_chain_check(shell_config, first, [True] * 5, list(range(5)), config_path=cfg)
    status.record_chain_check(shell_config, second, [True] * 2, list(range(2)), config_path=cfg)
    assert shell_config["last_verify"]["high_water"] == 2  # another database starts from its own count


def test_a_record_without_a_high_water_mark_is_still_valid_and_falls_back_to_its_event_count():
    assert config.last_verify({"last_verify": record(db="D")}, "D") is not None


@pytest.mark.parametrize("bad", [-1, "5", True, 2.5, None])
def test_a_malformed_high_water_mark_discards_the_record(bad):
    assert config.last_verify({"last_verify": record(db="D", high_water=bad)}, "D") is None


# ---- the header state -----------------------------------------------------------------------------------------------------

def current(tmp_path, rec, **db_kwargs):
    path = make_db(tmp_path / "vcoc.db", **db_kwargs)
    return status.current_status({"last_verify": {**rec, "db": path}}, path)


def test_fewer_events_than_ever_verified_is_reported_as_shortened(tmp_path):
    result = current(tmp_path, record(events=5, evidence_max=3, high_water=5), events=3)
    assert (result.state, result.removed) == ("shortened", 2)


def test_the_warning_works_from_the_menu_without_running_a_verification_again(tmp_path):
    result = current(tmp_path, record(events=2, evidence_max=3, high_water=9), events=2)  # verified at 2, but 9 were seen once
    assert (result.state, result.removed) == ("shortened", 7)


def test_an_old_record_without_a_high_water_mark_uses_its_event_count(tmp_path):
    result = current(tmp_path, record(events=5, evidence_max=3), events=4)
    assert (result.state, result.removed) == ("shortened", 1)


def test_the_same_number_of_events_is_not_shortened(tmp_path):
    assert current(tmp_path, record(events=2, evidence_max=3, high_water=2), events=2).state == "clean"


def test_more_events_than_ever_verified_is_stale_not_shortened(tmp_path):
    assert current(tmp_path, record(events=2, evidence_max=3, high_water=2), events=4).state == "stale"


def test_a_broken_event_is_still_reported_as_tamper_before_shortened(tmp_path):
    result = current(tmp_path, record(ok=False, bad_event=1, events=5, evidence_max=3, high_water=5), events=3)
    assert result.state == "tamper"


def test_an_emptied_log_is_shortened_too(tmp_path):
    assert current(tmp_path, record(events=5, evidence_max=3, high_water=5), events=0).state == "shortened"


def test_the_header_names_the_missing_events():
    text = status.header_text(status_of("shortened", removed=2), now=NOW)
    assert "chain ✖ SHORTENED · 2 events gone since 14:02" in text and len(text) <= 78
    assert "1 event gone" in status.header_text(status_of("shortened", removed=1), now=NOW)


@pytest.mark.parametrize("files", ["clean", "tamper", "unchecked"])
def test_the_shortened_header_fits_beside_a_files_segment(files):
    text = status.header_text(status_of("shortened", removed=123_456, files=files, files_n=3, files_kind="TAMPERED"), now=NOW)
    assert len(text) <= 78 and "SHORTENED" in text


def test_the_menu_frame_is_red_for_a_shortened_log():
    assert app._frame_style(status_of("shortened", removed=2)) == "class:state-tamper"


# ---- the Verify chain screen ----------------------------------------------------------------------------------------------

@pytest.fixture
def case(tmp_path, monkeypatch):
    """A signed chain of five events in ./vcoc.db with its key pair; returns (shell_config, cut) where cut(n) deletes the newest events."""
    monkeypatch.chdir(tmp_path)
    signing_key, verifying_key = generate_keypair()
    save_keypair(signing_key, tmp_path / "private_key.pem", tmp_path / "public_key.pem")
    chain = HashChain()
    for i in range(5):
        chain.add_event(evidence_id=f"EV{i}", actor="J. Doe", action="reviewed", signing_key=signing_key)
    conn = db.connect("vcoc.db")
    with conn:  # the events are about registered evidence: five files
        for i in range(5):
            conn.execute(
                "INSERT INTO evidence (evidence_id, original_filename, sha256, size_bytes, added_at) VALUES (?,?,?,?,?)",
                (f"EV{i}", f"f{i}.bin", "ab" * 32, 10, "2026-10-01T00:00:00Z"),
            )
    chain.save_db(conn)
    conn.close()

    def cut(keep: int) -> None:
        raw = sqlite3.connect("vcoc.db")
        raw.execute("DROP TRIGGER IF EXISTS custody_log_no_delete")  # what someone with the file does first
        raw.execute("DELETE FROM custody_log WHERE idx >= ?", (keep,))
        raw.commit()
        raw.close()

    return {"public_key": str(tmp_path / "public_key.pem")}, cut


def test_the_first_check_of_an_intact_chain_has_no_warning(case):
    shell_config, _ = case
    rows, _ = vs._run_chain_check(shell_config)
    assert len(rows) == 5 and all(row.startswith("OK") for row in rows)


def test_a_cut_chain_shows_a_warning_row_first_and_its_events_still_verify(case):
    shell_config, cut = case
    vs._run_chain_check(shell_config)  # verified with five events
    cut(3)
    rows, details = vs._run_chain_check(shell_config)
    assert rows[0].startswith("TAMPER  ") and "shortened" in rows[0] and "3" in rows[0] and "5" in rows[0]
    assert len(rows) == 4 and all(row.startswith("OK") for row in rows[1:])  # the three remaining events are fine
    assert "2 event(s) were removed" in "\n".join(details[0])


def test_the_warning_survives_checking_the_shorter_chain_again(case):
    shell_config, cut = case
    vs._run_chain_check(shell_config)
    cut(3)
    vs._run_chain_check(shell_config)
    rows, _ = vs._run_chain_check(shell_config)  # a second look must not forget what was lost
    assert rows[0].startswith("TAMPER  ") and status.current_status(shell_config, str(Path("vcoc.db").resolve())).state == "shortened"


def test_an_emptied_log_still_warns(case):
    shell_config, cut = case
    vs._run_chain_check(shell_config)
    cut(0)
    rows, details = vs._run_chain_check(shell_config)
    assert rows[0].startswith("TAMPER  ") and "shortened" in rows[0]


# ---- a manipulated key pair ----------------------------------------------------------------------------------------------

def test_an_unreadable_public_key_is_a_message_not_a_crash(case, tmp_path):
    shell_config, _ = case
    (tmp_path / "public_key.pem").write_text("this is not a key")
    rows, details = vs._run_chain_check(shell_config)
    assert rows == ["Public key unreadable"] and "public_key.pem" in "\n".join(details[0])


def test_a_different_public_key_fails_every_event(case, tmp_path):
    shell_config, _ = case
    _, other = generate_keypair()
    (tmp_path / "public_key.pem").write_bytes(other.to_pem())
    rows, _ = vs._run_chain_check(shell_config)
    assert len(rows) == 5 and all(row.startswith("TAMPER") for row in rows)


# ---- a brand-new database is not a shortened one ---------------------------------------------------------------------------
# A cut at the end keeps the log's first event; starting over (deleting vcoc.db) does not. The first event's hash tells them apart.

def make_chain_db(tmp_path, events: int, evidence: int = 1, seed: str = "ab") -> str:
    path = make_db(tmp_path / "vcoc.db", evidence=evidence, events=events)
    conn = sqlite3.connect(path)
    conn.execute("DROP TRIGGER IF EXISTS custody_log_no_update")
    conn.execute("UPDATE custody_log SET entry_hash = ? WHERE idx = 0", (seed * 32,))
    conn.commit()
    conn.close()
    return path


def test_the_first_events_hash_is_read_with_the_counts(tmp_path):
    path = make_chain_db(tmp_path, events=3, seed="cd")
    assert status.read_counts(path).first_hash == "cd" * 32
    assert status.read_counts(make_db(tmp_path / "e.db", evidence=1, events=0)).first_hash == ""


def test_a_cut_chain_keeps_its_first_event_so_it_is_shortened(tmp_path):
    path = make_chain_db(tmp_path, events=3, seed="cd")
    rec = record(events=5, evidence_max=1, high_water=5, first_hash="cd" * 32, db=path)
    assert status.current_status({"last_verify": rec}, path).state == "shortened"


def test_a_new_log_with_a_different_first_event_is_not_shortened(tmp_path):
    path = make_chain_db(tmp_path, events=1, seed="ef")  # the user deleted vcoc.db and started over
    rec = record(events=5, evidence_max=1, high_water=5, first_hash="cd" * 32, db=path)
    assert status.current_status({"last_verify": rec}, path).state != "shortened"


def test_the_high_water_mark_starts_over_for_a_different_log(tmp_path):
    path = make_chain_db(tmp_path, events=2, seed="ef")
    shell_config = {"last_verify": record(events=5, evidence_max=1, high_water=5, first_hash="cd" * 32, db=path)}
    status.record_chain_check(shell_config, path, [True, True], [0, 1], config_path=str(tmp_path / "shell_config.json"))
    assert shell_config["last_verify"]["high_water"] == 2 and shell_config["last_verify"]["first_hash"] == "ef" * 32


def test_a_verification_records_the_first_events_hash(tmp_path):
    path = make_chain_db(tmp_path, events=3, seed="cd")
    shell_config: dict = {}
    status.record_chain_check(shell_config, path, [True] * 3, [0, 1, 2], config_path=str(tmp_path / "shell_config.json"))
    assert shell_config["last_verify"]["first_hash"] == "cd" * 32


def test_an_emptied_log_with_evidence_still_registered_is_shortened(tmp_path):
    path = make_chain_db(tmp_path, events=0, evidence=3)
    rec = record(events=5, evidence_max=3, high_water=5, first_hash="cd" * 32, db=path)
    assert status.current_status({"last_verify": rec}, path).state == "shortened"


def test_an_empty_database_is_a_new_one_not_a_shortened_one(tmp_path):
    path = make_chain_db(tmp_path, events=0, evidence=0)
    rec = record(events=5, evidence_max=0, high_water=5, first_hash="cd" * 32, db=path)
    assert status.current_status({"last_verify": rec}, path).state != "shortened"


@pytest.mark.parametrize("bad", [5, True, None, ["x"]])
def test_a_malformed_first_hash_discards_the_record(bad):
    assert config.last_verify({"last_verify": record(db="D", first_hash=bad)}, "D") is None


def test_the_verify_screen_does_not_warn_after_the_database_was_started_over(case, tmp_path):
    shell_config, _ = case
    vs._run_chain_check(shell_config)  # verified: five events
    (tmp_path / "vcoc.db").unlink()
    signing_key, _ = generate_keypair()
    fresh = HashChain()
    fresh.add_event(evidence_id="NEW", actor="J. Doe", action="collected", signing_key=signing_key)
    conn = db.connect("vcoc.db")
    fresh.save_db(conn)
    conn.close()
    rows, _ = vs._run_chain_check(shell_config)
    assert not any("shortened" in row for row in rows)
