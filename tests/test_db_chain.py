import sqlite3

import pytest

from vcoc import db
from vcoc.ecdsa_signer import generate_keypair
from vcoc.hash_chain import HashChain
from vcoc.models import Evidence


def _mixed_chain(signing_key):
    chain = HashChain()
    chain.add_event(evidence_id="EV001", actor="J. Doe", action="collected", signing_key=signing_key)
    chain.add_event(
        evidence_ids=["EV001", "EV002"],
        actor="A. Roe",
        action="transferred",
        signing_key=signing_key,
        case_number="C-1",
        tag="urgent",
        notes="note, with | delimiters",
    )
    chain.add_event(evidence_ids=["EV003"], actor="A. Roe", action="reviewed", signing_key=signing_key)
    return chain


def test_chain_roundtrip_is_byte_identical(tmp_path):
    signing_key, verifying_key = generate_keypair()
    chain = _mixed_chain(signing_key)
    conn = db.connect(tmp_path / "vcoc.db")
    chain.save_db(conn)

    loaded = HashChain.load_db(conn)
    assert loaded.to_json() == chain.to_json()
    ok, _, _ = loaded.verify(verifying_key)
    assert ok


def test_empty_db_loads_empty_chain(tmp_path):
    conn = db.connect(tmp_path / "vcoc.db")
    assert HashChain.load_db(conn).entries == []


def test_save_db_appends_only_new_entries(tmp_path):
    signing_key, verifying_key = generate_keypair()
    conn = db.connect(tmp_path / "vcoc.db")
    chain = HashChain()
    chain.add_event(evidence_id="EV001", actor="a", action="x", signing_key=signing_key)
    chain.save_db(conn)

    chain = HashChain.load_db(conn)
    chain.add_event(evidence_id="EV002", actor="a", action="y", signing_key=signing_key)
    chain.save_db(conn)

    final = HashChain.load_db(conn)
    assert [e.evidence_id for e in final.entries] == ["EV001", "EV002"]
    assert final.verify(verifying_key)[0]


def test_concurrent_stale_append_is_rejected(tmp_path):
    signing_key, _ = generate_keypair()
    conn = db.connect(tmp_path / "vcoc.db")
    a = HashChain()
    a.add_event(evidence_id="EV001", actor="a", action="x", signing_key=signing_key)
    a.save_db(conn)

    stale = HashChain.load_db(conn)
    fresh = HashChain.load_db(conn)
    fresh.add_event(evidence_id="EV002", actor="a", action="y", signing_key=signing_key)
    fresh.save_db(conn)
    stale.add_event(evidence_id="EV003", actor="b", action="z", signing_key=signing_key)
    with pytest.raises(sqlite3.IntegrityError):
        stale.save_db(conn)
    assert len(HashChain.load_db(conn).entries) == 2


def test_failed_append_leaves_chain_unchanged(tmp_path):
    signing_key, _ = generate_keypair()
    conn = db.connect(tmp_path / "vcoc.db")
    chain = HashChain()
    chain.add_event(evidence_id="EV001", actor="a", action="x", signing_key=signing_key)
    chain.save_db(conn)

    chain.add_event(evidence_id="EV002", actor="a", action="y", signing_key=signing_key)
    chain.add_event(evidence_id="EV003", actor="a", action="z", signing_key=signing_key)
    chain.entries[2].signature = None  # NOT NULL violation on the second new row
    with pytest.raises(sqlite3.IntegrityError):
        chain.save_db(conn)
    assert len(HashChain.load_db(conn).entries) == 1


def test_evidence_and_folder_roundtrip(tmp_path):
    conn = db.connect(tmp_path / "vcoc.db")
    ev = Evidence("F1/a.bin", "a.bin", "ab" * 32, 3, "2026-01-01T00:00:00+00:00", "/x/a.bin", "F1")
    solo = Evidence("EV9", "z.bin", "cd" * 32, 5, "2026-01-02T00:00:00+00:00", "/x/z.bin")
    db.put_evidence(conn, ev)
    db.put_evidence(conn, solo)
    db.put_folder(conn, "F1", "ef" * 32, ["F1/a.bin"])

    index = db.load_evidence_index(conn)
    assert index["F1/a.bin"] == ev.__dict__
    assert index["EV9"] == solo.__dict__
    assert db.load_folder_index(conn) == {"F1": {"root": "ef" * 32, "member_ids": ["F1/a.bin"]}}


def test_put_evidence_overwrites_same_id(tmp_path):
    conn = db.connect(tmp_path / "vcoc.db")
    db.put_evidence(conn, Evidence("EV1", "a", "11" * 32, 1, "t"))
    db.put_evidence(conn, Evidence("EV1", "a", "22" * 32, 2, "t"))
    assert db.load_evidence_index(conn)["EV1"]["sha256"] == "22" * 32


def test_custody_log_rejects_update_and_delete(tmp_path):
    signing_key, _ = generate_keypair()
    conn = db.connect(tmp_path / "vcoc.db")
    chain = HashChain()
    chain.add_event(evidence_id="EV001", actor="a", action="x", signing_key=signing_key)
    chain.save_db(conn)

    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        conn.execute("UPDATE custody_log SET actor = 'Mallory' WHERE idx = 0")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        conn.execute("DELETE FROM custody_log WHERE idx = 0")

    chain.add_event(evidence_id="EV002", actor="a", action="y", signing_key=signing_key)
    chain.save_db(conn)
    assert len(HashChain.load_db(conn).entries) == 2
