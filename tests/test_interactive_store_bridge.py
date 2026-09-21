"""Pure-function tests for vcoc.interactive.store_bridge -- no terminal needed."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import os

from vcoc.interactive import store_bridge
from vcoc.models import Evidence
from vcoc.storage import EncryptedStore, KEY_SIZE


def make_evidence(evidence_id: str, sha256: str = "a" * 64, filename: str = "f.bin") -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        original_filename=filename,
        sha256=sha256,
        size_bytes=123,
        added_at="2026-01-01T00:00:00Z",
    )


# -- open_or_create_store -------------------------------------------------


def test_open_or_create_store_key_missing_creates_both(tmp_path):
    key_path = tmp_path / "vcoc.key"
    db_path = tmp_path / "evidence_store.db"
    assert not key_path.exists()

    store, message = store_bridge.open_or_create_store(str(key_path), str(db_path))
    try:
        assert key_path.exists()
        assert key_path.stat().st_size == KEY_SIZE
        assert db_path.exists()
        assert "Wrote key" in message
        assert "Created store" in message
    finally:
        store.close()


def test_open_or_create_store_key_exists_opens_existing(tmp_path):
    key_path = tmp_path / "vcoc.key"
    db_path = tmp_path / "evidence_store.db"
    store, _ = store_bridge.open_or_create_store(str(key_path), str(db_path))
    store.put_evidence(make_evidence("EV001"))
    store.close()

    store2, message = store_bridge.open_or_create_store(str(key_path), str(db_path))
    try:
        assert "Opened store" in message
        assert store2.get_evidence("EV001").evidence_id == "EV001"
    finally:
        store2.close()


# -- mirror_to_store --------------------------------------------------------


def test_mirror_to_store_success(tmp_path):
    store = EncryptedStore(tmp_path / "s.db", os.urandom(KEY_SIZE))
    try:
        err = store_bridge.mirror_to_store(store, make_evidence("EV001"))
        assert err is None
        assert store.get_evidence("EV001").evidence_id == "EV001"
    finally:
        store.close()


def test_mirror_to_store_failure_is_non_fatal(tmp_path, monkeypatch):
    store = EncryptedStore(tmp_path / "s.db", os.urandom(KEY_SIZE))
    try:
        def boom(self, evidence):
            raise RuntimeError("disk full")

        monkeypatch.setattr(EncryptedStore, "put_evidence", boom)
        err = store_bridge.mirror_to_store(store, make_evidence("EV001"))
        assert err is not None
        assert "disk full" in err
    finally:
        store.close()


# -- search: merge/dedup/tag -------------------------------------------------


def test_search_no_store_all_index_only():
    index = {"EV001": {"original_filename": "a.bin", "sha256": "a" * 64}}
    results = store_bridge.search(index, None, "")
    assert len(results) == 1
    assert results[0]["tag"] == "index-only"
    assert results[0]["store_sha256"] is None


def test_search_full_overlap_tags_mirrored(tmp_path):
    store = EncryptedStore(tmp_path / "s.db", os.urandom(KEY_SIZE))
    try:
        store.put_evidence(make_evidence("EV001", sha256="a" * 64))
        index = {"EV001": {"original_filename": "f.bin", "sha256": "a" * 64}}
        results = store_bridge.search(index, store, "")
        assert len(results) == 1
        assert results[0]["tag"] == "mirrored"
    finally:
        store.close()


def test_search_store_only():
    class FakeStore:
        def list_evidence(self):
            return [make_evidence("EV002", filename="store_only.bin")]

    results = store_bridge.search({}, FakeStore(), "")
    assert len(results) == 1
    assert results[0]["tag"] == "store-only"
    assert results[0]["evidence_id"] == "EV002"


def test_search_diverged_hash_shows_both():
    class FakeStore:
        def list_evidence(self):
            return [make_evidence("EV001", sha256="b" * 64)]

    index = {"EV001": {"original_filename": "f.bin", "sha256": "a" * 64}}
    results = store_bridge.search(index, FakeStore(), "")
    assert len(results) == 1
    assert results[0]["tag"] == "DIVERGED"
    assert results[0]["index_sha256"] == "a" * 64
    assert results[0]["store_sha256"] == "b" * 64


def test_search_filters_by_substring():
    index = {
        "EV001": {"original_filename": "alpha.bin", "sha256": "a" * 64},
        "EV002": {"original_filename": "beta.bin", "sha256": "b" * 64},
    }
    results = store_bridge.search(index, None, "EV00")
    assert len(results) == 2
    results = store_bridge.search(index, None, "alpha")
    assert len(results) == 1
    assert results[0]["evidence_id"] == "EV001"
    results = store_bridge.search(index, None, "nomatch")
    assert results == []


def test_search_no_overlap_merges_both_sources():
    class FakeStore:
        def list_evidence(self):
            return [make_evidence("EV002", filename="store.bin")]

    index = {"EV001": {"original_filename": "index.bin", "sha256": "a" * 64}}
    results = store_bridge.search(index, FakeStore(), "")
    tags = {r["evidence_id"]: r["tag"] for r in results}
    assert tags == {"EV001": "index-only", "EV002": "store-only"}
