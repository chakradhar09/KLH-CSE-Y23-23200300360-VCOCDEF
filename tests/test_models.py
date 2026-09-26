from vcoc.hashing import hash_bytes
from vcoc.models import CustodyEvent, Evidence

# Real legacy entry captured from this repo's own custody_log.json (index 0),
# single evidence_id shape, already signed under today's canonical_payload().
LEGACY_ENTRY = {
    "index": 0,
    "evidence_id": "EV001",
    "actor": "Chakri",
    "action": "collected",
    "timestamp": "2026-09-21T08:27:01.998931+00:00",
    "prev_hash": "0" * 64,
    "entry_hash": "44a805940703bc46c95268e8cec41ce968ea0a22ace17341beffc2ddd7d2f828",
    "signature": "fb20968f27e770718039d6cc8605a81c59654c96a43310849ef41c947288e19d59837479ddfaa5eca4249fc53104c1521817c8b4bd2c3ccd1cc81e674f9b85b9",
}


def test_evidence_without_folder_id_defaults_to_none():
    """Existing single-file construction (no folder_id kwarg) must keep working."""
    evidence = Evidence(
        evidence_id="EV001",
        original_filename="a.bin",
        sha256="a" * 64,
        size_bytes=5,
        added_at="2026-01-01T00:00:00+00:00",
    )
    assert evidence.folder_id is None


def test_evidence_with_folder_id_set():
    evidence = Evidence(
        evidence_id="EVFOLDER/sub/a.bin",
        original_filename="a.bin",
        sha256="a" * 64,
        size_bytes=5,
        added_at="2026-01-01T00:00:00+00:00",
        folder_id="EVFOLDER",
    )
    assert evidence.folder_id == "EVFOLDER"


def _legacy_event() -> CustodyEvent:
    return CustodyEvent(
        index=LEGACY_ENTRY["index"],
        evidence_id=LEGACY_ENTRY["evidence_id"],
        actor=LEGACY_ENTRY["actor"],
        action=LEGACY_ENTRY["action"],
        timestamp=LEGACY_ENTRY["timestamp"],
        prev_hash=LEGACY_ENTRY["prev_hash"],
    )


def test_legacy_single_evidence_id_canonical_payload_unchanged():
    """A CustodyEvent built the old way (evidence_id=, no evidence_ids=) must
    produce today's exact payload string -- byte-for-byte, nothing appended.
    """
    event = _legacy_event()
    assert event.canonical_payload() == "|".join(
        [
            str(LEGACY_ENTRY["index"]),
            LEGACY_ENTRY["evidence_id"],
            LEGACY_ENTRY["actor"],
            LEGACY_ENTRY["action"],
            LEGACY_ENTRY["timestamp"],
            LEGACY_ENTRY["prev_hash"],
        ]
    )


def test_real_legacy_entry_rehashes_identically():
    """The one test that must never fail: a real signed entry from this
    repo's own custody_log.json re-hashes to its already-recorded
    entry_hash under the new dual-shape code.
    """
    event = CustodyEvent.from_dict(LEGACY_ENTRY)
    recomputed = hash_bytes(event.canonical_payload().encode("utf-8"))
    assert recomputed == LEGACY_ENTRY["entry_hash"]


def test_legacy_from_dict_does_not_populate_evidence_ids():
    event = CustodyEvent.from_dict(LEGACY_ENTRY)
    assert event.evidence_ids is None
    assert event.evidence_id == "EV001"


def test_legacy_to_dict_round_trip_has_no_evidence_ids_key():
    event = CustodyEvent.from_dict(LEGACY_ENTRY)
    data = event.to_dict()
    assert "evidence_ids" not in data
    assert data["evidence_id"] == "EV001"


def test_new_shape_canonical_payload_includes_all_evidence_ids_and_fields():
    event = CustodyEvent(
        index=0,
        evidence_id="",
        evidence_ids=["EV001", "EV002"],
        actor="J. Doe",
        action="seized",
        timestamp="2026-09-22T00:00:00+00:00",
        prev_hash="0" * 64,
        case_number="C-001",
        tag="disk+memory",
        notes="seized together from workstation",
    )
    payload = event.canonical_payload()
    assert "EV001" in payload
    assert "EV002" in payload
    assert "C-001" in payload
    assert "disk+memory" in payload
    assert "seized together from workstation" in payload


def test_new_shape_hash_changes_when_tag_changes():
    """Proves case_number/tag/notes are load-bearing (hashed), not decorative."""
    base = CustodyEvent(
        index=0,
        evidence_id="",
        evidence_ids=["EV001"],
        actor="J. Doe",
        action="seized",
        timestamp="2026-09-22T00:00:00+00:00",
        prev_hash="0" * 64,
        tag="original",
    )
    mutated = CustodyEvent(
        index=0,
        evidence_id="",
        evidence_ids=["EV001"],
        actor="J. Doe",
        action="seized",
        timestamp="2026-09-22T00:00:00+00:00",
        prev_hash="0" * 64,
        tag="mutated",
    )
    assert base.canonical_payload() != mutated.canonical_payload()


def test_new_shape_to_dict_from_dict_round_trip():
    event = CustodyEvent(
        index=0,
        evidence_id="",
        evidence_ids=["EV001", "EV002"],
        actor="J. Doe",
        action="seized",
        timestamp="2026-09-22T00:00:00+00:00",
        prev_hash="0" * 64,
        case_number="C-001",
    )
    event.entry_hash = hash_bytes(event.canonical_payload().encode("utf-8"))
    data = event.to_dict()
    assert data["evidence_ids"] == ["EV001", "EV002"]
    assert "evidence_id" not in data or not data.get("evidence_id")

    reloaded = CustodyEvent.from_dict(data)
    assert reloaded.evidence_ids == ["EV001", "EV002"]
    assert reloaded.canonical_payload() == event.canonical_payload()
