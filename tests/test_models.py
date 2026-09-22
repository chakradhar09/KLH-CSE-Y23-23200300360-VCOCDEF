from vcoc.models import Evidence


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
