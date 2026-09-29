"""evidence_search.search: substring filter over the evidence table."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from vcoc.interactive.evidence_search import search

INDEX = {
    "EV002": {"original_filename": "beta.bin", "sha256": "b" * 64},
    "EV001": {"original_filename": "alpha.bin", "sha256": "a" * 64},
}


def test_empty_query_returns_all_sorted_by_id():
    assert [r["evidence_id"] for r in search(INDEX, "")] == ["EV001", "EV002"]


def test_query_matches_id_or_filename_case_insensitively():
    assert len(search(INDEX, "ev00")) == 2
    assert [r["evidence_id"] for r in search(INDEX, "ALPHA")] == ["EV001"]


def test_no_match_returns_empty():
    assert search(INDEX, "nomatch") == []


def test_result_carries_sha256():
    assert search(INDEX, "beta")[0]["sha256"] == "b" * 64
