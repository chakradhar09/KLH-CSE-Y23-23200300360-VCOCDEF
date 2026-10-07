"""The Evidence tab names the category it is showing in a heading row, with a divider under it."""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from vcoc.interactive import theme
from vcoc.interactive import verification_screen as vs

from test_evidence_screen_views import COUNTS, run_screen


@pytest.fixture(autouse=True)
def _theme():
    theme.set_current(theme.make_theme("dark"))
    yield
    theme.set_current(None)


# ---- the heading row -------------------------------------------------------------------------------------------------------

def test_the_heading_names_the_view_its_file_count_and_what_it_means():
    assert vs._view_heading(COUNTS, "tampered") == " Tampered · 1 file — re-hash does NOT match the recorded hash"
    assert vs._view_heading(COUNTS, "all") == " All · 7 files — every registered file, then the Merkle root"
    assert vs._view_heading({**COUNTS, "tampered": 0}, "tampered").startswith(" Tampered · 0 files — ")


def test_every_view_has_a_meaning_and_its_heading_fits_the_frame_even_with_huge_counts():
    big = {name: 1_234_567 for name in vs.VIEW_ORDER}
    for name in vs.VIEW_ORDER:
        assert vs.VIEW_NOTES[name]
        assert len(vs._view_heading(big, name)) <= 78


def test_the_heading_name_is_emphasised_and_the_rest_is_quiet():
    text = vs._view_heading(COUNTS, "unverifiable")
    fragments = theme.colorize(text, "heading", theme.make_theme("dark"))
    assert "".join(part for _, part in fragments) == text
    emphasised = [part for style, part in fragments if style == "class:accent class:b"]
    assert emphasised == ["Unverifiable"]
    assert all(style == "class:dim" for style, part in fragments if part.strip() and part != "Unverifiable")


# ---- the screen --------------------------------------------------------------------------------------------------------------

def test_the_heading_follows_f_and_a_divider_sits_directly_under_it(tmp_path, monkeypatch):
    everything, green, tampered = run_screen(tmp_path, monkeypatch, ["2", "f", "f"])
    for screen, heading in (
        (everything, "All · 7 files — every registered file, then the Merkle root"),
        (green, "All green · 1 file — re-hash matches and a custody event names it"),
        (tampered, "Tampered · 1 file — re-hash does NOT match the recorded hash"),
    ):
        lines = screen.split("\n")
        at = next(i for i, line in enumerate(lines) if heading in line)
        assert re.fullmatch(r"│─+│", lines[at + 1]), lines[at + 1]  # the very next row is a rule across the frame
        assert "evidence_id" in lines[at + 2] or "▸" in lines[at + 2]  # and the list starts right after it


def test_there_is_no_category_strip_any_more(tmp_path, monkeypatch):
    (screen,) = run_screen(tmp_path, monkeypatch, ["2"])
    assert "Not logged 4" not in screen and "[All 7]" not in screen  # only the current category's heading is shown


def test_the_last_view_has_its_heading_too(tmp_path, monkeypatch):
    screens = run_screen(tmp_path, monkeypatch, ["2"] + ["f"] * 5)  # All, All green, Tampered, Not logged, Unverifiable, Logged
    assert "Logged · 3 files — named by at least one custody event" in screens[-1]


def test_other_tabs_have_neither_the_heading_nor_the_divider_row(tmp_path, monkeypatch):
    chain, evidence = run_screen(tmp_path, monkeypatch, ["f", "2"])

    def rules(screen):
        return [line for line in screen.split("\n") if re.fullmatch(r"│─+│", line)]

    assert "files —" not in chain
    assert len(rules(chain)) == 2  # the tab bar's rule and the one above the help line
    assert len(rules(evidence)) == 3  # ... plus the divider under the heading


def test_the_extra_rows_do_not_push_the_position_footer_or_the_help_line_off_a_30_row_screen(tmp_path, monkeypatch):
    (screen,) = run_screen(tmp_path, monkeypatch, ["2"], files=60)  # 61 files + the Merkle row: the list scrolls
    assert re.search(r"1-\d+ of 62", screen)  # the position footer is still on screen
    assert "f view" in screen and screen.rstrip().endswith("┘")  # so are the help line and the frame's bottom edge
    lines = screen.split("\n")
    footer = next(i for i, line in enumerate(lines) if re.search(r"1-\d+ of 62", line))
    help_line = next(i for i, line in enumerate(lines) if "f view" in line)
    assert footer < help_line
