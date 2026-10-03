"""The Verification tabs and the Merkle screens wear the same look as the rest of the shell.

Reported gaps: the Evidence and Merkle tabs still showed the old one-line "Re-hashing 5/9 EV005 1.0 MB / 2.0 MB (50%)"
text (clipped by the 40-column sidebar, so the file count was cut off), there was no loading screen between the menu and
the Verification screens, the position footer floated above the bottom of the sidebar, and the Merkle root / proof pages
were plain.
"""

from __future__ import annotations

import io
import re
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from prompt_toolkit.application import create_app_session
from prompt_toolkit.data_structures import Size
from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import ColorDepth
from prompt_toolkit.output.vt100 import Vt100_Output

from test_theme_screens import ACCENT, drive, sequences, visible
from vcoc.interactive import forms, theme, verification_screen
from vcoc.interactive.verification_screen import _BackgroundLoad

MB = 1024 * 1024
SIDEBAR_COLUMNS = 36  # the sidebar is at most 40 wide; text longer than this risks being clipped


@pytest.fixture(autouse=True)
def _dark_theme():
    theme.set_current(theme.make_theme("dark"))
    yield
    theme.set_current(None)


def loader(*, progress=None, status="Loading...", started=100.0, now=112.3) -> _BackgroundLoad:
    bg = _BackgroundLoad(on_change=lambda: None, clock=lambda: now)
    bg.loading = True
    bg._started = started
    bg._progress = progress
    bg._status = status
    return bg


def stripped(raw: str) -> str:
    return re.sub(r"\r(?!\n)", "", re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", raw))


# ---- the sidebar's loading text ---------------------------------------------------------------------------------------

def test_loading_with_progress_shows_the_file_count_the_file_and_a_block_bar_on_separate_short_lines():
    text = loader(progress=(5, 9, "EV005", 1 * MB, 2 * MB)).screen_text()
    lines = text.split("\n")
    assert "  Re-hashing evidence" in lines
    assert "  File 5 of 9" in lines
    assert "  EV005" in lines and "  1.0 MB of 2.0 MB" in lines
    assert "  " + theme.progress_bar(0.5, 24) in lines  # four files done plus half of the fifth, out of nine
    assert "  12.3 s" in lines
    assert all(len(line) <= SIDEBAR_COLUMNS for line in lines), [len(l) for l in lines]


def test_the_file_count_uses_thousands_separators_and_a_huge_job_still_fits():
    text = loader(progress=(12_345, 92_879, "EV012345", 1 * MB, 2 * MB)).screen_text()
    assert "  File 12,345 of 92,879" in text.split("\n")
    assert all(len(line) <= SIDEBAR_COLUMNS for line in text.split("\n"))


def test_a_very_long_evidence_id_is_shortened_not_clipped():
    text = loader(progress=(1, 2, "E" * 60, 1, 2)).screen_text()
    assert all(len(line) <= SIDEBAR_COLUMNS for line in text.split("\n"))
    assert "…" in text


def test_the_largest_sizes_still_fit_the_sidebar():
    text = loader(progress=(92_879, 92_879, "EV092879", 1023 * 1024 * 1024, 1023 * 1024 * 1024)).screen_text()
    assert all(len(line) <= SIDEBAR_COLUMNS for line in text.split("\n")), [len(l) for l in text.split("\n")]


def test_the_overall_fraction_counts_finished_files_plus_the_part_of_the_current_one():
    assert loader().fraction() is None
    assert loader(progress=(1, 4, "a", 0, 100)).fraction() == 0.0
    assert loader(progress=(3, 4, "a", 50, 100)).fraction() == pytest.approx(0.625)
    assert loader(progress=(4, 4, "a", 100, 100)).fraction() == 1.0
    assert loader(progress=(2, 2, "empty", 0, 0)).fraction() == 1.0  # a zero-byte file counts as done


def test_loading_without_progress_shows_a_marquee_and_the_clock():
    lines = loader().screen_text().split("\n")
    assert "  Working..." in lines
    assert "  " + theme.marquee(12.3, width=24, block=5) in lines
    assert "  12.3 s" in lines
    assert all(len(line) <= SIDEBAR_COLUMNS for line in lines)


def test_the_clock_starts_when_the_load_starts():
    ticks = iter([50.0, 53.5])  # start() reads the clock once, then screen_text() once
    gate = threading.Event()
    bg = _BackgroundLoad(on_change=lambda: None, clock=lambda: next(ticks))
    bg.start(lambda report: gate.wait(2) or ([], []))
    try:
        assert "  3.5 s" in bg.screen_text().split("\n")
    finally:
        gate.set()
        bg.cancel()


# ---- the loading text, drawn ----------------------------------------------------------------------------------------

def run_slow_tab(progress, *, seconds=0.7, term_rows=24):
    """Open the Verification-style screen on a slow tab that reports `progress` (or nothing) and never finishes by itself."""
    gate = threading.Event()

    def slow(report):
        if progress is not None:
            report(*progress)
        gate.wait(5)
        return (["OK  EV1  (a)"], [["status: OK"]])

    buffer = io.StringIO()
    output = Vt100_Output(buffer, lambda: Size(term_rows, 80), term="xterm-256color", default_color_depth=ColorDepth.DEPTH_24_BIT)
    with create_pipe_input() as pipe:
        timer = threading.Timer(seconds, lambda: pipe.send_text("q"))
        timer.start()
        try:
            with create_app_session(input=pipe, output=output):
                with theme.ascii_borders(theme.current()):
                    verification_screen._run_sidebar_detail_app(
                        "Verification",
                        lambda: (["fast"], [["fast"]]),
                        top_bar=lambda: "  Chain  [ Evidence ]  Merkle  ",
                        slow_load=(lambda: "Evidence", slow),
                    )
        finally:
            timer.cancel()
            gate.set()
    return buffer.getvalue()


def test_the_evidence_tab_draws_the_block_bar_in_the_accent_while_it_hashes():
    raw = run_slow_tab((5, 9, "EV005", 1 * MB, 2 * MB))
    text = stripped(raw)
    assert "File 5 of 9" in text and "EV005" in text and "1.0 MB of 2.0 MB" in text
    assert "■" * 12 + "□" * 12 in text
    fill_styles = re.findall(r"\x1b\[([0-9;]*)m■{12}", raw)  # the color sent right before the filled part of the bar
    assert fill_styles and all(ACCENT in style for style in fill_styles), fill_styles


def test_the_merkle_tab_draws_a_marquee_while_it_works():
    text = stripped(run_slow_tab(None))
    assert "Working..." in text and re.search(r"\[[·■]{24}\]", text)


def spy_application(monkeypatch):
    seen = []
    real = verification_screen.Application

    def spy(*args, **kwargs):
        seen.append(kwargs.get("refresh_interval"))
        return real(*args, **kwargs)

    monkeypatch.setattr(verification_screen, "Application", spy)
    return seen


def test_a_screen_with_a_background_tab_redraws_ten_times_a_second_so_the_marquee_moves(monkeypatch):
    """prompt_toolkit repaints only changed cells, so animation is checked on the wiring: a redraw timer exists."""
    seen = spy_application(monkeypatch)
    run_slow_tab(None, seconds=0.2)
    assert seen == [0.1]


def test_a_screen_without_background_tabs_has_no_redraw_timer(monkeypatch):
    seen = spy_application(monkeypatch)
    drive(lambda: verification_screen._run_sidebar_detail_app("Verify Chain", lambda: (["OK  a"], [["x"]])), "q")
    assert seen == [None]


def test_the_old_one_line_status_is_gone():
    text = stripped(run_slow_tab((5, 9, "EV005", 1 * MB, 2 * MB)))
    assert "Re-hashing 5/9" not in text


def test_the_loading_sidebar_in_the_ascii_fallback_is_ascii_with_a_hash_bar():
    theme.set_current(theme.make_theme("dark", unicode=False))
    text = stripped(run_slow_tab((5, 9, "EV005", 1 * MB, 2 * MB)))
    assert "#" * 12 + "." * 12 in text and text.isascii()


def test_the_loading_sidebar_under_no_color_emits_no_color_codes():
    theme.set_current(theme.make_theme("plain"))
    raw = run_slow_tab((5, 9, "EV005", 1 * MB, 2 * MB))
    assert "38;2;" not in raw and "48;2;" not in raw


# ---- the position footer sits on the last line of the sidebar --------------------------------------------------------

ROWS = [f"OK  #{i} register on EV{i:04d}" for i in range(100)]
DETAILS = [["status: OK"]] * 100
TABS = lambda: "  Chain  [ Evidence ]  Merkle  "


@pytest.mark.parametrize("top_bar, chrome", [(None, 4), (TABS, 6)])
def test_the_footer_is_on_the_line_just_above_the_bottom_rule_and_the_rows_fill_the_rest(top_bar, chrome):
    _, raw = drive(
        lambda: verification_screen._run_sidebar_detail_app("Verify Chain", lambda: (ROWS, DETAILS), top_bar=top_bar), "q", rows=24
    )
    lines = visible(raw).split("\r\n")
    lines = lines[: next(i for i, line in enumerate(lines) if line.startswith("└")) + 1]  # one frame: drop the exit redraw
    inner_rule = max(i for i, line in enumerate(lines) if line.startswith("│" + "─" * 70))
    footer = next(i for i, line in enumerate(lines) if "of 100" in line)
    assert footer == inner_rule - 1
    shown = [line for line in lines if "OK  #" in line]
    assert len(shown) == 24 - chrome - 1  # every line of the column but the footer's


def test_a_short_list_has_no_footer():
    _, raw = drive(lambda: verification_screen._run_sidebar_detail_app("T", lambda: (ROWS[:5], DETAILS[:5])), "q", rows=24)
    assert "of 5" not in visible(raw) and "OK  #4" in visible(raw)


def test_a_list_that_exactly_fits_has_no_footer():
    lines_available = 24 - 4
    _, raw = drive(lambda: verification_screen._run_sidebar_detail_app("T", lambda: (ROWS[:lines_available], DETAILS[:lines_available])), "q", rows=24)
    text = visible(raw)
    assert "OK  #19" in text and f"of {lines_available}" not in text


# ---- a loading screen between the menu and the Verification screens ----------------------------------------------------

def spy_loading(monkeypatch):
    seen = []
    real = verification_screen.run_with_loading

    def spy(title, work, label="", status=None, cancel=None):
        seen.append((title, label))
        return real(title, work, label, status=status, cancel=cancel)

    monkeypatch.setattr(verification_screen, "run_with_loading", spy)
    return seen


def test_both_verification_screens_open_behind_a_loading_screen(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    seen = spy_loading(monkeypatch)
    drive(lambda: verification_screen.run_verification_screen({}), "q")
    drive(lambda: verification_screen.run_verify_chain_screen({}), "q")
    assert seen == [("Verification", "Checking the custody chain..."), ("Verify Chain", "Verifying the custody chain...")]


def test_the_loading_screen_is_drawn_before_the_verification_screen(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    text = stripped(drive(lambda: verification_screen.run_verification_screen({}), "q")[1])
    assert text.index("Checking the custody chain...") < text.index("Tab/←→ section")


def test_the_chain_is_checked_once_on_open_not_once_for_the_loading_screen_and_again_for_the_screen(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    calls = []
    real = verification_screen._run_chain_check
    monkeypatch.setattr(verification_screen, "_run_chain_check", lambda cfg=None: calls.append(1) or real(cfg))
    drive(lambda: verification_screen.run_verification_screen({}), "q")
    drive(lambda: verification_screen.run_verify_chain_screen({}), "q")
    assert len(calls) == 2  # one per screen opened


def test_keys_typed_ahead_during_the_loading_screen_reach_the_verification_screen(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result, raw = drive(lambda: verification_screen.run_verification_screen({}), "2q")  # jump to Evidence, then leave
    assert "Evidence" in stripped(raw)


def test_a_refresh_still_recomputes_without_a_second_loading_screen(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    seen = spy_loading(monkeypatch)
    drive(lambda: verification_screen.run_verify_chain_screen({}), "\x12q")  # Ctrl-R, then leave
    assert len(seen) == 1


# ---- the Merkle root and proof pages ------------------------------------------------------------------------------------

ROOT = "a" * 64
LEAF = "b" * 64
MERKLE_ROOT_OUTPUT = f"Merkle root over 2 evidence file(s)/folder(s): {ROOT}\n\n  EV001  {LEAF}\n  F1  {LEAF}  (214 files)"
MERKLE_PROOF_OUTPUT = '{\n  "evidence_id": "EV001",\n  "leaf": "' + LEAF + '",\n  "root": "' + ROOT + '",\n  "proof": {\n    "local_proof": []\n  }\n}'


def test_the_merkle_root_line_has_a_quiet_label_and_an_accented_root():
    frags = theme.colorize(MERKLE_ROOT_OUTPUT, "output", theme.make_theme("dark"))
    assert ("class:dim", "Merkle root over 2 evidence file(s)/folder(s):") in frags
    assert ("class:accent", ROOT) in frags


def test_the_items_under_the_root_show_the_id_plain_and_the_hash_and_file_count_dim():
    frags = theme.colorize(MERKLE_ROOT_OUTPUT, "output", theme.make_theme("dark"))
    assert ("class:dim", LEAF) in frags and ("class:dim", "  (214 files)") in frags
    assert ("", "EV001") in frags or ("", "  EV001") in frags


def test_the_proof_json_dims_its_keys_and_accents_the_root():
    frags = theme.colorize(MERKLE_PROOF_OUTPUT, "output", theme.make_theme("dark"))
    assert ("class:dim", '"leaf":') in frags and ("class:dim", '"evidence_id":') in frags
    assert ("class:accent", ROOT) in frags


def test_wrote_proof_is_a_success_line():
    assert theme.colorize("Wrote proof -> proof.json", "output", theme.make_theme("dark"))[0] == ("class:ok", "Wrote")


@pytest.mark.parametrize("text", [MERKLE_ROOT_OUTPUT, MERKLE_PROOF_OUTPUT, "Wrote proof -> proof.json", "Unknown evidence id: EV9", "No evidence registered yet."])
@pytest.mark.parametrize("name", ["dark", "light", "hc", "plain"])
def test_the_merkle_pages_rejoin_to_exactly_their_text(text, name):
    assert "".join(t for _, t in theme.colorize(text, "output", theme.make_theme(name))) == text


def test_the_merkle_root_page_draws_the_root_in_the_accent():
    _, raw = drive(lambda: forms.show_output("Merkle root", MERKLE_ROOT_OUTPUT), "x")
    assert ACCENT in ";".join(sequences(raw)) and ROOT[:30] in stripped(raw)  # the 64-character hash wraps onto a second line


# ---- styled() accepts a kind that can change -----------------------------------------------------------------------------

def test_styled_accepts_a_kind_chosen_at_draw_time():
    kind = ["sidebar"]
    render = theme.styled(lambda: "  [■■□□]  50%", lambda: kind[0])
    assert "".join(text for _, text in render()) == "  [■■□□]  50%"
    assert not any(style == "class:accent" for style, _ in render())  # as a sidebar row it is just text
    kind[0] = "loading"
    assert ("class:accent", "■■") in render()
