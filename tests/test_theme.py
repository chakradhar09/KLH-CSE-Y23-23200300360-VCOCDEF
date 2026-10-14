"""T1: the theme core is a pure style layer.

It decides colors, glyph fallback and the logo; it never edits the text the screens render. Every test that matters
here is therefore some form of "the fragments re-join to exactly the text that went in".
"""

from __future__ import annotations

import builtins
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from prompt_toolkit.styles import Style

from vcoc.interactive import theme
from vcoc.interactive.app import _render_menu
from vcoc.interactive.evidence_search import _format_result, _format_result_multi
from vcoc.interactive.loading import loading_text
from vcoc.interactive.verification_screen import _sidebar_text

LINUX_UTF8 = dict(platform="linux", encoding="utf-8")
ALL_THEMES = ["dark", "light", "hc", "plain"]


def joined(fragments) -> str:
    return "".join(text for _, text in fragments)


def styles_of(fragments, word: str) -> list[str]:
    return [style for style, text in fragments if word in text]


# ---- real renderer output used as fixtures -----------------------------------------------------------------------

def _rows():
    return [
        "OK  #0 register on EV001",
        "TAMPER  #1 analyze on EV002",
        "OK  #2 transfer on [EV004, EV005]",
        "!! EV004  (usb.bin)",
        "--  Merkle root over all evidence",
    ]


_EV = {"evidence_id": "EV001", "original_filename": "disk.E01", "sha256": "ab" * 32}

FIXTURES = {
    "menu": [(_render_menu(i), "menu") for i in range(9)],
    "sidebar": [(_sidebar_text(_rows(), sel, [0], 10), "sidebar") for sel in range(5)]
    + [(_sidebar_text(_rows() * 20, 3, [0], 10), "sidebar"), (_sidebar_text([], 0, [0], 10), "sidebar")],
    "detail": [
        ("entry: #4 analyze\nevidence_ids: EV002\nsignature: INVALID\nhash link: TAMPER, chain breaks at #4\nstatus: TAMPER DETECTED", "text"),
        ("re-hash: OK (matches recorded sha256)\ncustody log: logged\nsource_path: D:\\case\\a.bin", "text"),
        ("DOES NOT MATCH claimed root -- TAMPER DETECTED", "text"),
        ("MATCHES claimed root", "text"),
        ("Files recorded : 214 (1.8 GB)\nCustody event  : NOT logged (you chose not to log one)\n", "text"),
        ("", "text"),
        ("\n\n", "text"),
    ],
    "hint": [
        ("↑/↓ navigate   1-9,0 jump   Enter select   Esc/q quit", "hint"),
        (" Tab/↓ browse matches   Enter select/confirm   Esc cancel", "hint"),
        (" ↑/↓ select   PgUp/PgDn/Home/End jump   Space toggle   Enter confirm   Esc cancel", "hint"),
    ],
    "loading": [(loading_text("Adding evidence...", "Hashing file 3 of 9\n  a/b.bin (1.0 MB)", 4.2, "Esc cancels"), "text")],
    "results": [(_format_result(_EV, s), "text") for s in (True, False)]
    + [(_format_result_multi(_EV, s, c), "text") for s in (True, False) for c in (True, False)],
}
FIXTURES["tabs"] = [("  Chain  [ Evidence ]  Merkle  ", "tabs"), ("[ Chain ]   Evidence    Merkle  ", "tabs"), ("", "tabs")]
FIXTURES["list"] = [("▸ docs/\n  file.txt\n  OK report.txt", "list"), ("  (no matches)", "list"), ("", "list")]
FIXTURES["prompt"] = [(" Query:", "prompt"), (" Query:   (searching...)", "prompt"), (" Add evidence: File path:", "prompt")]
FIXTURES["plain"] = [("anything OK TAMPER ▸", "plain"), ("", "plain")]
FIXTURES["confirm"] = [(" Log a batch-register custody event for F1? [Y/n]: ", "confirm"), (" Keys not found. Generate? [y/N]: ", "confirm"), (" no brackets ", "confirm")]
FIXTURES["output"] = [
    ("Registered folder case_notes: 214 file(s)\n\nSummary\n  Files recorded : 214 (1.8 GB)\n  Custody event  : logged (batch-register)", "output"),
    ("Error: boom\nWarning: careful\nstatus: TAMPER DETECTED", "output"),
    ("{\n  \"leaf\": \"ab\",\n  \"proof\": []\n}", "output"),
]
_STATUS = "Hashing file 3 of 9\n  a/b.bin (1.0 MB)\n1.0 MB of 2.0 MB (50%)   1.0 MB/s   about 1.0 s left"
FIXTURES["loading_kind"] = [
    (loading_text("Adding evidence...", _STATUS + "\n\n" + theme.progress_bar(0.5), 4.2, "Esc cancels"), "loading"),
    (loading_text("Adding evidence...", "All 9 file(s) hashed (2.0 MB).\nRecording to the database...\n\n" + theme.progress_bar(1.0), 12.0), "loading"),
    (loading_text("Verifying...", theme.marquee(1.3), 1.3, "Cancelling... finishing the current file"), "loading"),
    (loading_text("Loading...", None, 0.0), "loading"),
]
ALL_FIXTURES = [pair for group in FIXTURES.values() for pair in group]


@pytest.mark.parametrize("name", ALL_THEMES)
@pytest.mark.parametrize("ansi16", [False, True])
def test_colorize_fragments_rejoin_to_exactly_the_input(name, ansi16):
    t = theme.make_theme(name, ansi16=ansi16)
    for text, kind in ALL_FIXTURES:
        assert joined(theme.colorize(text, kind, t)) == text, (kind, text)
        padded = joined(theme.colorize(text, kind, t, width=80)).split("\n")
        for out_line, in_line in zip(padded, text.split("\n")):  # only a selected row may grow, by trailing spaces only
            assert out_line.startswith(in_line) and not out_line[len(in_line):].strip(" "), (kind, in_line)


# ---- environment resolution --------------------------------------------------------------------------------------

def test_default_theme_is_dark_unicode():
    t = theme.resolve_theme({}, **LINUX_UTF8)
    assert t.name == "dark" and t.unicode is True


def test_no_color_wins_over_vcoc_theme():
    assert theme.resolve_theme({"NO_COLOR": "1", "VCOC_THEME": "light"}, **LINUX_UTF8).name == "plain"


def test_empty_no_color_is_ignored_per_convention():
    assert theme.resolve_theme({"NO_COLOR": "", "VCOC_THEME": "light"}, **LINUX_UTF8).name == "light"


def test_vcoc_theme_selects_a_preset_and_accepts_the_long_name_for_high_contrast():
    assert theme.resolve_theme({"VCOC_THEME": "light"}, **LINUX_UTF8).name == "light"
    assert theme.resolve_theme({"VCOC_THEME": "HC"}, **LINUX_UTF8).name == "hc"
    assert theme.resolve_theme({"VCOC_THEME": "high-contrast"}, **LINUX_UTF8).name == "hc"


def test_unknown_vcoc_theme_falls_back_to_dark():
    assert theme.resolve_theme({"VCOC_THEME": "neon"}, **LINUX_UTF8).name == "dark"


def test_term_dumb_means_plain_and_ascii():
    t = theme.resolve_theme({"TERM": "dumb"}, **LINUX_UTF8)
    assert t.name == "plain" and t.unicode is False


@pytest.mark.parametrize(
    "env, platform, encoding, expected",
    [
        ({}, "linux", "utf-8", True),
        ({"TERM": "xterm-256color"}, "linux", "UTF-8", True),
        ({"TERM": "linux"}, "linux", "utf-8", False),  # the Linux virtual console
        ({}, "linux", "latin-1", False),  # not a UTF-8 locale
        ({"WT_SESSION": "abc"}, "win32", "utf-8", True),  # Windows Terminal
        ({"TERM_PROGRAM": "vscode"}, "win32", "utf-8", True),
        ({"ConEmuANSI": "ON"}, "win32", "utf-8", True),
        ({"TERM": "xterm-256color"}, "win32", "utf-8", True),  # mintty / Git Bash
        ({"VCOC_ASCII": "1", "WT_SESSION": "abc"}, "win32", "utf-8", False),  # explicit override beats detection
        ({"VCOC_ASCII": "0", "TERM": "linux"}, "linux", "latin-1", True),
    ],
)
def test_unicode_detection(env, platform, encoding, expected):
    assert theme.resolve_theme(env, platform=platform, encoding=encoding).unicode is expected


WINDOWS_11 = 22631  # build number
WINDOWS_10_2016 = 14393  # before the console understood escape sequences


def test_windows_11_gets_unicode_even_when_no_known_terminal_announces_itself():
    """The classic console window, PyCharm's terminal and shells started through other tools set none of the markers."""
    assert theme.resolve_theme({}, platform="win32", encoding="utf-8", win_build=WINDOWS_11).unicode is True


def test_windows_ignores_a_non_utf8_python_stdout_encoding():
    """Python reports cp1252 whenever stdout is redirected; the console itself is still drawn through the Unicode API."""
    assert theme.resolve_theme({}, platform="win32", encoding="cp1252", win_build=WINDOWS_11).unicode is True


def test_a_pre_2018_windows_console_without_a_modern_terminal_falls_back_to_ascii():
    assert theme.resolve_theme({}, platform="win32", encoding="utf-8", win_build=WINDOWS_10_2016).unicode is False
    assert theme.resolve_theme({"WT_SESSION": "abc"}, platform="win32", encoding="utf-8", win_build=WINDOWS_10_2016).unicode is True


def test_windows_still_honors_the_explicit_ascii_override_and_term_dumb():
    assert theme.resolve_theme({"VCOC_ASCII": "1"}, platform="win32", encoding="utf-8", win_build=WINDOWS_11).unicode is False
    assert theme.resolve_theme({"TERM": "dumb"}, platform="win32", encoding="utf-8", win_build=WINDOWS_11).unicode is False


def test_non_windows_still_requires_a_utf8_encoding():
    assert theme.resolve_theme({}, platform="linux", encoding="cp1252", win_build=WINDOWS_11).unicode is False


def test_ansi16_and_hc_and_plain_use_reverse_selection_and_truecolor_dark_uses_a_tint():
    assert theme.resolve_theme({}, **LINUX_UTF8).reverse_selection is False
    assert theme.resolve_theme({}, ansi16=True, **LINUX_UTF8).reverse_selection is True
    assert theme.make_theme("hc").reverse_selection is True
    assert theme.make_theme("plain").reverse_selection is True


# ---- presets and the prompt_toolkit Style -------------------------------------------------------------------------

@pytest.mark.parametrize("name", ALL_THEMES)
@pytest.mark.parametrize("ansi16", [False, True])
def test_every_preset_builds_a_style_for_every_role(name, ansi16):
    t = theme.make_theme(name, ansi16=ansi16)
    style = theme.app_style(t)
    assert isinstance(style, Style)
    for role in ("chrome", "dim", "accent", "ok", "tamper", "warn", "sel", "bgsel", "b", "frame.border", "frame.label"):
        assert role in t.rules, role
        style.get_attrs_for_style_str(f"class:{role}")  # must not raise


def test_dark_ok_is_green_and_tamper_is_bold_red():
    style = theme.app_style(theme.make_theme("dark"))
    ok = style.get_attrs_for_style_str("class:ok")
    tamper = style.get_attrs_for_style_str("class:tamper")
    assert ok.color == "5fb878" and tamper.color == "ff6b68" and tamper.bold is True


def test_tint_selection_combines_a_verdict_color_with_the_row_background():
    attrs = theme.app_style(theme.make_theme("dark")).get_attrs_for_style_str("class:ok class:bgsel")
    assert attrs.color == "5fb878" and attrs.bgcolor == "262c35"


def test_plain_theme_defines_no_colors_only_attributes():
    style = theme.app_style(theme.make_theme("plain"))
    for role in ("chrome", "dim", "accent", "ok", "tamper", "warn", "sel", "b"):
        attrs = style.get_attrs_for_style_str(f"class:{role}")
        assert not attrs.color and not attrs.bgcolor, role
    tamper = style.get_attrs_for_style_str("class:tamper")
    assert tamper.bold and tamper.reverse


def test_high_contrast_tamper_is_a_red_background():
    attrs = theme.app_style(theme.make_theme("hc")).get_attrs_for_style_str("class:tamper")
    assert attrs.bgcolor == "ff5252" and attrs.bold is True


def test_ansi16_presets_use_only_ansi_color_names():
    for name in ("dark", "light"):
        for role, rule in theme.make_theme(name, ansi16=True).rules.items():
            for part in rule.split():
                if part.startswith(("fg:", "bg:")):
                    assert part[3:].startswith("ansi"), (name, role, rule)


# ---- colorize rules -----------------------------------------------------------------------------------------------

def test_verdict_words_get_the_right_class():
    t = theme.make_theme("dark")
    frags = theme.colorize(
        "status: OK\nhash link: TAMPER, chain breaks\nsignature: INVALID\nre-hash: MISMATCH\ncustody log: NOT logged\nsomething STALE\n",
        "text",
        t,
    )
    assert "class:ok" in styles_of(frags, "OK")
    assert "class:tamper" in styles_of(frags, "TAMPER")
    assert "class:tamper" in styles_of(frags, "INVALID")
    assert "class:tamper" in styles_of(frags, "MISMATCH")
    assert "class:warn" in styles_of(frags, "NOT logged")
    assert "class:warn" in styles_of(frags, "STALE")


def test_multiword_verdicts_are_one_fragment():
    t = theme.make_theme("dark")
    bad = theme.colorize("DOES NOT MATCH claimed root -- TAMPER DETECTED", "text", t)
    assert ("class:tamper", "DOES NOT MATCH claimed root") in bad
    assert ("class:tamper", "TAMPER DETECTED") in bad
    assert ("class:ok", "MATCHES claimed root") in theme.colorize("MATCHES claimed root", "text", t)


def test_leading_label_is_dim_and_the_value_is_not():
    frags = theme.colorize("actor: j.chakri", "text", theme.make_theme("dark"))
    assert frags[0] == ("class:dim", "actor:")
    assert all(style != "class:dim" for style, text in frags[1:])


def test_a_timestamp_value_is_not_split_into_a_second_label():
    frags = theme.colorize("timestamp: 2026-09-30T09:12:04Z", "text", theme.make_theme("dark"))
    assert frags[0] == ("class:dim", "timestamp:") and joined(frags) == "timestamp: 2026-09-30T09:12:04Z"


def test_menu_row_digit_is_dim_and_hint_descriptions_are_dim():
    frags = theme.colorize(_render_menu(0), "menu", theme.make_theme("dark"))
    assert ("class:dim", "2") in frags
    assert ("class:dim", " navigate") in frags and ("", "↑/↓") in frags


def test_selected_menu_row_is_one_selected_fragment_and_other_rows_are_not():
    frags = theme.colorize(_render_menu(3), "menu", theme.make_theme("dark"))
    assert ("class:sel", "▸ 4  Verify chain") in frags
    assert not any(style == "class:sel" and "Add evidence" in text for style, text in frags)


def test_sidebar_verdicts_are_colored_and_the_selected_row_keeps_its_verdict_on_a_tint_theme():
    dark = theme.make_theme("dark")
    frags = theme.colorize(_sidebar_text(_rows(), 1, [0], 10), "sidebar", dark)
    assert ("class:ok", "OK") in frags
    selected_verdict = [style for style, text in frags if text == "TAMPER"]
    assert selected_verdict == ["class:tamper class:bgsel"]


def test_sidebar_selected_row_is_one_reverse_fragment_on_a_reverse_theme():
    frags = theme.colorize(_sidebar_text(_rows(), 1, [0], 10), "sidebar", theme.make_theme("plain"))
    assert ("class:sel", "▸ TAMPER  #1 analyze on EV002") in frags


def test_sidebar_position_footer_and_empty_messages_are_dim():
    t = theme.make_theme("dark")
    frags = theme.colorize(_sidebar_text(_rows() * 20, 3, [0], 10), "sidebar", t)
    assert frags[-1][0] == "class:dim" and "of 100" in frags[-1][1]
    assert theme.colorize("  (no matches)", "sidebar", t) == [("class:dim", "  (no matches)")]


def test_selected_row_is_padded_to_the_requested_width_with_the_row_background():
    t = theme.make_theme("dark")
    frags = theme.colorize("▸ 1  Add evidence", "menu", t, width=30)
    assert joined(frags) == "▸ 1  Add evidence".ljust(30)
    assert frags[-1][0] == "class:bgsel"
    assert joined(theme.colorize("  2  Check evidence integrity", "menu", t, width=60)) == "  2  Check evidence integrity"


def test_padding_never_truncates_a_longer_row():
    t = theme.make_theme("dark")
    row = "▸ 8  Verification (chain / evidence / merkle)"
    assert joined(theme.colorize(row, "menu", t, width=10)) == row


# ---- ASCII fallback -----------------------------------------------------------------------------------------------

def test_to_ascii_leaves_no_non_ascii_character_for_every_glyph_the_screens_use():
    glyphs = "▸─│┌┐└┘┤├╭╮╰╯━◆■□●◐✖·—↑↓←→▼█…"
    out = joined(theme.to_ascii([("class:chrome", glyphs)]))
    assert out.isascii() and len(out) == len(glyphs)


def test_to_ascii_keeps_styles_and_plain_text_and_marks_unknown_glyphs():
    assert theme.to_ascii([("class:ok", "OK"), ("", " ▸ é")]) == [("class:ok", "OK"), ("", " > ?")]


def test_to_ascii_preserves_the_width_of_every_row():
    row = "┌─┤ Verify ├────┐"
    assert len(joined(theme.to_ascii([("", row)]))) == len(row)


def test_for_display_only_transliterates_when_the_theme_is_ascii():
    frags = [("", "▸ x")]
    assert theme.for_display(frags, theme.make_theme("dark", unicode=True)) == frags
    assert theme.for_display(frags, theme.make_theme("dark", unicode=False)) == [("", "> x")]


# ---- logo ---------------------------------------------------------------------------------------------------------

def test_logo_is_three_lines_at_24_rows_or_more():
    for rows in (24, 30, 80):
        lines = theme.logo_lines(rows)
        assert len(lines) == 3
        assert "VCoC" in joined(lines[1]) and "Verifiable Chain-of-Custody" in joined(lines[1])


def test_logo_is_one_line_between_18_and_23_rows():
    for rows in (18, 20, 23):
        lines = theme.logo_lines(rows)
        assert len(lines) == 1 and "VCoC" in joined(lines[0])


def test_logo_is_absent_below_18_rows():
    for rows in (0, 10, 15, 17):
        assert theme.logo_lines(rows) == []


def test_logo_fits_an_80_column_terminal_and_survives_the_ascii_fallback():
    for rows in (24, 20):
        for line in theme.logo_lines(rows):
            text = joined(line)
            assert len(text) <= 78
            ascii_text = joined(theme.to_ascii(line))
            assert ascii_text.isascii() and len(ascii_text) == len(text)


def test_logo_is_the_witness_shield_an_outlined_half_and_a_solid_half():
    full = theme.logo_lines(24)
    assert [joined(line)[:7] for line in full] == [" ▛▀▌▐██", " ▌ ▌▐██", " ▝▚▌▐▛▘"]
    assert [(line[1], line[2]) for line in full] == [(("class:b", "▛▀▌"), ("class:accent", "▐██")), (("class:b", "▌ ▌"), ("class:accent", "▐██")),
                                                     (("class:b", "▝▚▌"), ("class:accent", "▐▛▘"))]  # left the outline in text colour, right solid accent


def test_logo_marks_are_the_same_width_on_every_line_so_the_text_after_them_lines_up():
    full = theme.logo_lines(24)
    assert all(joined(line)[7:9].strip() == "" for line in full)  # a 7-column mark (a space and the 6-column shield), then the text
    assert joined(full[1]).index("VCoC") == 9  # the mark, two spaces, the name


def test_ascii_logo_is_a_drawn_shield_of_the_same_size_not_question_marks():
    for rows in (24, 20):
        uni, asc = theme.logo_lines(rows), theme.logo_lines(rows, unicode=False)
        assert [joined(line) for line in asc] == [joined(theme.to_ascii(line)) for line in asc]  # already plain ASCII
        assert all(joined(line).isascii() and "?" not in joined(line) for line in asc)
        assert [len(joined(line)) for line in asc] == [len(joined(line)) for line in uni]
    assert [joined(line)[:7] for line in theme.logo_lines(24, unicode=False)] == [" +-+ ##", " | | ##", " \\_| #/"]


def test_one_line_logo_is_the_two_halves_of_the_shield_then_the_name():
    line = theme.logo_lines(20)[0]
    assert joined(line).startswith(" ▜▌▐▛ VCoC") and ("class:b", "▜▌") in line and ("class:accent", "▐▛") in line


# ---- Phase 2 rules: tabs, lists, results, prompts, confirm, command output -----------------------------------------

def test_active_tab_is_accent_and_the_others_are_dim():
    frags = theme.colorize("  Chain  [ Evidence ]  Merkle  ", "tabs", theme.make_theme("dark"))
    assert ("class:accent", "[ Evidence ]") in frags
    assert [text for style, text in frags if style == "class:dim"] == ["  Chain  ", "  Merkle  "]


def test_list_rows_have_a_selected_row_and_never_a_verdict_color():
    dark = theme.make_theme("dark")
    frags = theme.colorize("▸ docs/\n  file.txt\n  OK report.txt", "list", dark)
    assert ("class:sel", "▸ docs/") in frags
    assert not any(style in ("class:ok", "class:tamper") for style, _ in frags)  # a file called "OK report" is just a file
    assert theme.colorize("  (no matches)", "list", dark) == [("class:dim", "  (no matches)")]


def test_search_results_dim_the_hash_prefix_and_accent_a_ticked_box():
    dark = theme.make_theme("dark")
    unticked = theme.colorize(_format_result(_EV, False), "results", dark)
    assert unticked[-1] == ("class:dim", "abababab...")
    ticked = theme.colorize(_format_result_multi(_EV, False, True), "results", dark)
    assert ("class:accent", "[x]") in ticked and ("", "[ ]") not in ticked
    selected = theme.colorize(_format_result(_EV, True), "results", dark)
    assert selected[-1] == ("class:dim class:bgsel", "abababab...")  # keeps its own color on the tint
    assert theme.colorize("  (searching...)", "results", dark) == [("class:dim", "  (searching...)")]


def test_prompt_lines_are_plain_except_a_parenthesised_status_which_is_dim():
    dark = theme.make_theme("dark")
    assert theme.colorize(" Actor:", "prompt", dark) == [("", " Actor:")]
    assert theme.colorize(" Query:   (searching...)", "prompt", dark) == [("", " Query:"), ("class:dim", "   (searching...)")]


def test_plain_kind_never_colors_anything():
    assert theme.colorize("status: OK TAMPER", "plain", theme.make_theme("dark")) == [("", "status: OK TAMPER")]


def test_confirm_accents_only_the_default_answer():
    dark = theme.make_theme("dark")
    no = theme.colorize(" Proceed? [y/N]: ", "confirm", dark)
    assert ("class:accent", "N") in no and ("class:dim", "y") in no
    yes = theme.colorize(" Proceed? [Y/n]: ", "confirm", dark)
    assert ("class:accent", "Y") in yes and ("class:dim", "n") in yes


def test_command_output_rules():
    dark = theme.make_theme("dark")
    frags = theme.colorize("Registered folder x: 1 file(s)\nSummary\n  Custody event  : NOT logged\nError: boom", "output", dark)
    assert frags[0] == ("class:ok", "Registered")
    assert ("class:accent", "Summary") in frags
    assert ("class:dim", "  Custody event  :") in frags and ("class:warn", "NOT logged") in frags
    assert ("class:warn", "Error:") in frags


# ---- Phase 3: the progress bar, the marquee and the loading screen's rules -------------------------------------------

def test_progress_bar_fills_in_proportion_and_ends_with_the_percentage():
    assert theme.progress_bar(0.0) == "[" + "□" * 40 + "]  0%"
    assert theme.progress_bar(0.5) == "[" + "■" * 20 + "□" * 20 + "]  50%"
    assert theme.progress_bar(1.0) == "[" + "■" * 40 + "]  100%"
    assert theme.progress_bar(0.25, width=8) == "[■■□□□□□□]  25%"


def test_progress_bar_never_claims_to_be_finished_early_and_clamps_out_of_range_values():
    almost = theme.progress_bar(0.999)
    assert almost.endswith("99%") and "□" in almost  # 99.9% is not 100%
    assert theme.progress_bar(-3) == theme.progress_bar(0.0)
    assert theme.progress_bar(7) == theme.progress_bar(1.0)


def test_progress_bar_survives_the_ascii_fallback_with_the_same_width():
    bar = theme.progress_bar(0.5)
    ascii_bar = joined(theme.to_ascii([("", bar)]))
    assert ascii_bar == "[" + "#" * 20 + "." * 20 + "]  50%" and len(ascii_bar) == len(bar)


def test_marquee_is_a_fixed_width_track_with_one_moving_block():
    for elapsed in (0.0, 0.4, 1.3, 7.7):
        line = theme.marquee(elapsed)
        assert len(line) == 42 and line[0] == "[" and line[-1] == "]"
        assert line.count("■") <= 8 and set(line[1:-1]) <= {"■", "·"}


def test_marquee_moves_over_time_and_repeats():
    assert theme.marquee(0.0) != theme.marquee(0.5)
    period = (40 + 8) / 14  # track plus block, at the marquee's speed
    assert theme.marquee(1.0) == theme.marquee(1.0 + period)


def test_progress_bar_line_is_colored_accent_while_running_and_green_when_complete():
    dark = theme.make_theme("dark")
    running = theme.colorize("  " + theme.progress_bar(0.5), "loading", dark)
    assert ("class:chrome", "[") in running and ("class:accent", "■" * 20) in running and ("class:chrome", "□" * 20) in running
    done = theme.colorize("  " + theme.progress_bar(1.0), "loading", dark)
    assert ("class:ok", "■" * 40) in done and ("class:ok", "  100%") in done


def test_marquee_line_is_an_accent_block_on_a_chrome_track():
    frags = theme.colorize("  " + theme.marquee(0.5), "loading", theme.make_theme("dark"))
    assert any(style == "class:accent" and set(text) == {"■"} for style, text in frags)
    assert any(style == "class:chrome" and "·" in text for style, text in frags)


def test_loading_screen_clock_hint_and_file_path_are_dim_and_cancelling_is_a_warning():
    dark = theme.make_theme("dark")
    frags = theme.colorize(loading_text("Adding...", _STATUS, 4.2, "Esc cancels"), "loading", dark)
    assert ("class:dim", "  4.2 s") in frags and ("class:dim", "  Esc cancels") in frags
    assert ("class:dim", "    a/b.bin (1.0 MB)") in frags
    cancelling = theme.colorize(loading_text("Adding...", None, 1.0, "Cancelling... finishing the current file"), "loading", dark)
    assert ("class:warn", "  Cancelling... finishing the current file") in cancelling


def test_a_file_named_like_a_verdict_is_not_colored_on_the_loading_screen():
    frags = theme.colorize("  Hashing file 1 of 2\n    OK_TAMPER_report.txt (1.0 KB)", "loading", theme.make_theme("dark"))
    assert not any(style in ("class:ok", "class:tamper") for style, _ in frags)


# ---- styled(), glyph(), the input frame and the lexer ---------------------------------------------------------------

def test_styled_turns_a_string_renderer_into_fragments_for_the_current_theme():
    theme.set_current(theme.make_theme("dark"))
    try:
        assert ("class:ok", "OK") in theme.styled(lambda: "status: OK", "text")()
        theme.set_current(theme.make_theme("dark", unicode=False))
        assert theme.styled(lambda: "↑/↓ x", "hint")() == [("", "^/v"), ("class:dim", " x")]
        padded = theme.styled(lambda: "▸ a", "list", width=lambda: 10)()
        assert joined(padded) == "> a".ljust(10)
    finally:
        theme.set_current(None)


def test_glyph_gives_the_unicode_character_or_its_ascii_stand_in():
    assert theme.glyph("─", theme.make_theme("dark")) == "─"
    assert theme.glyph("─", theme.make_theme("dark", unicode=False)) == "-"
    assert theme.glyph("│", theme.make_theme("dark", unicode=False)) == "|"


@pytest.mark.parametrize("name, color", [("dark", "d9a441"), ("light", "8a5000"), ("hc", "ffd400")])
def test_a_framed_input_uses_the_accent_color_for_its_border(name, color):
    style = theme.app_style(theme.make_theme(name))
    assert style.get_attrs_for_style_str("class:input class:frame.border").color == color
    assert style.get_attrs_for_style_str("class:frame.border").color != color  # other frames stay chrome


def test_lexer_colors_each_line_like_colorize_and_follows_the_ascii_fallback():
    from prompt_toolkit.document import Document

    theme.set_current(theme.make_theme("dark"))
    try:
        doc = Document("Registered folder x: 1 file(s)\nSummary\n  Files recorded : 2\nstatus: TAMPER DETECTED\n")
        get_line = theme.ThemeLexer().lex_document(doc)
        assert get_line(0)[0] == ("class:ok", "Registered")
        assert get_line(1) == [("class:accent", "Summary")]
        assert joined(get_line(2)) == "  Files recorded : 2"
        assert ("class:tamper", "TAMPER DETECTED") in get_line(3)
        theme.set_current(theme.make_theme("dark", unicode=False))
        assert joined(theme.ThemeLexer().lex_document(Document("→ ok\n"))(0)) == "> ok"
    finally:
        theme.set_current(None)


# ---- Phase 4: color depth, the Linux console palette and readability ------------------------------------------------

import re

from prompt_toolkit.output import ColorDepth


class FakeOutput:
    def __init__(self, depth):
        self._depth = depth

    def get_default_color_depth(self):
        return self._depth


def test_detected_depth_is_what_the_terminal_reports(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("PROMPT_TOOLKIT_COLOR_DEPTH", raising=False)
    assert theme.detect_color_depth(FakeOutput(ColorDepth.DEPTH_4_BIT)) == ColorDepth.DEPTH_4_BIT
    assert theme.detect_color_depth(FakeOutput(ColorDepth.DEPTH_24_BIT)) == ColorDepth.DEPTH_24_BIT


def test_no_color_and_the_prompt_toolkit_override_beat_what_the_terminal_reports(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert theme.detect_color_depth(FakeOutput(ColorDepth.DEPTH_24_BIT)) == ColorDepth.DEPTH_1_BIT
    monkeypatch.delenv("NO_COLOR")
    monkeypatch.setenv("PROMPT_TOOLKIT_COLOR_DEPTH", "DEPTH_8_BIT")
    assert theme.detect_color_depth(FakeOutput(ColorDepth.DEPTH_24_BIT)) == ColorDepth.DEPTH_8_BIT


def test_a_broken_output_falls_back_to_the_default_depth(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("PROMPT_TOOLKIT_COLOR_DEPTH", raising=False)

    class Broken:
        def get_default_color_depth(self):
            raise RuntimeError("no console")

    assert theme.detect_color_depth(Broken()) == ColorDepth.DEFAULT


@pytest.mark.parametrize("depth", [ColorDepth.DEPTH_24_BIT, ColorDepth.DEPTH_8_BIT])
def test_256_and_truecolor_terminals_get_the_hex_palette(depth):
    t = theme.resolve_theme({}, color_depth=depth, **LINUX_UTF8)
    assert t.rules == theme.make_theme("dark").rules and t.reverse_selection is False


def test_a_16_color_terminal_gets_ansi_names_and_a_reversed_selection():
    t = theme.resolve_theme({"VCOC_THEME": "light"}, color_depth=ColorDepth.DEPTH_4_BIT, **LINUX_UTF8)
    assert t.name == "light" and t.rules == theme.make_theme("light", ansi16=True).rules and t.reverse_selection is True


def test_a_one_bit_terminal_gets_the_plain_theme_whatever_was_asked_for():
    t = theme.resolve_theme({"VCOC_THEME": "light"}, color_depth=ColorDepth.DEPTH_1_BIT, **LINUX_UTF8)
    assert t.name == "plain"


def test_no_color_still_beats_a_color_capable_terminal():
    assert theme.resolve_theme({"NO_COLOR": "1"}, color_depth=ColorDepth.DEPTH_24_BIT, **LINUX_UTF8).name == "plain"


def test_the_linux_console_gets_its_own_palette_with_bright_colors_and_no_dim_gray():
    vt = theme.resolve_theme({"TERM": "linux"}, color_depth=ColorDepth.DEPTH_4_BIT, **LINUX_UTF8)
    assert vt.rules["accent"] == "fg:ansibrightyellow" and vt.rules["ok"] == "fg:ansibrightgreen"
    assert vt.rules["tamper"] == "bold fg:ansibrightred"
    assert vt.rules["chrome"] == "" and vt.rules["dim"] == ""  # "bright black" is nearly invisible on a Linux console
    assert vt.rules != theme.make_theme("dark", ansi16=True).rules and vt.unicode is False


def test_other_16_color_terminals_keep_the_generic_ansi_palette():
    other = theme.resolve_theme({"TERM": "xterm"}, color_depth=ColorDepth.DEPTH_4_BIT, **LINUX_UTF8)
    assert other.rules == theme.make_theme("dark", ansi16=True).rules


def _luminance(hex_color: str) -> float:
    channels = [int(hex_color[i : i + 2], 16) / 255 for i in (1, 3, 5)]
    channels = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]


def _contrast(a: str, b: str) -> float:
    high, low = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def _color(rule: str, kind: str = "fg") -> str:
    return re.search(rf"{kind}:(#[0-9a-f]{{6}})", rule).group(1)


# Backgrounds real terminals ship with: Windows Terminal Campbell, VS Code, One Dark, Ubuntu, Solarized, Dracula, ...
DARK_BACKGROUNDS = ["#000000", "#0c0c0c", "#12151a", "#1e1e1e", "#282c34", "#300a24", "#002b36", "#282a36"]
LIGHT_BACKGROUNDS = ["#ffffff", "#f6f5f1", "#fdf6e3", "#eeeeee"]
TEXT_ROLES = ("dim", "accent", "ok", "tamper", "warn")


@pytest.mark.parametrize("name, backgrounds", [("dark", DARK_BACKGROUNDS), ("light", LIGHT_BACKGROUNDS)])
def test_text_colors_are_readable_on_the_backgrounds_terminals_actually_use(name, backgrounds):
    rules = theme.make_theme(name).rules
    for background in backgrounds:
        for role in TEXT_ROLES:
            assert _contrast(_color(rules[role]), background) >= 4.5, (name, role, background)
        assert _contrast(_color(rules["chrome"]), background) >= 3.0, (name, "chrome", background)  # lines, not text


@pytest.mark.parametrize("name", ["dark", "light"])
def test_text_stays_readable_on_the_selected_row_tint(name):
    rules = theme.make_theme(name).rules
    tint = _color(rules["bgsel"], "bg")
    assert _contrast(_color(rules["sel"]), tint) >= 4.5
    for role in TEXT_ROLES:
        assert _contrast(_color(rules[role]), tint) >= 4.5, (name, role)


def test_high_contrast_is_readable_on_black_and_its_tamper_badge_has_a_readable_pair():
    rules = theme.make_theme("hc").rules
    for role in ("dim", "accent", "ok", "warn", "chrome"):
        assert _contrast(_color(rules[role]), "#000000") >= 7.0, role
    assert _contrast(_color(rules["tamper"]), _color(rules["tamper"], "bg")) >= 4.5


ANSI_NAMES = {  # (name, hex) per canonical palette: Windows Terminal Campbell, xterm, the Linux console (VGA)
    "campbell": ("#0c0c0c", {"ansibrightblack": "#767676", "ansiyellow": "#c19c00", "ansibrightgreen": "#16c60c", "ansibrightred": "#e74856", "ansibrightyellow": "#f9f1a5"}),
    "xterm": ("#000000", {"ansibrightblack": "#7f7f7f", "ansiyellow": "#cdcd00", "ansibrightgreen": "#00ff00", "ansibrightred": "#ff0000", "ansibrightyellow": "#ffff00"}),
    "vga": ("#000000", {"ansibrightblack": "#555555", "ansiyellow": "#aa5500", "ansibrightgreen": "#55ff55", "ansibrightred": "#ff5555", "ansibrightyellow": "#ffff55"}),
}


def _ansi_contrast(rule: str, palette: str) -> float | None:
    background, colors = ANSI_NAMES[palette]
    name = re.search(r"fg:(ansi\w+)", rule)
    return None if name is None else _contrast(colors[name.group(1)], background)


@pytest.mark.parametrize("palette", ["campbell", "xterm"])
def test_the_16_color_dark_palette_is_readable_on_common_ansi_palettes(palette):
    rules = theme.make_theme("dark", ansi16=True).rules
    for role in ("accent", "ok", "tamper", "warn"):
        assert _ansi_contrast(rules[role], palette) >= 4.5, (palette, role)
    assert _ansi_contrast(rules["dim"], palette) >= 4.0, palette  # bright black: Campbell's 4.3 is the weakest


def test_the_linux_console_palette_is_readable_on_the_vga_palette():
    vt = theme.resolve_theme({"TERM": "linux"}, color_depth=ColorDepth.DEPTH_4_BIT, **LINUX_UTF8).rules
    for role in ("accent", "ok", "tamper", "warn"):
        assert _ansi_contrast(vt[role], "vga") >= 4.5, role


# ---- purity and cost ----------------------------------------------------------------------------------------------

def test_theme_does_no_file_io(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("theme must not open files")

    monkeypatch.setattr(builtins, "open", boom)
    t = theme.resolve_theme({"VCOC_THEME": "light"}, **LINUX_UTF8)
    theme.colorize(_render_menu(0), "menu", t, width=80)
    theme.app_style(t)
    theme.logo_lines(24)
    theme.to_ascii([("", "▸")])


def test_colorize_of_a_full_window_is_fast():
    t = theme.make_theme("dark")
    text = "\n".join(_rows() * 20)  # 100 lines, more than any real terminal shows
    best = min(_timed(lambda: theme.colorize(text, "sidebar", t)) for _ in range(5))
    assert best < 0.005, f"colorize took {best * 1000:.2f} ms for 100 lines"


def _timed(fn) -> float:
    start = time.perf_counter()
    fn()
    return time.perf_counter() - start
