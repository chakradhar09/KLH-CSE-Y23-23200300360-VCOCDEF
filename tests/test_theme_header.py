"""T13: the main menu's status header and the frame that follows the chain's state.

The header reports the last *known* verification; it never runs one, never creates the database, and can never leave a
stale "CLEAN" on screen after evidence was added.
"""

from __future__ import annotations

import os
import re
import sqlite3
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from test_last_verify import at, make_db, status_of
from test_theme_screens import TAMPER_RED, WARN, drive, sequences, visible
from vcoc import db
from vcoc.ecdsa_signer import generate_keypair, save_keypair
from vcoc.hash_chain import HashChain
from vcoc.interactive import app, status, theme

NOW = at(2, 16, 30)


@pytest.fixture(autouse=True)
def _reset_current_theme():
    yield
    theme.set_current(None)


def joined(fragments) -> str:
    return "".join(text for _, text in fragments)


def everything(raw: str) -> str:
    """All the text the terminal was sent, escape sequences stripped."""
    return re.sub(r"\r(?!\n)", "", re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", raw))


# ---- colors ----------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize(
    "result, token, style",
    [
        (status_of("clean"), "● CLEAN", "class:ok"),
        (status_of("stale", new=3), "◐ STALE", "class:warn"),
        (status_of("stale", new=3), "3 new", "class:warn"),
        (status_of("tamper", bad_event=4), "✖ TAMPER", "class:tamper"),
        (status_of("unverified"), "○ not verified yet", "class:dim"),
    ],
)
def test_header_colors_each_state(result, token, style):
    frags = theme.colorize(status.header_text(result, now=NOW), "header", theme.make_theme("dark"))
    assert (style, token) in frags


def test_header_fragments_rejoin_to_the_header_text_for_every_state():
    dark = theme.make_theme("dark")
    for state in ("clean", "stale", "tamper", "unverified", "nodb", "unavailable"):
        text = status.header_text(status_of(state, new=3, bad_event=4), now=NOW)
        assert joined(theme.colorize(text, "header", dark)) == text


def test_header_labels_and_separators_are_quiet():
    frags = theme.colorize(status.header_text(status_of("clean"), now=NOW), "header", theme.make_theme("dark"))
    assert ("class:dim", " DB") in frags and ("class:chrome", "│") in frags
    assert any(style == "class:dim" and text.startswith("verified") for style, text in frags)


def test_the_unverified_circle_has_an_ascii_stand_in():
    assert joined(theme.to_ascii([("", "○ ◐ ● ✖")])) == "o ~ * x"


@pytest.mark.parametrize("name", ["dark", "light", "hc", "plain"])
@pytest.mark.parametrize("ansi16", [False, True])
def test_every_preset_has_a_frame_border_for_the_stale_and_tamper_states(name, ansi16):
    style = theme.app_style(theme.make_theme(name, ansi16=ansi16))
    for state in ("state-stale", "state-tamper"):
        style.get_attrs_for_style_str(f"class:{state} class:frame.border")  # must not raise


def test_the_dark_frame_turns_amber_when_stale_and_bold_red_when_tampered():
    style = theme.app_style(theme.make_theme("dark"))
    assert style.get_attrs_for_style_str("class:state-stale class:frame.border").color == "e8944a"
    tamper = style.get_attrs_for_style_str("class:state-tamper class:frame.border")
    assert tamper.color == "ff6b68" and tamper.bold is True
    assert style.get_attrs_for_style_str("class:frame.border").color == "78838e"  # a clean frame stays grey


def test_the_high_contrast_tamper_frame_uses_the_red_not_the_black_text_color():
    assert theme.app_style(theme.make_theme("hc")).get_attrs_for_style_str("class:state-tamper class:frame.border").color == "ff5252"


def test_the_plain_theme_marks_a_tamper_frame_with_bold_only():
    attrs = theme.app_style(theme.make_theme("plain")).get_attrs_for_style_str("class:state-tamper class:frame.border")
    assert attrs.bold is True and not attrs.color


# ---- layout ----------------------------------------------------------------------------------------------------------

def test_the_header_block_is_the_line_a_rule_and_a_blank_from_20_rows_just_the_line_from_16_and_absent_below():
    dark = theme.make_theme("dark")
    result = status_of("clean")
    tall = joined(app._header_fragments(result, dark, 24, 78))
    assert tall.count("\n") == 3 and "─" * 78 in tall and "CLEAN" in tall  # the line, the rule and a blank line each end a line
    assert joined(app._header_fragments(result, dark, 20, 78)).count("\n") == 3
    short = joined(app._header_fragments(result, dark, 19, 78))
    assert short.count("\n") == 1 and "CLEAN" in short
    assert joined(app._header_fragments(result, dark, 16, 78)).count("\n") == 1
    assert app._header_fragments(result, dark, 15, 78) == []
    assert app._header_fragments(None, dark, 24, 78) == []


def test_the_header_block_in_the_ascii_fallback_is_ascii():
    text = joined(app._header_fragments(status_of("tamper", bad_event=4), theme.make_theme("dark", unicode=False), 24, 78))
    assert text.isascii() and "x TAMPER" in text and "-" * 78 in text


@pytest.mark.parametrize("rows", [24, 20, 19, 18, 17, 16, 15])  # 15: the smallest that holds all 11 items and the hint
def test_every_menu_item_and_the_hint_stay_visible_with_the_header_at_every_height(rows):
    theme.set_current(theme.make_theme("dark"))
    _, raw = drive(lambda: app._run_main_menu(status_of("clean")), "q", rows=rows)
    text = visible(raw)
    assert all(label in text for label in app.menu.MENU_ITEMS) and "Esc/q quit" in text
    assert ("CLEAN" in text) is (rows >= 16)
    assert ("VCoC" in text) is (rows >= 18)


def test_the_menu_without_a_header_is_exactly_as_before():
    theme.set_current(theme.make_theme("dark"))
    _, raw = drive(app._run_main_menu, "q", rows=24)
    assert "DB " not in visible(raw)


# ---- the frame follows the state --------------------------------------------------------------------------------------

def corner_style(raw: str) -> str:
    """The color codes the terminal was sent right before the frame's top-left corner: the border's own style."""
    return re.findall(r"\x1b\[([0-9;]*)m┌", raw)[0]


def test_a_tampered_chain_turns_the_menu_frame_red_and_a_stale_one_amber_and_a_clean_one_grey():
    theme.set_current(theme.make_theme("dark"))
    _, tampered = drive(lambda: app._run_main_menu(status_of("tamper", bad_event=4)), "q")
    _, stale = drive(lambda: app._run_main_menu(status_of("stale", new=3)), "q")
    _, clean = drive(lambda: app._run_main_menu(status_of("clean")), "q")
    assert "255;107;104" in corner_style(tampered) and "1" in corner_style(tampered).split(";")  # bold red
    assert "232;148;74" in corner_style(stale)
    assert "120;131;142" in corner_style(clean)  # #78838e, the chrome grey: a clean or unverified chain does not alarm


def test_an_unverified_chain_or_a_missing_database_leaves_the_frame_grey():
    theme.set_current(theme.make_theme("dark"))
    for result in (status_of("unverified"), status_of("nodb", items=0), status_of("unavailable", items=0)):
        _, raw = drive(lambda: app._run_main_menu(result), "q")
        assert "120;131;142" in corner_style(raw)


def test_the_header_text_reaches_the_screen_in_every_state():
    theme.set_current(theme.make_theme("dark"))
    for result, expected in ((status_of("tamper", bad_event=4), "TAMPER"), (status_of("stale", new=3), "3 new"), (status_of("unverified"), "not verified yet")):
        _, raw = drive(lambda: app._run_main_menu(result), "q")
        assert expected in visible(raw)


# ---- the shell: read once per menu, never create, never break ----------------------------------------------------------

def build_case(tmp_path):
    signing_key, _ = generate_keypair()
    save_keypair(signing_key, tmp_path / "private_key.pem", tmp_path / "public_key.pem")
    chain = HashChain()
    chain.add_event(evidence_id="EV001", actor="tester", action="collected", signing_key=signing_key)
    chain.save_db(db.connect(tmp_path / "vcoc.db"))
    conn = db.connect(tmp_path / "vcoc.db")
    with conn:
        conn.execute("INSERT INTO evidence (evidence_id, original_filename, sha256, size_bytes, added_at) VALUES ('EV001','a.bin','ab',1,'t')")
    conn.close()


def run_shell(tmp_path, monkeypatch, keys):
    for key in ("NO_COLOR", "VCOC_ASCII", "VCOC_THEME"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("PROMPT_TOOLKIT_COLOR_DEPTH", "DEPTH_24_BIT")
    monkeypatch.chdir(tmp_path)
    return everything(drive(app.run_shell, keys, rows=24)[1])


VERIFY = "4" + "\r" + "\r" + "q"  # Verify chain (accept both default key paths), then back to the menu


def test_the_shell_never_creates_the_database_just_to_draw_the_header(tmp_path, monkeypatch):
    text = run_shell(tmp_path, monkeypatch, "q")
    assert "not created yet" in text and not (tmp_path / "vcoc.db").exists()


def test_the_header_goes_from_not_verified_to_clean_after_a_real_verification(tmp_path, monkeypatch):
    build_case(tmp_path)
    text = run_shell(tmp_path, monkeypatch, VERIFY + "q")
    assert "not verified yet" in text and "CLEAN" in text
    assert text.index("not verified yet") < text.index("CLEAN")


def test_the_header_is_stale_not_clean_when_evidence_was_added_after_the_verification(tmp_path, monkeypatch):
    build_case(tmp_path)
    run_shell(tmp_path, monkeypatch, VERIFY + "q")  # verify, quit; the result is saved in shell_config.json
    conn = db.connect(tmp_path / "vcoc.db")
    with conn:
        conn.execute("INSERT INTO evidence (evidence_id, original_filename, sha256, size_bytes, added_at) VALUES ('EV002','b.bin','cd',1,'t')")
    conn.close()
    text = run_shell(tmp_path, monkeypatch, "q")  # a new shell session
    assert "STALE" in text and "1 new" in text and "CLEAN" not in text


def test_a_tampered_chain_shows_tamper_in_the_header_on_the_next_menu(tmp_path, monkeypatch):
    build_case(tmp_path)
    conn = sqlite3.connect(tmp_path / "vcoc.db")
    conn.execute("DROP TRIGGER custody_log_no_update")
    conn.execute("UPDATE custody_log SET actor = 'mallory' WHERE idx = 0")
    conn.commit()
    conn.close()
    text = run_shell(tmp_path, monkeypatch, VERIFY + "q")
    assert "TAMPER" in text.split("not verified yet", 1)[1]


def test_the_status_read_cannot_create_a_database_even_if_the_file_vanishes_after_the_existence_check(tmp_path, monkeypatch):
    missing = tmp_path / "vcoc.db"
    monkeypatch.setattr(os.path, "exists", lambda path: True)  # the check passed, then the file went away
    assert status.read_counts(str(missing)) is None
    monkeypatch.undo()
    assert not missing.exists()


def test_a_failing_status_read_never_breaks_the_menu(tmp_path, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(status, "current_status", boom)
    text = run_shell(tmp_path, monkeypatch, "q")
    assert "Add evidence" in text and "DB " not in text


def test_the_status_is_read_between_screens_not_while_the_menu_redraws(tmp_path, monkeypatch):
    calls = []
    real = status.current_status
    monkeypatch.setattr(status, "current_status", lambda *a, **k: calls.append(1) or real(*a, **k))
    run_shell(tmp_path, monkeypatch, "\x1b[B\x1b[A\x1b[B\x1b[Aq")  # a few key presses and redraws, one menu
    assert len(calls) == 1


def test_reading_the_status_of_a_large_database_is_fast(tmp_path):
    path = make_db(tmp_path / "vcoc.db", evidence=1, events=1)
    conn = sqlite3.connect(path)
    with conn:
        conn.executemany(
            "INSERT INTO evidence (evidence_id, original_filename, sha256, size_bytes, added_at) VALUES (?,?,?,?,?)",
            [(f"X{i:06d}", "f", "ab", 1, "t") for i in range(30_000)],
        )
    conn.close()
    start = time.perf_counter()
    result = status.current_status({}, path)
    assert result.items == 30_001 and time.perf_counter() - start < 0.1
