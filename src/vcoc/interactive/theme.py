"""The shell's look: palettes, glyph fallback and logo, as a layer over the text the screens already render.

Nothing here edits a screen's string. `colorize` splits the text into (style, fragment) pairs that always re-join to
exactly what went in, so the renderers (and the tests that pin them) never change. Pure: no files, DB or network.
"""

from __future__ import annotations

import contextlib
import itertools
import os
import re
import sys
from dataclasses import dataclass

from prompt_toolkit.lexers import Lexer
from prompt_toolkit.output import ColorDepth
from prompt_toolkit.styles import Style

Fragments = list[tuple[str, str]]

THEME_NAMES = ("dark", "light", "hc", "plain")
_ALIASES = {"high-contrast": "hc"}


def _line_color(rule: str) -> str:
    """A text rule as a bold line color for a frame border: its background if it is a reverse badge, else its foreground."""
    found = re.search(r"bg:(\S+)", rule) or re.search(r"fg:(\S+)", rule)
    return f"bold fg:{found.group(1)}" if found else "bold"


def _rules(chrome, dim, accent, ok, tamper, warn, sel, bgsel) -> dict[str, str]:
    return {
        "chrome": chrome, "dim": dim, "accent": accent, "ok": ok, "tamper": tamper, "warn": warn,
        "sel": sel, "bgsel": bgsel, "b": "bold", "title": "bold", "frame.border": chrome, "frame.label": "bold",
        "input frame.border": accent,  # a Frame wrapped in style="class:input": the box that has the keyboard
        "state-stale frame.border": _line_color(warn),  # the main menu's frame follows the chain's last known state
        "state-tamper frame.border": _line_color(tamper),
    }


_TRUECOLOR = {
    "dark": _rules("fg:#78838e", "fg:#939ca9", "fg:#d9a441", "fg:#5fb878", "bold fg:#ff6b68", "fg:#e8944a", "bold fg:#f0c060 bg:#262c35", "bg:#262c35"),
    "light": _rules("fg:#727a84", "fg:#545e6c", "fg:#8a5000", "fg:#17703a", "bold fg:#b52326", "fg:#964b08", "bold fg:#6b3f00 bg:#e4e0d1", "bg:#e4e0d1"),
    "hc": _rules("fg:#ffffff", "fg:#cfcfcf", "bold fg:#ffd400", "fg:#3dff7d", "bold fg:#000000 bg:#ff5252", "fg:#ffb000", "bold reverse", "reverse"),
    "plain": _rules("", "", "bold", "", "bold reverse", "bold", "bold reverse", "reverse"),
}
# 16-color terminals: ANSI names only, so the terminal's own palette picks the exact shade.
_ANSI16 = {
    "dark": _rules("fg:ansibrightblack", "fg:ansibrightblack", "fg:ansiyellow", "fg:ansibrightgreen", "bold fg:ansibrightred", "fg:ansiyellow", "bold reverse", "reverse"),
    "light": _rules("fg:ansibrightblack", "fg:ansibrightblack", "fg:ansiblue", "fg:ansigreen", "bold fg:ansired", "fg:ansiyellow", "bold reverse", "reverse"),
}

# The Linux virtual console: "bright black" is #555 on black there, so chrome and hints stay in the default color.
_VT = _rules("", "", "fg:ansibrightyellow", "fg:ansibrightgreen", "bold fg:ansibrightred", "fg:ansibrightyellow", "bold reverse", "reverse")


@dataclass(frozen=True)
class Theme:
    name: str
    rules: dict[str, str]  # prompt_toolkit style class -> style string
    unicode: bool  # False: draw the ASCII fallback at display time
    reverse_selection: bool  # True: the selected row reverses; False: it gets a background tint


def make_theme(name: str, *, ansi16: bool = False, unicode: bool = True, vt: bool = False) -> Theme:
    """A preset; `ansi16` swaps in ANSI color names, `vt` the Linux console palette (dark only)."""
    if vt and name == "dark":
        rules = _VT
    else:
        rules = _ANSI16[name] if ansi16 and name in _ANSI16 else _TRUECOLOR[name]
    return Theme(name, dict(rules), unicode, name in ("hc", "plain") or ansi16 or vt)


_MODERN_WINDOWS_BUILD = 17763  # Windows 10 1809: the console understands escape sequences and ships TrueType fonts


def _windows_build() -> int:
    try:
        return sys.getwindowsversion().build
    except AttributeError:
        return 0


def _unicode_ok(env, platform: str, encoding: str, win_build: int) -> bool:
    override = env.get("VCOC_ASCII", "").lower()
    if override in ("1", "true", "yes"):
        return False
    if override in ("0", "false", "no"):
        return True
    if env.get("TERM", "") in ("linux", "dumb"):
        return False
    if platform == "win32":
        # prompt_toolkit draws a Windows console through the console API, not through Python's stdout encoding (which
        # reads cp1252 whenever stdout is redirected), so only an old console without a modern terminal needs ASCII.
        modern_host = any(env.get(key) for key in ("WT_SESSION", "TERM_PROGRAM", "ConEmuANSI", "ANSICON", "TERM"))
        return modern_host or win_build >= _MODERN_WINDOWS_BUILD
    return "utf" in encoding.lower()


def detect_color_depth(output=None) -> ColorDepth:
    """The depth the shell will be drawn at: NO_COLOR or PROMPT_TOOLKIT_COLOR_DEPTH first, else what the terminal supports."""
    forced = ColorDepth.from_env()
    if forced is not None:
        return forced
    try:
        if output is None:
            from prompt_toolkit.application import get_app_session

            output = get_app_session().output
        return output.get_default_color_depth()
    except Exception:
        return ColorDepth.DEFAULT


def resolve_theme(
    env=None,
    *,
    platform: str | None = None,
    encoding: str | None = None,
    ansi16: bool = False,
    win_build: int | None = None,
    color_depth: ColorDepth | None = None,
) -> Theme:
    """NO_COLOR (or TERM=dumb, or a 1-bit terminal) > VCOC_THEME > dark; glyphs from VCOC_ASCII, else detected.

    `color_depth` picks the palette: ANSI names on a 16-color terminal (the Linux console gets its own), the plain theme
    when the terminal has no color, the hex palette otherwise.
    """
    env = os.environ if env is None else env
    platform = sys.platform if platform is None else platform
    if win_build is None:
        win_build = _windows_build()
    if encoding is None:
        encoding = getattr(sys.stdout, "encoding", None) or ""
    if env.get("NO_COLOR") or env.get("TERM") == "dumb" or color_depth == ColorDepth.DEPTH_1_BIT:
        name = "plain"
    else:
        wanted = env.get("VCOC_THEME", "").strip().lower()
        wanted = _ALIASES.get(wanted, wanted)
        name = wanted if wanted in THEME_NAMES else "dark"
    ansi16 = ansi16 or color_depth == ColorDepth.DEPTH_4_BIT
    vt = ansi16 and env.get("TERM") == "linux"
    return make_theme(name, ansi16=ansi16, unicode=_unicode_ok(env, platform, encoding, win_build), vt=vt)


def app_style(theme: Theme) -> Style:
    return Style.from_dict(theme.rules)


_current: Theme | None = None


def current() -> Theme:
    """The theme every screen uses; resolved from the environment on first use (run_shell resolves it afresh)."""
    global _current
    if _current is None:
        _current = resolve_theme()
    return _current


def set_current(theme: Theme | None) -> None:
    global _current
    _current = theme


_ASCII_BORDER = {"HORIZONTAL": "-", "VERTICAL": "|", "TOP_LEFT": "+", "TOP_RIGHT": "+", "BOTTOM_LEFT": "+", "BOTTOM_RIGHT": "+"}


@contextlib.contextmanager
def ascii_borders(theme: Theme):
    """Draw prompt_toolkit's Frame borders in ASCII while the body runs (a Frame reads them when it is built)."""
    if theme.unicode:
        yield
        return
    from prompt_toolkit.widgets.base import Border

    saved = {name: getattr(Border, name) for name in _ASCII_BORDER}
    for name, glyph in _ASCII_BORDER.items():
        setattr(Border, name, glyph)
    try:
        yield
    finally:
        for name, glyph in saved.items():
            setattr(Border, name, glyph)


# ---- colorize ----------------------------------------------------------------------------------------------------

_LABEL = re.compile(r"^(\s*[A-Za-z][\w .-]*?:)(?=\s|$)")
_VERDICT = re.compile(
    r"TAMPER DETECTED|DOES NOT MATCH claimed root|MATCHES claimed root|NOT logged|TAMPER|INVALID|MISMATCH|STALE|\bOK\b|\bVALID\b|\blogged\b"
)
_GAP = re.compile(r"(\s{3,})")
_MENU_ROW = re.compile(r"^(▸| ) (\d)  (.*)$")
_SIDEBAR_ROW = re.compile(r"^(▸| ) (.*)$")
_ROW_STATUS = re.compile(r"^(OK|TAMPER|!!|--)(\s+)(.*)$")
_QUIET = re.compile(r"^\s+(?:[\d,]+-[\d,]+ of [\d,]+|\(.*\))$")  # sidebar position footer, "(no matches)"


def _verdict_class(word: str) -> str:
    if word.startswith(("TAMPER", "DOES NOT", "INVALID", "MISMATCH")):
        return "class:tamper"
    return "class:warn" if word in ("NOT logged", "STALE") else "class:ok"


def _text_line(body: str) -> Fragments:
    out: Fragments = []
    pos = 0
    label = _LABEL.match(body)
    if label:
        out.append(("class:dim", label.group(1)))
        pos = label.end(1)
    for found in _VERDICT.finditer(body, pos):
        if found.start() > pos:
            out.append(("", body[pos:found.start()]))
        out.append((_verdict_class(found.group(0)), found.group(0)))
        pos = found.end()
    if pos < len(body):
        out.append(("", body[pos:]))
    return out


def _hint_line(body: str) -> Fragments:
    """Key names plain, what they do dim; keys and descriptions are separated by three or more spaces."""
    out: Fragments = []
    for chunk in _GAP.split(body):
        if not chunk:
            continue
        if chunk.isspace():
            out.append(("", chunk))
            continue
        key, desc = re.match(r"(\s*\S+(?: [^\sa-z]\S*)*)(.*)", chunk, re.S).groups()  # key names run up to the first lowercase word
        out.append(("", key))
        if desc:
            out.append(("class:dim", desc))
    return out


def _selected(parts: Fragments, theme: Theme, width: int | None) -> Fragments:
    """The selected row: one reversed fragment, or a tint behind the text that keeps each verdict's own color."""
    text = "".join(part for _, part in parts)
    pad = " " * (width - len(text)) if width and len(text) < width else ""
    if theme.reverse_selection:
        return [("class:sel", text + pad)]
    out: Fragments = []
    for cls, part in parts:
        style = f"{cls} class:bgsel" if cls else "class:sel"
        if out and out[-1][0] == style:
            out[-1] = (style, out[-1][1] + part)
        else:
            out.append((style, part))
    if pad:
        out.append(("class:bgsel", pad))
    return out


def _menu_line(body: str, theme: Theme, width: int | None) -> Fragments:
    row = _MENU_ROW.match(body)
    if row is None:
        return _hint_line(body) if body.strip() else []
    if row.group(1) == "▸":
        return _selected([("", body)], theme, width)
    return [("", row.group(1) + " "), ("class:dim", row.group(2)), ("", "  " + row.group(3))]


def _sidebar_line(body: str, theme: Theme, width: int | None) -> Fragments:
    if _QUIET.match(body):
        return [("class:dim", body)]
    row = _SIDEBAR_ROW.match(body)
    if row is None:
        return _text_line(body)
    marker, rest = row.groups()
    status = _ROW_STATUS.match(rest)
    if status:
        word, gap, tail = status.groups()
        cls = {"OK": "class:ok", "--": "class:dim"}.get(word, "class:tamper")
        parts = [(cls, word), ("", gap + tail)]
    else:
        parts = [("", rest)]
    if marker == "▸":
        return _selected([("", "▸ "), *parts], theme, width)
    return [("", "  "), *parts]


_TAB = re.compile(r"\[ [^\]]+ \]")
_RESULT = re.compile(r"^(▸| ) (\[[ x]\] )?(.*?)(\S+\.\.\.)$")
_PROMPT = re.compile(r"^(.*?)(\s*\(.*\))?$")
_CONFIRM = re.compile(r"(\[)([Yy])(/)([Nn])(\])")
_LEVEL = re.compile(r"^(Error|Warning):")


def _plain_line(body: str, theme: Theme, width: int | None) -> Fragments:
    return [("", body)] if body else []


def _tabs_line(body: str, theme: Theme, width: int | None) -> Fragments:
    out: Fragments = []
    pos = 0
    for tab in _TAB.finditer(body):
        if tab.start() > pos:
            out.append(("class:dim", body[pos:tab.start()]))
        out.append(("class:accent", tab.group(0)))
        pos = tab.end()
    if pos < len(body):
        out.append(("class:dim", body[pos:]))
    return out


def _list_line(body: str, theme: Theme, width: int | None) -> Fragments:
    """A pick-list row: a marker and a name, never a verdict (a file called "OK report" is just a file)."""
    if _QUIET.match(body):
        return [("class:dim", body)]
    row = _SIDEBAR_ROW.match(body)
    if row and row.group(1) == "▸":
        return _selected([("", body)], theme, width)
    return _plain_line(body, theme, width)


def _results_line(body: str, theme: Theme, width: int | None) -> Fragments:
    """A search result: `▸ [x] EV001  name  abcd1234...`; the hash prefix dim, a ticked box accent."""
    if _QUIET.match(body):
        return [("class:dim", body)]
    row = _RESULT.match(body)
    if row is None:
        return _plain_line(body, theme, width)
    marker, box, middle, sha = row.groups()
    parts: Fragments = [("", marker + " ")]
    if box:
        parts += [("class:accent" if box[1] == "x" else "", box[:3]), ("", " ")]
    parts += [("", middle), ("class:dim", sha)]
    return _selected(parts, theme, width) if marker == "▸" else parts


def _prompt_line(body: str, theme: Theme, width: int | None) -> Fragments:
    """A form label; only a trailing "(status)" such as "(searching...)" is dim."""
    label, status = _PROMPT.match(body).groups()
    return ([("", label)] if label else []) + ([("class:dim", status)] if status else [])


def _confirm_line(body: str, theme: Theme, width: int | None) -> Fragments:
    """"question [y/N]: ", with the default answer (the capital letter) in the accent."""
    found = _CONFIRM.search(body)
    if found is None:
        return _plain_line(body, theme, width)
    yes, no = found.group(2), found.group(4)
    out: Fragments = [("", body[:found.start()])] if found.start() else []
    out += [
        ("class:dim", "["), ("class:accent" if yes.isupper() else "class:dim", yes), ("class:dim", "/"),
        ("class:accent" if no.isupper() else "class:dim", no), ("class:dim", "]"),
    ]
    if found.end() < len(body):
        out.append(("class:dim", body[found.end():]))
    return out


def _output_line(body: str, theme: Theme, width: int | None) -> Fragments:
    """A line of command output (the add-evidence summary, a check result, a proof)."""
    if body.strip() == "Summary":
        return [("class:accent", body)]
    if body.startswith("Registered"):
        return [("class:ok", "Registered"), ("", body[len("Registered"):])]
    level = _LEVEL.match(body)
    if level:
        return [("class:warn", level.group(0)), ("", body[level.end():])]
    return _text_line(body)


_BAR_CELLS, _MARQUEE_BLOCK, _MARQUEE_SPEED = 40, 8, 14  # cells in a bar; cells in the moving block; cells per second


def progress_bar(fraction: float, width: int = _BAR_CELLS) -> str:
    """`[■■■□□□]  53%`; rounds down, so it never shows a finished bar before the work is."""
    fraction = min(max(fraction, 0.0), 1.0)
    filled = int(fraction * width)
    return "[" + "■" * filled + "□" * (width - filled) + f"]  {int(fraction * 100)}%"


def marquee(elapsed: float, width: int = _BAR_CELLS, block: int = _MARQUEE_BLOCK) -> str:
    """`[····■■■■■■■■·····]`: a block sliding along a track, for waits that have no percentage."""
    head = int(elapsed * _MARQUEE_SPEED + 1e-9) % (width + block) - block
    return "[" + "".join("■" if head <= i < head + block else "·" for i in range(width)) + "]"


_BAR = re.compile(r"^(\s*)\[([■□]+)\](\s+\d+%)?$")
_MARQUEE = re.compile(r"^(\s*)\[([·■]+)\]$")
_CLOCK = re.compile(r"^\s+\d+(?:\.\d+)? s$")


def _loading_line(body: str, theme: Theme, width: int | None) -> Fragments:
    """A line of the loading screen: the bar or marquee, the elapsed clock, the Esc hint and the file being hashed."""
    bar = _BAR.match(body)
    if bar:
        indent, cells, percent = bar.groups()
        filled = cells.count("■")
        empty = len(cells) - filled
        done = empty == 0
        out: Fragments = [("", indent), ("class:chrome", "[")]
        out += [("class:ok" if done else "class:accent", "■" * filled)] if filled else []
        out += [("class:chrome", "□" * empty)] if empty else []
        out.append(("class:chrome", "]"))
        if percent:
            out.append(("class:ok" if done else "", percent))
        return out
    track = _MARQUEE.match(body)
    if track:
        out = [("", track.group(1)), ("class:chrome", "[")]
        for char, run in itertools.groupby(track.group(2)):
            out.append(("class:accent" if char == "■" else "class:chrome", "".join(run)))
        out.append(("class:chrome", "]"))
        return out
    if _CLOCK.match(body) or body.strip() == "Esc cancels" or body.startswith("    ") and body.strip():
        return [("class:dim", body)]
    if body.strip().startswith("Cancelling..."):
        return [("class:warn", body)]
    return _plain_line(body, theme, width)


_HEADER = re.compile(
    r"(?P<ok>● CLEAN)|(?P<warn>◐ STALE|[\d,]+ new)|(?P<tamper>✖ TAMPER)"
    r"|(?P<dim>○ not verified yet|verified [\d: -]+\d|since [\d: -]+\d|not created yet|status unavailable|^ DB)"
    r"|(?P<chrome>│)"
)


def _header_line(body: str, theme: Theme, width: int | None) -> Fragments:
    """The main menu's status header (see status.header_text): the chain's state colored, everything else quiet."""
    out: Fragments = []
    pos = 0
    for found in _HEADER.finditer(body):
        if found.start() > pos:
            out.append(("", body[pos:found.start()]))
        out.append((f"class:{found.lastgroup}", found.group(0)))
        pos = found.end()
    if pos < len(body):
        out.append(("", body[pos:]))
    return out


_LINE_KINDS = {
    "menu": _menu_line, "sidebar": _sidebar_line, "tabs": _tabs_line, "list": _list_line, "results": _results_line,
    "prompt": _prompt_line, "plain": _plain_line, "confirm": _confirm_line, "output": _output_line,
    "loading": _loading_line, "header": _header_line, "hint": lambda body, theme, width: _hint_line(body),
}


def colorize(text: str, kind: str = "text", theme: Theme | None = None, width: int | None = None) -> Fragments:
    """(style, fragment) pairs for `text` that always re-join to `text`; only a selected row is padded, by spaces."""
    theme = theme or make_theme("dark")
    line_fn = _LINE_KINDS.get(kind, lambda body, theme, width: _text_line(body))
    out: Fragments = []
    last = text.count("\n")
    for i, body in enumerate(text.split("\n")):
        out.extend(line_fn(body, theme, width))
        if i < last:
            out.append(("", "\n"))
    return [(style, part) for style, part in out if part]


def inner_width() -> int | None:
    """Columns inside a frame (its borders take two); None when there is no terminal to ask."""
    from prompt_toolkit.application import get_app

    try:
        return get_app().output.get_size().columns - 2
    except Exception:
        return None


def styled(render, kind: str = "text", width=None):
    """A screen's string renderer as a callable returning styled fragments for the current theme (ASCII-converted when needed).

    `width` is a column count or a zero-argument callable returning one; it only pads the selected row.
    """

    def fragments() -> Fragments:
        theme = current()
        return for_display(colorize(render(), kind, theme, width() if callable(width) else width), theme)

    return fragments


class ThemeLexer(Lexer):
    """Colors a read-only text buffer (the command-output screen) line by line, lazily, for the current theme."""

    def lex_document(self, document):
        theme = current()
        lines = document.lines

        def get_line(lineno: int) -> Fragments:
            return for_display(colorize(lines[lineno], "output", theme), theme)

        return get_line


# ---- ASCII fallback ----------------------------------------------------------------------------------------------

_ASCII = {
    "▸": ">", "─": "-", "│": "|", "┌": "+", "┐": "+", "└": "+", "┘": "+", "┤": "|", "├": "|",
    "╭": "+", "╮": "+", "╰": "+", "╯": "+", "━": "=", "◆": "#", "■": "#", "□": ".", "●": "*", "◐": "~", "✖": "x",
    "·": "-", "—": "-", "↑": "^", "↓": "v", "←": "<", "→": ">", "▼": "v", "█": "_", "…": ".", "○": "o",
}


def to_ascii(fragments: Fragments) -> Fragments:
    """Same width, same styles; every glyph the screens use gets a plain stand-in, anything else becomes '?'."""
    return [(style, "".join(c if c.isascii() else _ASCII.get(c, "?") for c in part)) for style, part in fragments]


def for_display(fragments: Fragments, theme: Theme) -> Fragments:
    return fragments if theme.unicode else to_ascii(fragments)


def glyph(char: str, theme: Theme) -> str:
    """One character of the screens' own drawing (a rule, a divider), or its ASCII stand-in."""
    return char if theme.unicode else _ASCII.get(char, "?")


# ---- logo --------------------------------------------------------------------------------------------------------

_FULL_ROWS, _ONE_LINE_ROWS = 24, 16  # terminal rows needed for the three-line and the one-line mark


def logo_lines(rows: int) -> list[Fragments]:
    """The shield mark for a terminal `rows` tall: three lines from 24 rows, one line from 16, none below."""
    name = "VCoC"
    if rows >= _FULL_ROWS:
        return [
            [("class:chrome", "  ╭─────╮")],
            [("class:chrome", "  │ "), ("class:accent", "◆━◆"), ("class:chrome", " │"), ("class:b", f"  {name}"), ("class:dim", "  Verifiable Chain-of-Custody")],
            [("class:chrome", "  ╰──▼──╯"), ("class:dim", "  for digital evidence files")],
        ]
    if rows >= _ONE_LINE_ROWS:
        return [[("class:chrome", " ╭"), ("class:accent", "◆━◆"), ("class:chrome", "╮ "), ("class:b", name), ("class:dim", "  Verifiable Chain-of-Custody")]]
    return []
