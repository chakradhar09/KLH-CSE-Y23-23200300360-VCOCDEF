# Spec: Forensic Identity Layer — Direction A (Style Layer)

Source idea: `Doc/design/forensic-identity-layer.md`. Interactive preview: `Doc/design/shell-preview.html`. Implementation plan: `tasks/plan-forensic-identity.md`.

**Scope (updated 2026-10-03):** direction A (palette, shield logo, themes, `NO_COLOR`, Windows/Linux console fallbacks) **plus** the status header with state-colored frame (B), the block progress bar on folder ingest (C) and the indeterminate marquee on loading screens. Not doing: animated splash, Rich/Textual, mouse support, live re-verify in the header. The header stores the last verify result in `shell_config.json`.

## Objective

Give the interactive shell (`python cli.py shell`) a recognizable, sober "forensic" identity — shield logo, semantic colors, selectable themes — so custody status (`OK` / `TAMPER`) is readable at a glance in live demos and in research-paper screenshots, while remaining usable for real examiners (high-contrast, `NO_COLOR`, legacy and Linux consoles).

**Hard constraint:** the new look is a *layer over* the existing text. No existing rendered string, key binding, paging or loading behavior changes.

**Users:** (1) capstone evaluators watching a demo / reading screenshots; (2) forensic examiners running the shell for real work. Both matter equally.

### Acceptance criteria (summary; testable form under Success Criteria)
- Main menu, verification screens and loading screen are styled and show the logo (menu only).
- Color is never the only signal: `OK` / `TAMPER` words remain in the text.
- `NO_COLOR`, `TERM=dumb`, and missing Unicode degrade gracefully (Windows legacy console and Linux consoles alike).
- All existing tests pass **unmodified**; no new dependencies; no menu/loading slowdown.

## Assumptions (correct me before implementation)
1. Styling is done with `prompt_toolkit` 3.0.x (already a dependency; 3.0.53 installed) via `Style`, fragment lists and `Application(style=..., color_depth=...)`. No Rich/Textual.
2. We do **not** paint a background color; "charcoal" is achieved through gray chrome (frame, rules, dim hints) so light-background terminals are not broken. The `light` preset exists for those users.
3. In 16-color terminals the palette uses ANSI names (`ansired`, `ansigreen`, `ansiyellow`) which follow the user's own terminal theme; hex colors are used only for 256/truecolor.
4. `NO_COLOR` follows the no-color.org convention: disables color but keeps attributes (bold / reverse / dim). Theme choice is an env var, `VCOC_THEME` (`dark` | `light` | `high-contrast` | `plain`), default `dark`. No config-file key and no CLI flag in this slice.
5. Existing glyphs `▸` and `─` stay inside the string renderers. The ASCII fallback is applied **at display time** in the style layer, never inside the renderers, so renderer-level tests are unaffected on any OS.
6. Screens in scope: main menu (`app.py`), verification screens (`verification_screen.py`), loading screen (`loading.py`). Forms and evidence-search screens only inherit the frame/chrome style, not text colorizing.
7. Logo thresholds by terminal rows: `>= 24` full 3-line mark, `18–23` one-line mark, `< 18` none (the 11 menu items + hint need 15 rows and must always fit; raised from 16 when the two witness items were added, 2026-10-14). Status line from 16 rows, its rule from 20, the witness line from 24.

## Tech Stack
- Python 3, `prompt_toolkit>=3.0` (installed 3.0.53). No new dependencies.
- Tests: `pytest` (`pyproject.toml`: `pythonpath = ["src", "."]`, `testpaths = ["tests"]`).

## Commands
```
Test (all):       python -m pytest -q
Test (this slice): python -m pytest tests/test_theme.py -q
Run the shell:    python cli.py shell
Plain / NO_COLOR: NO_COLOR=1 python cli.py shell                 # bash
                  $env:NO_COLOR=1; python cli.py shell           # PowerShell
Theme preset:     VCOC_THEME=high-contrast python cli.py shell
Force ASCII:      VCOC_ASCII=1 python cli.py shell
Graph refresh:    graphify update .                              # after code changes (project rule)
```
No linter/formatter is configured in the repo; none is introduced.

## Project Structure
```
src/vcoc/interactive/theme.py    → NEW: presets, resolve_theme(), colorize(), logo_lines(), to_ascii(), app_style()
src/vcoc/interactive/app.py      → wire: logo above menu, colorize menu text, Application(style=...)
src/vcoc/interactive/verification_screen.py → wire: colorize sidebar/detail, Application(style=...)
src/vcoc/interactive/loading.py  → wire: colorize loading_text, Application(style=...)   (see Open Questions: base)
tests/test_theme.py              → NEW: unit tests for theme.py
tests/test_theme_wiring.py       → NEW: smoke tests that the three screens build/run styled
Doc/design/                      → SPEC.md (this file), idea one-pager, interactive preview (shell-preview.html)
```
Dependency direction: `app/verification_screen/loading → theme`. `theme` imports nothing from the project (no DB, no file I/O, no `cli`/`verifier`).

## Design

```python
# theme.py (shape, not final code)
@dataclass(frozen=True)
class Theme:
    name: str
    styles: dict[str, str]        # prompt_toolkit class -> style string; empty values = attributes only
    unicode: bool                 # False => display-time ASCII transliteration

def resolve_theme(env=None, *, platform=None, encoding=None, ansi16=False) -> Theme: ...   # make_theme(name, ansi16=, unicode=) builds a preset directly
    # precedence: NO_COLOR / TERM=dumb -> plain; else VCOC_THEME; else dark.
    # unicode: VCOC_ASCII=1/0 wins; else ASCII if stdout encoding not UTF-8, TERM in {"linux","dumb"},
    #          or Windows without Windows Terminal / ConEmu / VS Code markers.

def colorize(text: str, kind: str = "text", theme: Theme | None = None, width: int | None = None) -> list[tuple[str, str]]: ...   # kind: text | menu | sidebar | hint
    # pure; O(len(text)); precompiled regexes.
    # INVARIANT: "".join(t for _, t in colorize(text, theme)) == text   (before to_ascii)
    # classes: ok, tamper, selected, hint, rule, accent

def logo_lines(rows: int) -> list[list[tuple[str, str]]]: ...   # for_display(fragments, theme) applies to_ascii when theme.unicode is False
def to_ascii(fragments): ...      # ▸ -> >   ─ -> -   ◆ -> #   ━ -> =   ■ -> #   □ -> .
def app_style(theme: Theme) -> Style: ...
```

Color roles (dark preset): chrome gray, accent amber (`#d9a441`), OK green, TAMPER bold red on default background, hints dim, selection = reverse + accent. High-contrast: bold white/yellow, TAMPER = reverse red. Plain: bold / reverse / dim only.

Logo (witness shield, as in the film logo: two halves with a gap, the left an outline in the text colour, the right solid in
the accent, one point; decided 2026-10-14, replacing the 2026-10-03 chain-link shield). A cell is about twice as tall as wide,
so at 3 rows the shield is 6 columns wide; the first block version spread it over 8 and read as a heart. Full / one-line:
```
 ▛▀▌▐██
 ▌ ▌▐██  VCoC  Verifiable Chain-of-Custody
 ▝▚▌▐▛▘  for digital evidence files

 ▜▌▐▛ VCoC  Verifiable Chain-of-Custody
```
ASCII fallback: a drawn shield of the same size (`logo_lines(rows, unicode=False)`), not a transliteration of the blocks:
```
 +-+ ##
 | | ##  VCoC  Verifiable Chain-of-Custody
 \_| #/  for digital evidence files

 \||/ VCoC  Verifiable Chain-of-Custody
```

## Code Style
Match the surrounding module style: `from __future__ import annotations`, short docstrings that explain *why*, type hints on public functions, no comments restating code.

```python
def colorize(text: str, kind: str = "text", theme: Theme | None = None, width: int | None = None) -> list[tuple[str, str]]:
    """Split text into (style, fragment) pairs; the fragments always re-join to exactly `text`."""
    out: list[tuple[str, str]] = []
    for line in text.splitlines(keepends=True):
        out.extend(_style_line(line))
    return out
```
Conventions: snake_case functions, `_private` helpers, module-level precompiled `re` patterns, no globals mutated at import time (env is read inside `resolve_theme`, passed in for tests).

## Testing Strategy
Level: unit (pytest) for `theme.py`; small smoke tests for wiring. No mocks of prompt_toolkit internals beyond `create_pipe_input` / `DummyOutput` (already the pattern in `test_interactive_loading.py`).

Unit (`tests/test_theme.py`):
- `resolve_theme`: precedence (`NO_COLOR` > `VCOC_THEME` > default), unknown `VCOC_THEME` falls back to `dark`, `TERM=dumb` → plain, `VCOC_ASCII` override, Windows/Linux-console heuristics via injected env.
- `colorize` round-trip invariant over fixtures from the real renderers (menu text, sidebar rows, detail text, loading text) for every preset.
- `colorize` marks `OK` / `TAMPER` / `!!` / `MATCHES` / `DOES NOT MATCH` with the right class; plain preset emits no color styles.
- `to_ascii` leaves no non-ASCII characters; `logo_lines` collapses at the 24 / 16 row thresholds.
- Perf guard: `colorize` of a 100-line sample under 5 ms (generous bound; catches accidental O(n²)).

Wiring (`tests/test_theme_wiring.py`): main menu, a verification screen and the loading screen run through a pipe input with `DummyOutput` under each preset and under `NO_COLOR` without raising.

Regression gate: the **entire existing suite runs green with zero edits to existing test files.**

Manual (checklist, recorded in the PR): Windows Terminal, legacy cmd.exe, Linux `xterm-256color`, Linux VT (`TERM=linux`), `NO_COLOR=1`, and a 24-row / 15-row terminal. Linux checks cannot be run from this Windows environment.

## Boundaries
- **Always:** keep every existing renderer's returned string identical; keep the `colorize` round-trip invariant; run the full suite before declaring done; run `graphify update .` after code changes; keep `theme.py` free of DB / file / network access.
- **Ask first:** adding any dependency; changing any existing rendered string or key binding; adding a config-file key or CLI flag for theme; touching `db.py`, `hashing.py`, `merkle.py`, `verifier.py`; expanding scope to B or C.
- **Never:** convey status by color alone; run work (DB reads, verification) from a style/render path; edit or loosen existing tests to make them pass; paint a forced background; commit, push or open a PR without an explicit request (project rule in `CLAUDE.md`).

## Success Criteria
1. `python -m pytest -q` passes with no existing test file modified.
2. For every preset and every renderer fixture, `colorize` fragments re-join to the exact source text.
3. Under `NO_COLOR=1` the shell shows no color escape codes but still shows bold/reverse selection and the full text.
4. With ASCII fallback on, the menu, verification and loading screens contain no non-ASCII characters in the display layer, and the logo, selection marker and rules are still legible.
5. At 80x24 the main menu shows the full logo plus all 9 items and the hint; at 80x15 the logo is gone and every item and the hint are still visible.
6. Opening the main menu is not measurably slower (within noise, ±5%) than before on the existing dataset; `theme.py` import does no I/O.
7. Verdict rows (`OK` / `TAMPER`) are distinguishable in a grayscale screenshot (words present, TAMPER also bold/reverse).

## Decisions (2026-10-03)

| # | Question | Decision |
|---|---|---|
| 1 | Where do the design files live? | `Doc/design/` (tracked). Holds `SPEC.md`, the idea one-pager and the interactive preview. The live plan and checklist stay in `tasks/` as `plan-forensic-identity.md` / `todo-forensic-identity.md`, following the repo's `plan-<topic>.md` convention; `tasks/plan.md` and `tasks/todo.md` belong to the earlier shell work and are untouched. |
| 2 | Where is the last verify result stored? | `shell_config.json` (no schema change; `custody_log` untouched). |
| 3 | Shorten the help lines that clip at 80 columns? | **Approved as task T16** (2026-10-03). It is the only task that changes existing text; wording approved 2026-10-03 (lines in `tasks/todo-forensic-identity.md`). No existing test pins these strings. |
| 4 | Logo | **Shield** (changed from Chain on 2026-10-03); Chain and Blocks stay in the preview for reference. |
| 5 | Selected-row highlight | Full-width tint; text-only tint is the fallback if width-aware padding proves fragile. |
| 6 | Indeterminate marquee (T9) | Included. |
| 7 | Where to implement | Directly on `main`, not in the worktree. The worktree branch `worktree-forensic-identity-layer` is kept on disk but is not used for the work. |

## Next Phases (after approval)
Plan → `tasks/plan.md`; Tasks → `tasks/todo.md`. Suggested slice order: (1) `theme.py` + unit tests; (2) main-menu wiring + logo; (3) verification-screen wiring; (4) loading-screen wiring; (5) manual terminal matrix.

## Implementation notes (2026-10-03): what was built, and where it differs from the text above

Built: `theme.py` (palettes, `colorize`, `styled`, ASCII fallback, logo, progress bar, marquee, lexer, depth detection),
`status.py` (header data), `config.py` additions (atomic `last_verify`), wiring in `app.py`, `forms.py`,
`evidence_search.py`, `verification_screen.py`, `loading.py`, `menu.py`; 322 new tests (727 passing before, 1049 after) in `tests/test_theme*.py`,
`tests/test_last_verify.py` and `tests/test_help_lines.py`. No existing test file was edited.

Differences from the design above:

- **Progress bar delivery.** `loading_text` did not gain a `bar` argument. An existing test replaces `run_with_loading` with
  a spy that accepts only `status` and `cancel`, so the bar rides on the existing status text
  (`_IngestProgress.screen_text()`); `loading_text`, `run_with_loading` and `_IngestProgress.text()` are byte-identical.
- **Windows Unicode default.** The first rule (ASCII on Windows without a known terminal marker, and whenever Python's
  stdout is not UTF-8) wrongly refused Unicode on Windows 11. Modern Windows (build 17763+) now defaults to Unicode and
  ignores Python's stdout encoding, which reads cp1252 whenever stdout is redirected.
- **Palette values.** Re-tuned after a contrast audit over 8 dark and 4 light terminal backgrounds (dark `dim` `#939ca9`,
  `chrome` `#78838e`; light `ok #17703a`, `tamper #b52326`, `warn #964b08`, `accent #8a5000`, `dim #545e6c`, `chrome #727a84`).
  Text is at least 4.5:1 and lines at least 3:1; `tests/test_theme.py` enforces it.
- **Color depth.** `resolve_theme(color_depth=...)` picks hex for 256/truecolor, ANSI names for 16 colors, a dedicated bright
  palette for the Linux console (`TERM=linux`), and the plain theme for 1-bit terminals. A headless output (prompt_toolkit's
  `DummyOutput`) reports 1-bit, so tests that need colors set `PROMPT_TOOLKIT_COLOR_DEPTH`.
- **Status header.** New module `status.py`; the last verify result lives in `shell_config.json` (decision 2). The item
  count is cached per database, keyed by the highest evidence rowid, because `COUNT(*)` over 92,879 rows was the header's
  only real cost (1.7 ms); menu open went from 19.47 ms to 19.54 ms.
- **Help lines (T16).** The seven help lines are named constants (`HELP_*`) and a test asserts each fits 78 columns.
- **Hint styling.** Key names run up to the first lowercase word, so `↑/↓ PgUp/PgDn select` keeps both keys plain.
- **`logo_lines(rows)`** takes only the terminal height, and `colorize(text, kind, theme, width)` takes the kind of text;
  `for_display(fragments, theme)` applies the ASCII fallback.

### Follow-up after a hands-on review (2026-10-03)

Screens that still looked like the old shell, now brought into line (49 tests in `tests/test_verification_look.py`):

- **Verification > Evidence / Merkle tabs.** While a tab works in the background, the sidebar shows short lines that fit its
  40-column width (the old single line `Re-hashing 5/9  EV005  1.0 MB / 2.0 MB (50%)` was clipped, hiding the file count): the
  file count with thousands separators, the file, its bytes, a 24-cell block bar of overall progress, and the clock. A tab with
  no progress (Merkle) shows the marquee. The screen redraws ten times a second only when it has a background tab.
- **Loading screen before Verify chain and Verification.** The chain is checked behind the shared full-screen loading screen,
  once (the result is reused by the screen), so a plain terminal never shows between the menu and these screens.
- **Position footer** (`1-40 of 92,879`). The sidebar now uses the column's real height, so the rows fill it and the footer sits
  on its last line instead of floating above it.
- **Merkle root and Merkle proof pages.** Root line: quiet label and accented root; items: id plain, hash and file count dim;
  proof JSON: keys dim, the root's hash accented; `Wrote proof -> file` is a success line.
