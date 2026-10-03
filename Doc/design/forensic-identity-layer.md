# Forensic Identity Layer for the Interactive Shell

## Problem Statement
How might we give the shell a recognizable identity (logo, color) that makes custody status readable at a glance, without changing screen text, key bindings, or the loading and paging optimizations?

## Recommended Direction
Build **A first**, then **B**, then **C** if time allows.

- **A — Style layer (palette + logo + themes/NO_COLOR).** A new `theme.py` holds a "sober forensic" palette (charcoal/gray chrome, one amber accent, green for OK, red only for TAMPER), a shield logo (a chain link inside a shield), and dark / light / high-contrast presets. A pure `colorize(text)` function turns the existing strings into styled fragments; the string renderers are untouched, so existing tests stay unmodified. Graceful degradation is part of A: truecolor → 256 → 16 → none; `NO_COLOR` or `TERM=dumb` gives attribute-only output; terminals without Unicode (legacy Windows console, Linux VT) get ASCII glyphs.
- **B — Status-driven header.** Home frame shows DB, evidence count and the *last known* chain-verify result with its time, border color following that state. Must never run verify-chain, and must show staleness ("3 added since") so a green banner never overstates integrity.
- **C — Block progress bar.** `[■■■■□□□□] 48%` on the loading/ingest screens. Polish; ship last.

## Key Assumptions to Validate
- [ ] `colorize(text)` can style every screen without changing any returned string. Test: full existing suite green, unmodified; round-trip invariant (`"".join(fragments) == text`).
- [ ] Glyph fallback works on legacy Windows console and a Linux VT (`TERM=linux`). Test: render on cmd.exe, Windows Terminal, and `TERM=linux` / `xterm-256color` / `NO_COLOR=1`.
- [ ] The style layer costs no measurable menu-open or redraw time. Test: time menu open before/after; micro-benchmark `colorize`.
- [ ] (B only) A last-verify result can be recorded/read without breaking the append-only `custody_log`. Test: check whether a verify event is already logged; if not, defer B.

## MVP Scope
**In:** `theme.py` (palette, three presets, `NO_COLOR`, ASCII fallback, logo that collapses by terminal height), `colorize` applied to the main menu, the verification screens (OK/TAMPER) and the loading screen. **Out:** status header (B), progress bar (C), any change to rendered text.

## Not Doing (and Why)
- Animated splash — adds startup latency right after the work to remove flashes; first thing to rot in a demo.
- Rich/Textual rewrite — risks every optimization and test for a cosmetic gain, and adds a dependency.
- Color-only status — verdicts stay as text (`OK`/`TAMPER`) for screenshots, print and accessibility.
- Mouse support / widgets — out of scope; the key-driven flow already works.
- Live re-verify in the header — `verify-chain` is the expensive operation; the header may only report the last known result.

## Open Questions
- Does anything already record the last verify result, or would B need a new write?
- Which terminal do the demo evaluators use? That sets which fallback tier matters most.
- User-facing switch for the theme: env var, `--theme` flag, or config entry?
