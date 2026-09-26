"""Verification screen: top tab bar (Chain / Evidence / Merkle) + sidebar of
results + detail pane. Calls the standalone verifier.py functions directly
-- same independent, from-scratch checks an outside auditor would run via
`python verifier.py`, just rendered in the shell instead of printed.
"""

from __future__ import annotations

import json
from pathlib import Path

from prompt_toolkit import Application
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import HSplit, Layout, VSplit, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.layout.dimension import D
from prompt_toolkit.widgets import Frame

import cli as cli_module
import verifier as verifier_module
from vcoc.visualize import build_chain_view, format_entry_detail_lines

TABS = ["Chain", "Evidence", "Merkle"]


def _load_json(path: str) -> object | None:
    p = Path(path)
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8"))


def _run_chain_check(shell_config: dict | None = None) -> tuple[list[str], list[str]]:
    """Returns (sidebar rows, detail lines per row -- parallel lists).

    One row per custody event (not one aggregate row), so the sidebar can be
    navigated the same way the Evidence tab's one-row-per-record list
    already is. Each row's detail pane shows the same rich per-entry info
    verify-chain's CLI output has: both hashes, a truncated signature, and
    an independent per-entry OK/TAMPER status.

    public_key_path comes from shell_config["public_key"] when the shell
    has one configured (via menu.ensure_keys, Task 8) -- that's the same
    key Log custody event / Verify chain already trust, wherever the user
    pointed it. Falls back to the cwd default for callers with no
    shell_config (or a config that hasn't set a key yet), same as before.
    """
    entries = _load_json(cli_module.DEFAULT_LOG)
    if entries is None:
        return ["No custody log found"], [f"{cli_module.DEFAULT_LOG} does not exist yet."]
    public_key_path = (shell_config or {}).get("public_key") or cli_module.DEFAULT_PUBLIC_KEY
    if not Path(public_key_path).exists():
        return ["No public key found"], [f"{public_key_path} does not exist yet -- run Generate keypair first."]

    from ecdsa import VerifyingKey

    verifying_key = VerifyingKey.from_pem(Path(public_key_path).read_bytes())
    if not entries:
        return ["No custody events logged yet"], [["custody_log.json is empty."]]

    per_entry = verifier_module.verify_each(entries, verifying_key)
    chain_view = build_chain_view(entries)

    rows = []
    details = []
    for entry, verification in zip(chain_view, per_entry):
        eids = ", ".join(entry["evidence_ids"])
        target = f"[{eids}]" if len(entry["evidence_ids"]) > 1 else eids
        marker = "OK  " if verification.ok else "TAMPER  "
        rows.append(f"{marker}#{entry['index']} {entry['action']} on {target}")
        details.append(format_entry_detail_lines(entry, verification=verification))

    return rows, details


def _run_evidence_check() -> tuple[list[str], list[list[str]]]:
    index = _load_json(cli_module.DEFAULT_EVIDENCE_INDEX)
    if not index:
        return ["No evidence registered"], [["evidence_index.json is empty or missing."]]
    entries = _load_json(cli_module.DEFAULT_LOG) or []
    folder_index = _load_json(cli_module.DEFAULT_FOLDER_INDEX) or {}

    results, root = verifier_module.verify_evidence_index(index, entries, folder_index=folder_index)
    rows = []
    details = []
    for r in results:
        marker = "OK " if r.ok else "!! "
        rows.append(f"{marker}{r.evidence_id}  ({r.original_filename})")
        details.append(
            [
                f"evidence_id: {r.evidence_id}",
                f"original_filename: {r.original_filename}",
                f"recorded sha256: {r.recorded_sha256}",
                f"source_path: {r.source_path or '(not recorded)'}",
                f"re-hash: {r.rehash_status}",
                f"custody log: {r.logged_status}",
            ]
        )
    if root is not None:
        rows.append("--  Merkle root over all evidence")
        details.append([f"Recomputed root over {len(results)} evidence file(s):", root])
    return rows, details


def _run_merkle_check() -> tuple[list[str], list[list[str]]]:
    index = _load_json(cli_module.DEFAULT_EVIDENCE_INDEX)
    if not index:
        return ["No evidence registered"], [["evidence_index.json is empty or missing -- nothing to build a Merkle root from."]]
    folder_index = _load_json(cli_module.DEFAULT_FOLDER_INDEX) or {}

    # Group by folder_id (or the record's own id if solo) the same way
    # cli.py's _build_main_tree does, so this independently recomputed root
    # matches `merkle-root` for evidence sets containing folder batches.
    grouped_ids = sorted({rec.get("folder_id") or eid for eid, rec in index.items()})
    leaves = [
        folder_index[gid]["root"] if gid in folder_index else index[gid]["sha256"] for gid in grouped_ids
    ]
    root = verifier_module.merkle_root(leaves)
    rows = [f"Root over {len(leaves)} leaf(ves)/folder(s)"]
    details = [[f"Recomputed Merkle root (from evidence_index.json, independent implementation):", root]]

    proof_path = "proof.json"
    if Path(proof_path).exists():
        proof_data = _load_json(proof_path)
        proof_ok = verifier_module.verify_nested_proof(proof_data["leaf"], proof_data["proof"], proof_data["root"])
        eid = proof_data.get("evidence_id", "<unknown>")
        rows.append(f"{'OK' if proof_ok else 'TAMPER'}  proof.json ({eid})")
        details.append(
            [
                f"evidence_id: {eid}",
                f"leaf: {proof_data['leaf']}",
                f"claimed root: {proof_data['root']}",
                "MATCHES claimed root" if proof_ok else "DOES NOT MATCH claimed root -- TAMPER DETECTED",
            ]
        )
    return rows, details


def _run_sidebar_detail_app(
    title: str,
    load_rows: "callable[[], tuple[list[str], list[list[str]]]]",
    top_bar: "callable[[], str] | None" = None,
    extra_keybindings: "callable[[object], None] | None" = None,
    help_text: str = " ↑/↓ select   Ctrl-R/F5 refresh   Esc/q back",
) -> None:
    """Shared sidebar (list of rows) + detail pane (lines for the selected
    row) full-screen application. `load_rows()` is called on open and on
    every manual refresh; `top_bar`/`extra_keybindings` let a caller add a
    tab bar and tab-switching keys on top of the same base screen, without
    duplicating the sidebar/detail/navigation plumbing.
    """
    selected_row = [0]
    rows: list[str] = []
    details: list[list[str]] = []

    def load():
        nonlocal rows, details
        rows, details = load_rows()
        selected_row[0] = 0

    load()

    def render_sidebar() -> str:
        lines = []
        for i, row in enumerate(rows):
            marker = "▸" if i == selected_row[0] else " "
            lines.append(f"{marker} {row}")
        return "\n".join(lines) if lines else "  (nothing to show)"

    def render_detail() -> str:
        if not details:
            return ""
        return "\n".join(details[selected_row[0]])

    kb = KeyBindings()

    if extra_keybindings is not None:
        extra_keybindings(kb, load)

    @kb.add("up")
    def _(event):
        if rows:
            selected_row[0] = max(0, selected_row[0] - 1)

    @kb.add("down")
    def _(event):
        if rows:
            selected_row[0] = min(len(rows) - 1, selected_row[0] + 1)

    @kb.add("c-r")
    @kb.add("f5")
    def _(event):
        load()

    @kb.add("escape")
    @kb.add("q")
    @kb.add("c-c")
    def _(event):
        event.app.exit()

    top_rows = []
    if top_bar is not None:
        top_rows = [Window(FormattedTextControl(top_bar), height=1), Window(height=1, char="─")]

    body = HSplit(
        [
            *top_rows,
            VSplit(
                [
                    Window(FormattedTextControl(render_sidebar), width=D(min=28, max=40)),
                    Window(width=1, char="│"),
                    Window(FormattedTextControl(render_detail), wrap_lines=True),
                ]
            ),
            Window(height=1, char="─"),
            Window(FormattedTextControl(lambda: help_text), height=1),
        ]
    )
    app = Application(
        layout=Layout(Frame(body, title=title)),
        key_bindings=kb,
        full_screen=True,
    )
    app.run()


def run_verification_screen(shell_config: dict | None = None) -> None:
    tab_runners = [
        lambda: _run_chain_check(shell_config),
        _run_evidence_check,
        _run_merkle_check,
    ]
    active_tab = [0]

    def render_top_bar() -> str:
        parts = []
        for i, name in enumerate(TABS):
            label = f" {name} "
            parts.append(f"[{label}]" if i == active_tab[0] else f" {label} ")
        return "".join(parts)

    def add_tab_keybindings(kb: KeyBindings, load) -> None:
        @kb.add("tab")
        @kb.add("right")
        def _(event):
            active_tab[0] = (active_tab[0] + 1) % len(TABS)
            load()

        @kb.add("s-tab")
        @kb.add("left")
        def _(event):
            active_tab[0] = (active_tab[0] - 1) % len(TABS)
            load()

        @kb.add("1")
        def _(event):
            active_tab[0] = 0
            load()

        @kb.add("2")
        def _(event):
            active_tab[0] = 1
            load()

        @kb.add("3")
        def _(event):
            active_tab[0] = 2
            load()

    _run_sidebar_detail_app(
        "Verification",
        lambda: tab_runners[active_tab[0]](),
        top_bar=render_top_bar,
        extra_keybindings=add_tab_keybindings,
        help_text=" Tab/←→ switch section   1-3 jump   ↑/↓ select   Ctrl-R/F5 refresh   Esc/q back",
    )


def run_verify_chain_screen(shell_config: dict | None = None) -> None:
    """Standalone 'Verify chain' screen: sidebar lists one row per custody
    event, detail pane shows full per-entry hash/signature/status -- same
    information the Verification screen's Chain tab shows, but as its own
    dedicated entry point (menu item 4), not a tab inside a bigger screen.
    """
    _run_sidebar_detail_app("Verify Chain", lambda: _run_chain_check(shell_config))
