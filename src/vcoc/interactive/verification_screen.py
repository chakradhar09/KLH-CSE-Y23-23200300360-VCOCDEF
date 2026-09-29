
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
from vcoc import db
from vcoc.hash_chain import HashChain
from vcoc.visualize import build_chain_view, format_entry_detail_lines

TABS = ["Chain", "Evidence", "Merkle"]


def _load_json(path: str) -> object | None:
    p = Path(path)
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8"))


def _open_db():
    return db.connect(cli_module.DEFAULT_DB) if Path(cli_module.DEFAULT_DB).exists() else None


def _load_entries() -> list[dict] | None:
    conn = _open_db()
    return None if conn is None else [e.to_dict() for e in HashChain.load_db(conn).entries]


def _load_index() -> dict:
    return cli_module._load_evidence_index(cli_module.DEFAULT_DB)


def _load_folders() -> dict:
    return cli_module._load_folder_index(cli_module.DEFAULT_DB)


def _run_chain_check(shell_config: dict | None = None) -> tuple[list[str], list[str]]:
    entries = _load_entries()
    if entries is None:
        return ["No custody log found"], [f"{cli_module.DEFAULT_DB} does not exist yet."]
    public_key_path = (shell_config or {}).get("public_key") or cli_module.DEFAULT_PUBLIC_KEY
    if not Path(public_key_path).exists():
        return ["No public key found"], [f"{public_key_path} does not exist yet -- run Generate keypair first."]

    from ecdsa import VerifyingKey

    verifying_key = VerifyingKey.from_pem(Path(public_key_path).read_bytes())
    if not entries:
        return ["No custody events logged yet"], [["The custody log is empty."]]

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
    index = _load_index()
    if not index:
        return ["No evidence registered"], [["No evidence in the database."]]
    entries = _load_entries() or []
    folder_index = _load_folders()

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
    index = _load_index()
    if not index:
        return ["No evidence registered"], [["No evidence in the database -- nothing to build a Merkle root from."]]
    folder_index = _load_folders()

    grouped_ids = sorted({rec.get("folder_id") or eid for eid, rec in index.items()})
    leaves = [
        folder_index[gid]["root"] if gid in folder_index else index[gid]["sha256"] for gid in grouped_ids
    ]
    root = verifier_module.merkle_root(leaves)
    rows = [f"Root over {len(leaves)} leaf(ves)/folder(s)"]
    details = [[f"Recomputed Merkle root (from the evidence table, independent implementation):", root]]

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
    _run_sidebar_detail_app("Verify Chain", lambda: _run_chain_check(shell_config))
