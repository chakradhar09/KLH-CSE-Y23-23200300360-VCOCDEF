
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from collections import deque
from pathlib import Path

from prompt_toolkit import Application
from prompt_toolkit.application import get_app
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import HSplit, Layout, VSplit, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.layout.dimension import D
from prompt_toolkit.widgets import Frame

import cli as cli_module
import verifier as verifier_module
from vcoc import db

from . import status as chain_status
from . import theme
from .evidence_search import _add_jump_keys, _visible_height, window_text
from .loading import run_with_loading
from vcoc.hash_chain import HashChain
from vcoc.visualize import build_chain_view, format_entry_detail_lines

TABS = ["Chain", "Evidence", "Merkle"]
_SIDEBAR_WIDTH = 40  # the sidebar's widest column count; the selected row's tint is padded to it
_SIDEBAR_BAR_CELLS = 24  # a progress bar or marquee that fits the column with its indent and percentage
# Help lines must fit the 78 columns inside a frame on an 80-column terminal (tests/test_help_lines.py checks every HELP_*).
HELP_SIDEBAR = " ↑/↓ select   PgUp/PgDn/Home/End jump   Ctrl-R/F5 refresh   Esc/q back"
HELP_VERIFICATION = " Tab/←→ section   1-3 jump   ↑/↓ PgUp/PgDn   Ctrl-R refresh   Esc/q back"


def _load_json(path: str) -> object | None:
    p = Path(path)
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8"))


def _open_db(db_path: str | None = None):
    path = db_path or cli_module.DEFAULT_DB
    return db.connect(path) if Path(path).exists() else None


def _load_entries(db_path: str | None = None) -> list[dict] | None:
    conn = _open_db(db_path)
    return None if conn is None else [e.to_dict() for e in HashChain.load_db(conn).entries]


def _load_index(db_path: str | None = None) -> dict:
    return cli_module._load_evidence_index(db_path or cli_module.DEFAULT_DB)


def _load_folders(db_path: str | None = None) -> dict:
    return cli_module._load_folder_index(db_path or cli_module.DEFAULT_DB)


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
    chain_status.record_chain_check(
        shell_config, os.path.abspath(cli_module.DEFAULT_DB), [v.ok for v in per_entry], [e["index"] for e in entries]
    )
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


_BLOCK = 256  # rows fetched per query and spacing of the saved keys (one block covers any on-screen window)
_PAGE = 1000  # rows read per query while re-hashing
_REHASH_STATUSES = ("match", "MISMATCH", "not found", "no source_path recorded")
_REHASH_OK = (True, False, True, True)


class _EvidenceResults:
    """The Evidence tab's result: ONE byte per evidence row (re-hash status + logged flag) and a saved key every
    _BLOCK rows. Row text and details are built on demand from the database, a block at a time, so a 400,000-row
    check holds a few hundred KB instead of ~1.9 KB per row. Safe to read from a thread other than the one that
    built it (every block fetch opens its own short-lived connection)."""

    def __init__(self, db_path: str, flags: bytearray, keys: list[str], root: str):
        self._db_path = db_path
        self._flags = flags  # bit 0-1: index into _REHASH_STATUSES, bit 2: logged, bit 3: logged only via its folder
        self._keys = keys  # evidence_id of every _BLOCK-th row, in id order
        self._root = root
        self._block_no = -1
        self._block: list[tuple] = []

    @property
    def total(self) -> int:
        return len(self._flags) + 1  # + the "Merkle root over all evidence" row

    def _fetch(self, i: int) -> tuple:
        block_no = i // _BLOCK
        if block_no != self._block_no:
            conn = sqlite3.connect(self._db_path)
            try:
                self._block = conn.execute(
                    "SELECT evidence_id, original_filename, sha256, source_path, folder_id FROM evidence"
                    " WHERE evidence_id >= ? ORDER BY evidence_id LIMIT ?",
                    (self._keys[block_no], _BLOCK),
                ).fetchall()
            finally:
                conn.close()
            self._block_no = block_no
        return self._block[i - block_no * _BLOCK]

    def row(self, i: int) -> str:
        if i == len(self._flags):
            return "--  Merkle root over all evidence"
        evidence_id, filename, _, _, _ = self._fetch(i)
        flag = self._flags[i]
        ok = _REHASH_OK[flag & 3] and bool(flag & 4)
        return f"{'OK ' if ok else '!! '}{evidence_id}  ({filename})"

    def detail(self, i: int) -> list[str]:
        if i == len(self._flags):
            return [f"Recomputed root over {len(self._flags)} evidence file(s):", self._root]
        evidence_id, filename, sha256, source_path, folder_id = self._fetch(i)
        flag = self._flags[i]
        logged = "NOT LOGGED" if not flag & 4 else f"logged (via folder {folder_id})" if flag & 8 else "logged"
        return [
            f"evidence_id: {evidence_id}",
            f"original_filename: {filename}",
            f"recorded sha256: {sha256}",
            f"source_path: {source_path or '(not recorded)'}",
            f"re-hash: {_REHASH_STATUSES[flag & 3]}",
            f"custody log: {logged}",
        ]


class _LazySeq:
    """list-like view (len, index, negative index, iteration, ==) over one kind of _EvidenceResults output."""

    def __init__(self, results: _EvidenceResults, kind: str):
        self._results = results
        self._get = results.row if kind == "row" else results.detail

    def __len__(self) -> int:
        return self._results.total

    def __getitem__(self, i):
        if isinstance(i, slice):
            return [self[j] for j in range(*i.indices(len(self)))]
        n = len(self)
        if i < 0:
            i += n
        if not 0 <= i < n:
            raise IndexError(i)
        return self._get(i)

    def __iter__(self):
        for i in range(len(self)):
            yield self._get(i)

    def __eq__(self, other):
        if isinstance(other, (list, tuple, _LazySeq)):
            return len(self) == len(other) and all(a == b for a, b in zip(self, other))
        return NotImplemented

    __hash__ = None


def _evidence_rows(conn):
    """(evidence_id, sha256, source_path, folder_id, size_bytes) of every evidence row, in id order.

    Keyset pages, each fetched completely: no statement stays open while files are hashed, so the database is not
    read-locked for the minutes a big re-hash takes (an open cursor here locked the Merkle tab out)."""
    last = None
    while True:
        if last is None:
            page = conn.execute(
                "SELECT evidence_id, sha256, source_path, folder_id, size_bytes FROM evidence ORDER BY evidence_id LIMIT ?",
                (_PAGE,),
            ).fetchall()
        else:
            page = conn.execute(
                "SELECT evidence_id, sha256, source_path, folder_id, size_bytes FROM evidence WHERE evidence_id > ?"
                " ORDER BY evidence_id LIMIT ?",
                (last, _PAGE),
            ).fetchall()
        if not page:
            return
        yield from page
        last = page[-1][0]


def _pool_size(jobs: int, total: int) -> int:
    """Workers a re-hash of `total` rows really uses: `jobs`, but 1 (serial) below the pool's minimum file count."""
    return jobs if jobs > 1 and total >= verifier_module.PARALLEL_MIN_FILES else 1


def _rehashed(rows, total: int, jobs: int, progress):
    """(position, row, status) for every row, re-hashed from disk, in row order.

    jobs > 1 hashes in a process pool (the whole 400k-row check is file-open/read latency, not CPU): progress then fires once
    per hashed file, when it is done, not per chunk. The workers are stopped when this generator is closed or an exception
    (the progress hook's cancel) leaves the loop that reads it."""
    if _pool_size(jobs, total) == 1:
        for position, row in enumerate(rows, 1):
            yield position, row, verifier_module.evidence_rehash_status(position, total, row[0], row[2], row[1], progress)
        return

    pending = deque()  # the rows the pool has been handed and not yet answered: bounded by the pool's look-ahead

    def entries():
        for row in rows:  # EVERY row, so results stay 1:1 with rows: an empty source_path answers without any I/O
            pending.append(row)
            yield row[2], row[1], row[4]

    results = verifier_module._rehash_parallel(entries(), jobs)
    try:
        for position, result in enumerate(results, 1):
            row = pending.popleft()
            if isinstance(result, OSError):  # not "missing": raised, exactly as a serial run does
                raise result
            if result is None:  # a very big file: hashed here, so it keeps byte-level progress and chunk-level cancel
                result = verifier_module.evidence_rehash_status(position, total, row[0], row[2], row[1], progress)
            elif progress is not None and result in ("match", "MISMATCH"):
                size = row[4] or 0
                progress(position, total, row[0], size, size)
            yield position, row, result
    finally:
        results.close()


def _run_evidence_check(
    progress=None, db_path: str | None = None, jobs: int | None = None
) -> tuple[list[str], list[list[str]]]:
    # db_path: pass an absolute path when this runs on a background thread, so a later chdir cannot redirect it
    # jobs: re-hash worker processes; None = verifier.auto_jobs (VCOC_HASH_JOBS wins, small databases stay serial)
    path = db_path or cli_module.DEFAULT_DB
    if not Path(path).exists():
        return ["No evidence registered"], [["No evidence in the database."]]
    conn = db.connect(path)
    try:
        total = conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
        if not total:
            return ["No evidence registered"], [["No evidence in the database."]]
        logged_ids: set[str] = set()
        for entry in _load_entries(path) or []:
            if entry.get("evidence_ids") is not None:
                logged_ids.update(entry["evidence_ids"])
            else:
                logged_ids.add(entry["evidence_id"])

        # Folder ids that are both logged and really registered: their members count as logged (see verifier.py)
        logged_folders = {r[0] for r in conn.execute("SELECT folder_id FROM folders") if r[0] in logged_ids}

        flags = bytearray()
        keys: list[str] = []
        if jobs is None:
            jobs = verifier_module.auto_jobs(total)
        set_workers = getattr(progress, "set_workers", None)  # the shell's loader shows it in the sidebar
        if set_workers is not None:
            set_workers(_pool_size(jobs, total))
        stream = _rehashed(_evidence_rows(conn), total, jobs, progress)
        try:
            for position, (evidence_id, _, _, folder_id, _), status in stream:
                if (position - 1) % _BLOCK == 0:
                    keys.append(evidence_id)
                if evidence_id in logged_ids:
                    logged = 4
                elif folder_id in logged_folders:
                    logged = 12
                else:
                    logged = 0
                flags.append(_REHASH_STATUSES.index(status) | logged)
        finally:
            stream.close()  # on an exception (the progress hook's cancel) this is what stops the pool's workers

        leaves = [leaf for _, leaf, _ in db.group_leaves(conn, counts=False)]
    finally:
        conn.close()
    results = _EvidenceResults(path, flags, keys, verifier_module.merkle_root(leaves))
    return _LazySeq(results, "row"), _LazySeq(results, "detail")


def _run_merkle_check(
    db_path: str | None = None, proof_path: str | None = None
) -> tuple[list[str], list[list[str]]]:
    path = db_path or cli_module.DEFAULT_DB
    if not Path(path).exists():
        return ["No evidence registered"], [["No evidence in the database -- nothing to build a Merkle root from."]]
    conn = db.connect(path)
    try:
        leaves = [leaf for _, leaf, _ in db.group_leaves(conn, counts=False)]  # one group per folder / standalone file, sorted by id
    finally:
        conn.close()
    if not leaves:
        return ["No evidence registered"], [["No evidence in the database -- nothing to build a Merkle root from."]]
    root = verifier_module.merkle_root(leaves)
    rows = [f"Root over {len(leaves)} leaf(ves)/folder(s)"]
    details = [[f"Recomputed Merkle root (from the evidence table, independent implementation):", root]]

    proof_path = proof_path or "proof.json"
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


class _Cancelled(Exception):
    # Deliberately not an OSError (InterruptedError is one): nothing between the callback and the loader may swallow it.
    pass


class _BackgroundLoad:
    """Runs a slow load on a daemon thread so the prompt_toolkit event loop stays free.

    Starting a new load or calling cancel() supersedes the running one: its progress callback raises
    _Cancelled (stopping the hash at the next chunk) and its result is dropped, never published."""

    def __init__(self, on_change, on_result=None, min_interval: float = 0.1, clock=time.monotonic):
        self._on_change = on_change
        self._on_result = on_result
        self._min_interval = min_interval
        self._clock = clock
        self._started = 0.0
        self._lock = threading.Lock()
        self._generation = 0
        self._last_change = 0.0
        self.loading = False
        self._status = ""
        self._progress = None
        self._workers = None  # how many re-hash workers the running load reports it uses (None until it says)

    @property
    def status(self) -> str:
        if self._progress is not None:
            i, n, evidence_id, done, total = self._progress
            fmt = verifier_module._fmt_bytes
            pct = 100 * done // total if total else 100
            return f"Re-hashing {i}/{n}  {evidence_id}  {fmt(done)} / {fmt(total)} ({pct}%)"
        return self._status

    @status.setter
    def status(self, text: str) -> None:
        self._status = text
        self._progress = None

    def fraction(self) -> float | None:
        """How far through all the files the re-hash is (finished files plus the part done of the current one); None before any."""
        if self._progress is None:
            return None
        i, n, _, done, total = self._progress
        part = min(done / total, 1.0) if total else 1.0
        return min(((i - 1) + part) / n, 1.0) if n else 1.0

    def screen_text(self) -> str:
        """What the sidebar column shows while this loads: short lines (the column is at most 40 wide), a block bar when
        the progress is known and a moving marquee when it is not, and the elapsed clock."""
        elapsed = self._clock() - self._started
        clock = f"  {elapsed:.1f} s"
        if self._progress is None:
            return "\n".join(["  Working...", "", "  " + theme.marquee(elapsed, _SIDEBAR_BAR_CELLS, 5), "", clock])
        i, n, evidence_id, done, total = self._progress
        fmt = verifier_module._fmt_bytes
        name = evidence_id if len(evidence_id) <= 30 else evidence_id[:29] + "…"
        lines = [
            "  Re-hashing evidence", f"  File {i:,} of {n:,}", f"  {name}", f"  {fmt(done)} of {fmt(total)}", "",
            "  " + theme.progress_bar(self.fraction(), _SIDEBAR_BAR_CELLS), "",
        ]
        if elapsed > 0:  # files per second so far (files finished or being hashed / time), and the workers doing them
            rate = i / elapsed
            speed = f"{rate:,.0f} files/s" if rate >= 10 else f"{rate:.1f} files/s"
            workers = self._workers
            lines.append("  " + (f"{workers} worker{'s' * (workers != 1)}  " if workers else "") + speed)
        return "\n".join(lines + [clock])

    def start(self, load) -> None:
        with self._lock:
            self._generation += 1
            gen = self._generation
            self.loading = True
            self._started = self._clock()
            self._workers = None
            self.status = "Loading..."

        def progress(i: int, n: int, evidence_id: str, done: int, total: int) -> None:
            if gen != self._generation:
                raise _Cancelled
            self._progress = (i, n, evidence_id, done, total)  # formatted only when the screen asks for the text
            now = time.monotonic()
            if done >= total or now - self._last_change >= self._min_interval:
                self._last_change = now
                self._on_change()

        def set_workers(count: int) -> None:
            if gen == self._generation:  # a superseded load must not overwrite the newer one's count
                self._workers = count

        progress.set_workers = set_workers  # a load that knows its worker count says so; plain callbacks never have to

        def run() -> None:
            try:
                result = load(progress)
            except _Cancelled:
                return
            except Exception as exc:
                result = ([f"Error: {exc}"], [[f"Error: {exc}"]])
            with self._lock:  # publish under the lock so a newer start() can never be overwritten by this stale result
                if gen != self._generation:
                    return
                self.loading = False
                self.status = ""
                if self._on_result is not None:
                    self._on_result(result)
            self._on_change()

        threading.Thread(target=run, daemon=True, name="vcoc-bgload").start()

    def cancel(self) -> None:
        with self._lock:
            self._generation += 1
            self.loading = False
            self.status = ""


def _sidebar_text(rows: list[str], selected: int, top: list[int], height: int) -> str:
    """The sidebar: only the visible rows (a 92,879-row Evidence tab redraws as cheaply as a 3-row one)."""
    if not rows:
        return "  (nothing to show)"
    return window_text(
        rows,
        lambda row, i: f"{'▸' if i == selected else ' '} {row}",
        selected,
        top,
        height,
        footer=len(rows) > height,  # a short list looks exactly as before: no position line
    )


def _sidebar_lines(has_tabs: bool) -> int:
    """Lines in the sidebar column: the terminal minus the frame, the rule and help line (and the tab bar with its rule)."""
    try:
        rows = get_app().output.get_size().rows
    except Exception:
        rows = 40
    return max(5, rows - 4 - (2 if has_tabs else 0))


def _run_sidebar_detail_app(
    title: str,
    load_rows: "callable[[], tuple[list[str], list[list[str]]]]",
    top_bar: "callable[[], str] | None" = None,
    extra_keybindings: "callable[[object], None] | None" = None,
    help_text: str = HELP_SIDEBAR,
    slow_load: "tuple[callable[[], object | None], callable[[callable], tuple[list[str], list[list[str]]]]] | None" = None,
    loading_label: str | None = None,
) -> None:
    # slow_load = (slow_key, load_with_progress). slow_key() returns a hashable key while the active tab is a slow tab
    # (None for fast tabs). Each slow tab keeps ONE background loader and result for the life of the screen, so switching
    # tabs neither cancels nor restarts it: the hash keeps running and the tab shows live progress or the finished result
    # on return. Only Ctrl-R/F5 on that tab restarts it; leaving the screen cancels everything. load_rows stays zero-arg.
    selected_row = [0]
    top = [0]  # first visible sidebar row (the sidebar renders only a window of the rows)
    view = [([], [])]  # what the active FAST tab shows: (rows, details), replaced wholesale
    results: dict = {}  # slow tab key -> (rows, details), replaced wholesale by its worker thread
    loaders: dict = {}  # slow tab key -> _BackgroundLoad
    started: set = set()
    holder: list[Application] = []

    def active_key():
        return slow_load[0]() if slow_load is not None else None

    def loader_for(key) -> _BackgroundLoad:
        if key not in loaders:
            loaders[key] = _BackgroundLoad(
                on_change=lambda: holder and holder[0].invalidate(),
                on_result=lambda result, k=key: results.__setitem__(k, result),
            )
        return loaders[key]

    def current():
        """(loader or None, rows, details) for whichever tab is showing."""
        key = active_key()
        if key is None:
            return (None, *view[0])
        return (loaders.get(key), *results.get(key, ([], [])))

    # With a loading_label the first (fast-tab) load runs behind the shared full-screen loading screen, so the plain terminal
    # never shows between the menu and this screen; the result is used as-is, not computed a second time.
    preloaded = []
    if loading_label is not None and active_key() is None:
        preloaded.append(run_with_loading(title, load_rows, loading_label))

    def load(refresh: bool = False):
        selected_row[0] = 0
        top[0] = 0
        key = active_key()
        if key is None:
            view[0] = preloaded.pop() if preloaded else load_rows()
        elif refresh or key not in started:
            started.add(key)
            results.pop(key, None)
            load_fns = slow_load[1]
            loader_for(key).start(load_fns[key] if isinstance(load_fns, dict) else load_fns)  # supersedes an earlier run of this tab

    load()

    def sidebar_loading() -> bool:
        bg = current()[0]
        return bg is not None and bg.loading

    def render_sidebar() -> str:
        bg, rows, _ = current()
        if bg is not None and bg.loading:
            return bg.screen_text()
        # The column's real height, so the rows fill it and the position footer lands on its last line.
        lines = _sidebar_lines(top_bar is not None)
        return _sidebar_text(rows, selected_row[0], top, lines - 1 if len(rows) > lines else lines)

    def render_detail() -> str:
        bg, _, details = current()
        if bg is not None and bg.loading:
            return "Working in the background; it keeps running if you switch tabs.\nEsc/q leaves and cancels   Ctrl-R restarts"
        if not details:
            return ""
        return "\n".join(details[selected_row[0]])

    kb = KeyBindings()

    if extra_keybindings is not None:
        extra_keybindings(kb, load)

    @kb.add("up")
    def _(event):
        if current()[1]:
            selected_row[0] = max(0, selected_row[0] - 1)

    @kb.add("down")
    def _(event):
        rows = current()[1]
        if rows:
            selected_row[0] = min(len(rows) - 1, selected_row[0] + 1)

    _add_jump_keys(kb, selected_row, lambda: len(current()[1]))

    @kb.add("c-r")
    @kb.add("f5")
    def _(event):
        load(refresh=True)  # the ONLY thing that restarts a slow tab's hash

    @kb.add("escape")
    @kb.add("q")
    @kb.add("c-c")
    def _(event):
        event.app.exit()

    shell_theme = theme.current()
    rule, divider = theme.glyph("─", shell_theme), theme.glyph("│", shell_theme)
    top_rows = []
    if top_bar is not None:
        top_rows = [
            Window(FormattedTextControl(theme.styled(top_bar, "tabs")), height=1),
            Window(height=1, char=rule, style="class:chrome"),
        ]

    body = HSplit(
        [
            *top_rows,
            VSplit(
                [
                    Window(
                        FormattedTextControl(
                            theme.styled(render_sidebar, lambda: "loading" if sidebar_loading() else "sidebar", width=_SIDEBAR_WIDTH)
                        ),
                        width=D(min=28, max=_SIDEBAR_WIDTH),
                    ),
                    Window(width=1, char=divider, style="class:chrome"),
                    Window(FormattedTextControl(theme.styled(render_detail)), wrap_lines=True),
                ]
            ),
            Window(height=1, char=rule, style="class:chrome"),
            Window(FormattedTextControl(theme.styled(lambda: help_text, "hint")), height=1),
        ]
    )
    app = Application(
        layout=Layout(Frame(body, title=title)),
        key_bindings=kb,
        full_screen=True,
        style=theme.app_style(shell_theme),
        refresh_interval=0.1 if slow_load is not None else None,  # a tab that loads in the background animates its marquee
    )
    holder.append(app)
    try:
        app.run()
    finally:
        for bg in loaders.values():
            bg.cancel()  # leaving the screen must stop any hash still running in the background


def run_verification_screen(shell_config: dict | None = None) -> None:
    db_path = os.path.abspath(cli_module.DEFAULT_DB)  # bound now: the slow tabs load on a background thread
    proof_path = os.path.abspath("proof.json")
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
        slow_load=(
            lambda: TABS[active_tab[0]] if TABS[active_tab[0]] in ("Evidence", "Merkle") else None,
            {
                "Evidence": lambda progress: _run_evidence_check(progress=progress, db_path=db_path),
                "Merkle": lambda progress: _run_merkle_check(db_path=db_path, proof_path=proof_path),
            },
        ),
        extra_keybindings=add_tab_keybindings,
        help_text=HELP_VERIFICATION,
        loading_label="Checking the custody chain...",
    )


def run_verify_chain_screen(shell_config: dict | None = None) -> None:
    _run_sidebar_detail_app(
        "Verify Chain", lambda: _run_chain_check(shell_config), loading_label="Verifying the custody chain..."
    )
