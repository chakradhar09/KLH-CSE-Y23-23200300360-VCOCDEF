
from __future__ import annotations

import argparse
import contextlib
import io
import os
import re
import time
from pathlib import Path

import cli as cli_module
import verifier as verifier_module

from . import config as config_module
from . import forms, theme
from .evidence_search import search_evidence_db, search_evidence_multi_db
from .loading import run_with_loading
from .verification_screen import run_verification_screen, run_verify_chain_screen

MENU_ITEMS = [
    "Add evidence",
    "Check evidence integrity",
    "Log custody event",
    "Verify chain",
    "Merkle root",
    "Merkle proof",
    "Generate keypair",
    "Verification (chain / evidence / merkle)",
    "Quit",
]


def _fmt_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f} s"
    whole = int(seconds)
    minutes, secs = divmod(whole, 60)
    if minutes < 60:
        return f"{minutes} min {secs:02d} s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours} h {minutes:02d} min {secs:02d} s"


class IngestCancelled(Exception):
    """Raised from the progress hook after Esc: the ingest stops and nothing it hashed is recorded."""


class _IngestProgress:
    """The `progress` hook of a folder add-evidence, plus the live text the loading screen shows for it.

    The ingest thread only stores the latest numbers (one tuple assignment); the screen builds the text when it redraws.
    """

    def __init__(self, clock=time.monotonic):
        self._clock = clock
        self._first: float | None = None
        self._last: tuple | None = None
        self.cancelled = False

    def cancel(self) -> None:
        self.cancelled = True

    def __call__(self, i, n, rel, size, done, total) -> None:
        if self.cancelled:
            raise IngestCancelled("Cancelled: nothing was recorded.")
        if self._first is None:
            self._first = self._clock()
        self._last = (i, n, rel, size, done, total)

    @property
    def files(self) -> int:
        return self._last[1] if self._last else 0

    @property
    def hashed_bytes(self) -> int:
        return self._last[4] if self._last else 0

    def fraction(self) -> float | None:
        """Bytes hashed over bytes in total (1.0 for an empty folder); None until the first report. Never reads the clock."""
        last = self._last
        if last is None:
            return None
        done, total = last[4], last[5]
        return min(done / total, 1.0) if total else 1.0

    def screen_text(self) -> str:
        """What the loading screen shows: `text()` unchanged, then a blank line and the block progress bar."""
        text = self.text()
        fraction = self.fraction()
        return text if fraction is None else f"{text}\n\n{theme.progress_bar(fraction)}"

    def text(self) -> str:
        last = self._last
        if last is None:
            return "Scanning the folder..."
        i, n, rel, size, done, total = last
        fmt = verifier_module._fmt_bytes
        if i == n and done >= total:  # every file is hashed: what is left is writing the rows
            return f"All {n:,} file(s) hashed ({fmt(total)}).\nRecording to the database..."
        elapsed = max(self._clock() - self._first, 1e-9)
        rate = done / elapsed
        pct = 100 * done // total if total else 100
        line = f"{fmt(done)} of {fmt(total)} ({pct}%)"
        if done:
            line += f"   {fmt(rate)}/s"
            if rate:
                line += f"   about {_fmt_duration((total - done) / rate)} left"
        shown = rel if len(rel) <= 70 else "..." + rel[-67:]
        return f"Hashing file {i:,} of {n:,}\n  {shown} ({fmt(size)})\n{line}"


def _ingest_summary(output: str, progress: _IngestProgress, elapsed: float, logged_event: bool) -> str:
    """The closing block of a folder add-evidence: how many files were recorded, how long it took, custody event."""
    match = re.search(r"Registered folder .*?: (\d+) file\(s\)", output)
    recorded = int(match.group(1)) if match else progress.files
    fmt = verifier_module._fmt_bytes
    speed = f"{recorded / elapsed:,.0f} files/s, {fmt(progress.hashed_bytes / elapsed)}/s" if elapsed > 0 else ""
    return (
        "\n\nSummary\n"
        f"  Files recorded : {recorded:,} ({fmt(progress.hashed_bytes)})\n"
        f"  Total time     : {_fmt_duration(elapsed)}  ({speed})\n"
        f"  Custody event  : {'logged (batch-register)' if logged_event else 'NOT logged (you chose not to log one)'}"
    )


def _run_cmd(func, namespace: argparse.Namespace) -> str:
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            func(namespace)
    except SystemExit:
        pass
    except Exception as exc:
        print(f"Error: {exc}", file=buf)
    return buf.getvalue().strip()


def _defaults() -> argparse.Namespace:
    return argparse.Namespace(
        db=cli_module.DEFAULT_DB,
        private_key=cli_module.DEFAULT_PRIVATE_KEY,
        public_key=cli_module.DEFAULT_PUBLIC_KEY,
    )


def _run_cmd_loading(title: str, label: str, func, namespace: argparse.Namespace, status=None, cancel=None) -> str:
    """_run_cmd behind a loading screen, so slow commands never run with the plain terminal on display."""
    return run_with_loading(title, lambda: _run_cmd(func, namespace), label, status=status, cancel=cancel)


def _pick_evidence_id() -> str | None:
    # The search screens read the table a page at a time (no index load), so there is nothing slow to hide any more.
    return search_evidence_db(os.path.abspath(cli_module.DEFAULT_DB))


def ensure_keys(shell_config: dict, config_path: str = config_module.DEFAULT_CONFIG_PATH) -> bool:
    private_key = shell_config.get("private_key")
    public_key = shell_config.get("public_key")
    if private_key and public_key and Path(private_key).exists() and Path(public_key).exists():
        return True

    private_key = forms.prompt_path(
        "Locate signing key", "Private key path:", private_key or cli_module.DEFAULT_PRIVATE_KEY
    )
    if private_key is None:
        return False
    public_key = forms.prompt_path(
        "Locate signing key", "Public key path:", public_key or cli_module.DEFAULT_PUBLIC_KEY
    )
    if public_key is None:
        return False

    if not Path(private_key).exists() or not Path(public_key).exists():
        if not forms.confirm(f"Keys not found. Generate a new keypair at {private_key} / {public_key}?"):
            return False
        ns = _defaults()
        ns.private_key = private_key
        ns.public_key = public_key
        output = _run_cmd(cli_module.cmd_init_keys, ns)
        forms.show_output("Generate keypair", output)

    shell_config["private_key"] = private_key
    shell_config["public_key"] = public_key
    config_module.save_config(config_path, shell_config)
    return True


def action_add_evidence(shell_config: dict) -> None:
    file_path = forms.prompt_path("Add evidence", "File path:")
    if file_path is None:
        return
    evidence_id = forms.prompt_text("Add evidence", "Evidence ID:")
    if evidence_id is None:
        return
    is_folder = Path(file_path).is_dir()

    ns = _defaults()
    ns.file = file_path
    ns.evidence_id = evidence_id
    ns.actor = None
    ns.private_key = None

    if is_folder and forms.confirm(f"Log a batch-register custody event for {evidence_id}?", default=True):
        if not ensure_keys(shell_config):
            return
        ns.private_key = shell_config["private_key"]
        actor = forms.prompt_text("Add evidence", "Actor:")
        if actor is None:
            return
        ns.actor = actor

    progress = _IngestProgress() if is_folder else None
    if progress is not None:
        ns.progress = progress  # live status on the loading screen; also stops the per-file lines flooding the output
    started = time.monotonic()
    output = _run_cmd_loading(
        "Add evidence",
        "Hashing and registering the evidence...",
        cli_module.cmd_add_evidence,
        ns,
        status=progress.screen_text if progress is not None else None,
        cancel=progress.cancel if progress is not None else None,
    )
    if progress is not None and progress.cancelled:
        output = "Cancelled: nothing was recorded."
    elif progress is not None and "Registered folder" in output:
        output += _ingest_summary(output, progress, time.monotonic() - started, ns.private_key is not None)

    forms.show_output("Add evidence", output)


def action_check_evidence(shell_config: dict) -> None:
    evidence_id = _pick_evidence_id()
    if evidence_id is None:
        return
    ns = _defaults()
    ns.file = None
    ns.evidence_id = evidence_id
    output = _run_cmd_loading(
        "Check evidence integrity", "Re-hashing the file and comparing...", cli_module.cmd_check_evidence, ns
    )
    forms.show_output("Check evidence integrity", output)


def action_log_event(shell_config: dict) -> None:
    if not ensure_keys(shell_config):
        return
    evidence_ids = search_evidence_multi_db(os.path.abspath(cli_module.DEFAULT_DB))
    if evidence_ids is None:
        return
    actor = forms.prompt_text("Log custody event", "Actor:")
    if actor is None:
        return
    action = forms.prompt_text("Log custody event", "Action:")
    if action is None:
        return
    ns = _defaults()
    ns.evidence_id = evidence_ids
    ns.actor = actor
    ns.action = action
    ns.private_key = shell_config["private_key"]
    ns.case_number = None
    ns.tag = None
    ns.notes = None
    if len(evidence_ids) > 1:
        case_number = forms.prompt_text("Log custody event", "Case number (optional):")
        if case_number is None:
            return
        tag = forms.prompt_text("Log custody event", "Tag (optional):")
        if tag is None:
            return
        notes = forms.prompt_text("Log custody event", "Notes (optional):")
        if notes is None:
            return
        ns.case_number = case_number or None
        ns.tag = tag or None
        ns.notes = notes or None
    output = _run_cmd_loading("Log custody event", "Signing and logging the event...", cli_module.cmd_log_event, ns)
    forms.show_output("Log custody event", output)


def action_verify_chain(shell_config: dict) -> None:
    if not ensure_keys(shell_config):
        return
    run_verify_chain_screen(shell_config)


def action_merkle_root(shell_config: dict) -> None:
    output = _run_cmd_loading("Merkle root", "Computing the Merkle root...", cli_module.cmd_merkle_root, _defaults())
    forms.show_output("Merkle root", output)


def action_merkle_proof(shell_config: dict) -> None:
    evidence_id = _pick_evidence_id()
    if evidence_id is None:
        return
    out_path = forms.prompt_path("Merkle proof", "Output file (blank for stdout):")
    if out_path is None:
        return
    ns = _defaults()
    ns.evidence_id = evidence_id
    ns.out = out_path or None
    output = _run_cmd_loading("Merkle proof", "Building the Merkle proof...", cli_module.cmd_merkle_proof, ns)
    forms.show_output("Merkle proof", output)


def action_init_keys(shell_config: dict) -> None:
    ns = _defaults()
    private_key = forms.prompt_path("Generate keypair", "Private key path:", ns.private_key)
    if private_key is None:
        return
    public_key = forms.prompt_path("Generate keypair", "Public key path:", ns.public_key)
    if public_key is None:
        return
    ns.private_key = private_key
    ns.public_key = public_key
    output = _run_cmd(cli_module.cmd_init_keys, ns)
    forms.show_output("Generate keypair", output)


def action_verification(shell_config: dict) -> None:
    run_verification_screen(shell_config)


ACTIONS = [
    action_add_evidence,
    action_check_evidence,
    action_log_event,
    action_verify_chain,
    action_merkle_root,
    action_merkle_proof,
    action_init_keys,
    action_verification,
    None,
]
