"""Main menu dispatch table -- collects inputs, calls the existing cmd_* functions."""

from __future__ import annotations

import argparse
import contextlib
import io
from pathlib import Path

import cli as cli_module
from vcoc.storage import EncryptedStore

from . import config as config_module
from . import forms, store_bridge
from .evidence_search import search_evidence, search_evidence_multi
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


def _run_cmd(func, namespace: argparse.Namespace) -> str:
    """Call an existing cmd_* function, capturing stdout, sys.exit(), and errors.

    cmd_* functions were written for a one-shot process that's fine to crash;
    the shell is a long-running session that must survive one bad action
    (e.g. verify-chain on a missing log file) and return to the menu.
    """
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            func(namespace)
    except SystemExit:
        pass
    except Exception as exc:  # noqa: BLE001 -- surfaced to the user, shell must not crash
        print(f"Error: {exc}", file=buf)
    return buf.getvalue().strip()


def _defaults() -> argparse.Namespace:
    """A namespace pre-filled with build_parser()'s own defaults."""
    return argparse.Namespace(
        evidence_index=cli_module.DEFAULT_EVIDENCE_INDEX,
        folder_index=cli_module.DEFAULT_FOLDER_INDEX,
        log=cli_module.DEFAULT_LOG,
        private_key=cli_module.DEFAULT_PRIVATE_KEY,
        public_key=cli_module.DEFAULT_PUBLIC_KEY,
    )


def _pick_evidence_id(store: EncryptedStore | None) -> str | None:
    index = cli_module._load_evidence_index(cli_module.DEFAULT_EVIDENCE_INDEX)
    return search_evidence(index, store)


def ensure_keys(shell_config: dict, config_path: str = config_module.DEFAULT_CONFIG_PATH) -> bool:
    """Confirm private/public key paths exist, prompting + persisting if not.

    Re-checks Path.exists() on every call rather than trusting a cached
    config entry, so a key deleted between sessions re-prompts instead of
    silently failing later. Returns False if the user cancels.
    """
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


def action_add_evidence(store: EncryptedStore | None, shell_config: dict) -> None:
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
    ns.folder_index = cli_module.DEFAULT_FOLDER_INDEX
    ns.actor = None
    ns.private_key = None

    if is_folder and forms.confirm(f"Log a batch-register custody event for {evidence_id}?"):
        if not ensure_keys(shell_config):
            return
        ns.private_key = shell_config["private_key"]
        ns.log = shell_config.get("log", cli_module.DEFAULT_LOG)
        actor = forms.prompt_text("Add evidence", "Actor:")
        if actor is None:
            return
        ns.actor = actor

    output = _run_cmd(cli_module.cmd_add_evidence, ns)

    if store is not None:
        from vcoc.models import Evidence

        index = cli_module._load_evidence_index(ns.evidence_index)
        if is_folder:
            member_ids = [eid for eid, rec in index.items() if rec.get("folder_id") == evidence_id]
            mirrored, failed = 0, 0
            for member_id in member_ids:
                err = store_bridge.mirror_to_store(store, Evidence(**index[member_id]))
                if err:
                    failed += 1
                else:
                    mirrored += 1
            output += f"\nMirrored {mirrored}/{len(member_ids)} folder member(s) to store"
            if failed:
                output += f" ({failed} failed)"
        else:
            rec = index.get(evidence_id)
            if rec is not None:
                err = store_bridge.mirror_to_store(store, Evidence(**rec))
                output += "\n" + (f"Warning: {err}" if err else f"Mirrored {evidence_id} to store")

    forms.show_output("Add evidence", output)


def action_check_evidence(store: EncryptedStore | None, shell_config: dict) -> None:
    evidence_id = _pick_evidence_id(store)
    if evidence_id is None:
        return
    ns = _defaults()
    ns.file = None
    ns.evidence_id = evidence_id
    output = _run_cmd(cli_module.cmd_check_evidence, ns)
    forms.show_output("Check evidence integrity", output)


def action_log_event(store: EncryptedStore | None, shell_config: dict) -> None:
    if not ensure_keys(shell_config):
        return
    index = cli_module._load_evidence_index(cli_module.DEFAULT_EVIDENCE_INDEX)
    evidence_ids = search_evidence_multi(index, store)
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
    output = _run_cmd(cli_module.cmd_log_event, ns)
    forms.show_output("Log custody event", output)


def action_verify_chain(store: EncryptedStore | None, shell_config: dict) -> None:
    if not ensure_keys(shell_config):
        return
    run_verify_chain_screen(shell_config)


def action_merkle_root(store: EncryptedStore | None, shell_config: dict) -> None:
    output = _run_cmd(cli_module.cmd_merkle_root, _defaults())
    forms.show_output("Merkle root", output)


def action_merkle_proof(store: EncryptedStore | None, shell_config: dict) -> None:
    evidence_id = _pick_evidence_id(store)
    if evidence_id is None:
        return
    out_path = forms.prompt_path("Merkle proof", "Output file (blank for stdout):")
    if out_path is None:
        return
    ns = _defaults()
    ns.evidence_id = evidence_id
    ns.out = out_path or None
    output = _run_cmd(cli_module.cmd_merkle_proof, ns)
    forms.show_output("Merkle proof", output)


def action_init_keys(store: EncryptedStore | None, shell_config: dict) -> None:
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


def action_verification(store: EncryptedStore | None, shell_config: dict) -> None:
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
    None,  # Quit -- handled by app.py
]
