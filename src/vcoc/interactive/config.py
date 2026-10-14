
from __future__ import annotations

import json
import os
import threading
from pathlib import Path

DEFAULT_CONFIG_PATH = "shell_config.json"


def load_config(path: str = DEFAULT_CONFIG_PATH) -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def save_config(path: str, data: dict) -> None:
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")


def _save_atomic(path: str, data: dict) -> None:
    """Write beside the target, then replace it, so a crash never leaves a half-written config."""
    target = Path(path)
    temporary = target.with_name(target.name + ".tmp")
    try:
        temporary.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.replace(temporary, target)
    except OSError:
        temporary.unlink(missing_ok=True)
        raise


_write_lock = threading.Lock()  # the chain check saves from the screen's thread, the evidence check from its worker thread


def _remember(shell_config: dict, key: str, record: dict, path: str | None) -> None:
    with _write_lock:  # setting a key while the other thread dumps the dict would break its json.dumps
        shell_config[key] = record
        try:
            _save_atomic(os.path.abspath(path or DEFAULT_CONFIG_PATH), shell_config)
        except OSError:
            pass


def record_last_verify(shell_config: dict, record: dict, path: str | None = None) -> None:
    """Remember the latest chain verification (in this session and in the config file); a failed write is not an error."""
    _remember(shell_config, "last_verify", record, path)


def record_evidence_check(shell_config: dict, record: dict, path: str | None = None) -> None:
    """Remember the latest evidence check (files re-hashed against their recorded sha256), the same way."""
    _remember(shell_config, "last_evidence_check", record, path)


def record_witness_check(shell_config: dict, record: dict, path: str | None = None) -> None:
    """Remember the latest check of the log against a witness-cosigned checkpoint, the same way."""
    _remember(shell_config, "last_witness", record, path)


def _count(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def last_verify(shell_config: dict, db_path: str) -> dict | None:
    """The recorded verification of this database, or None when there is none or the entry is malformed."""
    record = shell_config.get("last_verify")
    if not isinstance(record, dict) or record.get("db") != db_path:
        return None
    at = record.get("at")
    well_formed = (
        isinstance(at, (int, float)) and not isinstance(at, bool)
        and isinstance(record.get("ok"), bool)
        and _count(record.get("events"))
        and _count(record.get("evidence_max"))
        and (record.get("bad_event") is None or _count(record.get("bad_event")))
        and ("high_water" not in record or _count(record["high_water"]))  # older records have neither of these two
        and ("first_hash" not in record or isinstance(record["first_hash"], str))
    )
    return record if well_formed else None


def last_witness(shell_config: dict, db_path: str) -> dict | None:
    """The recorded witness-checkpoint check of this database, or None when there is none or the entry is malformed."""
    record = shell_config.get("last_witness")
    if not isinstance(record, dict) or record.get("db") != db_path:
        return None
    well_formed = (
        isinstance(record.get("at"), (int, float)) and not isinstance(record.get("at"), bool)
        and isinstance(record.get("ok"), bool)
        and all(_count(record.get(key)) for key in ("size", "events", "cosigners", "quorum"))
        and isinstance(record.get("first_hash", ""), str)
    )
    return record if well_formed else None


def last_evidence_check(shell_config: dict, db_path: str) -> dict | None:
    """The recorded evidence check of this database, or None when there is none or the entry is malformed."""
    record = shell_config.get("last_evidence_check")
    if not isinstance(record, dict) or record.get("db") != db_path:
        return None
    at = record.get("at")
    counts = ("total", "tampered", "not_logged", "unverifiable", "events", "evidence_max")
    well_formed = isinstance(at, (int, float)) and not isinstance(at, bool) and all(_count(record.get(key)) for key in counts)
    return record if well_formed else None
