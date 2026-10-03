
from __future__ import annotations

import json
import os
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


def record_last_verify(shell_config: dict, record: dict, path: str | None = None) -> None:
    """Remember the latest chain verification (in this session and in the config file); a failed write is not an error."""
    shell_config["last_verify"] = record
    try:
        _save_atomic(os.path.abspath(path or DEFAULT_CONFIG_PATH), shell_config)
    except OSError:
        pass


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
    )
    return record if well_formed else None
