"""Shell config file (persisted key paths across sessions).

Plain JSON dict, no schema -- same weight class as evidence_index.json.
"""

from __future__ import annotations

import json
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
