"""Pure-function tests for vcoc.interactive.config -- no terminal needed."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from vcoc.interactive import config


def test_load_config_missing_file_returns_empty_dict(tmp_path):
    path = tmp_path / "shell_config.json"
    assert not path.exists()

    assert config.load_config(str(path)) == {}


def test_save_then_load_round_trips(tmp_path):
    path = tmp_path / "shell_config.json"
    data = {"private_key": "keys/priv.pem", "public_key": "keys/pub.pem"}

    config.save_config(str(path), data)
    loaded = config.load_config(str(path))

    assert loaded == data
    assert path.exists()


def test_load_config_corrupt_file_returns_empty_dict(tmp_path):
    path = tmp_path / "shell_config.json"
    path.write_text("{not valid json", encoding="utf-8")

    assert config.load_config(str(path)) == {}
