"""Headless tests for vcoc.interactive.menu.ensure_keys (no real TTY)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from prompt_toolkit.application import create_app_session
from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput

from vcoc.interactive import menu


CLEAR_DEFAULT = "\x01\x0b"  # Ctrl-A (start of line) + Ctrl-K (kill to end) -- clears prefilled default text


def run_ensure_keys(keys: str, cwd: Path, shell_config: dict, config_path: str):
    import os

    old_cwd = os.getcwd()
    os.chdir(cwd)
    try:
        with create_pipe_input() as pipe_input:
            pipe_input.send_text(keys)
            with create_app_session(input=pipe_input, output=DummyOutput()):
                return menu.ensure_keys(shell_config, config_path)
    finally:
        os.chdir(old_cwd)


def test_existing_configured_keys_skip_prompt_entirely(tmp_path):
    priv = tmp_path / "priv.pem"
    pub = tmp_path / "pub.pem"
    priv.write_text("fake private key", encoding="utf-8")
    pub.write_text("fake public key", encoding="utf-8")
    shell_config = {"private_key": str(priv), "public_key": str(pub)}
    config_path = str(tmp_path / "shell_config.json")

    # No keys sent -- if this needs to prompt, it will hang since nothing
    # is queued. Passing "" proves ensure_keys never calls Application.run().
    result = run_ensure_keys("", tmp_path, shell_config, config_path)

    assert result is True
    assert shell_config == {"private_key": str(priv), "public_key": str(pub)}


def test_missing_config_prompts_and_persists_existing_key_paths(tmp_path):
    priv = tmp_path / "mykey_priv.pem"
    pub = tmp_path / "mykey_pub.pem"
    priv.write_text("fake private key", encoding="utf-8")
    pub.write_text("fake public key", encoding="utf-8")
    shell_config: dict = {}
    config_path = str(tmp_path / "shell_config.json")

    keys = (
        CLEAR_DEFAULT + str(priv) + "\r"
        + CLEAR_DEFAULT + str(pub) + "\r"
    )
    result = run_ensure_keys(keys, tmp_path, shell_config, config_path)

    assert result is True
    assert shell_config["private_key"] == str(priv)
    assert shell_config["public_key"] == str(pub)
    assert Path(config_path).exists()
    import json

    saved = json.loads(Path(config_path).read_text(encoding="utf-8"))
    assert saved == shell_config


def test_cancelling_private_key_prompt_returns_false_and_leaves_config_untouched(tmp_path):
    shell_config: dict = {}
    config_path = str(tmp_path / "shell_config.json")

    result = run_ensure_keys(CLEAR_DEFAULT + "\x1b", tmp_path, shell_config, config_path)

    assert result is False
    assert shell_config == {}
    assert not Path(config_path).exists()


def test_configured_path_no_longer_exists_re_prompts(tmp_path):
    deleted_priv = tmp_path / "gone_priv.pem"
    new_priv = tmp_path / "new_priv.pem"
    new_pub = tmp_path / "new_pub.pem"
    new_priv.write_text("fake private key", encoding="utf-8")
    new_pub.write_text("fake public key", encoding="utf-8")
    # configured private_key path does not exist on disk
    shell_config = {"private_key": str(deleted_priv), "public_key": str(new_pub)}
    config_path = str(tmp_path / "shell_config.json")

    # public_key default is already correct (new_pub) -- just confirm it as-is.
    keys = CLEAR_DEFAULT + str(new_priv) + "\r" + "\r"
    result = run_ensure_keys(keys, tmp_path, shell_config, config_path)

    assert result is True
    assert shell_config["private_key"] == str(new_priv)
    assert shell_config["public_key"] == str(new_pub)
