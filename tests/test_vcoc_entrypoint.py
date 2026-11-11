"""The `vcoc` command dispatches to the CLI, the verifier and the witness; the root shims stay the same modules."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from vcoc import __version__
from vcoc.__main__ import main

ROOT = Path(__file__).resolve().parent.parent


def test_version(capsys):
    main(["--version"])
    assert capsys.readouterr().out.strip() == f"vcoc {__version__}"


@pytest.mark.parametrize("argv, prog", [(["add-evidence", "--help"], "usage: vcoc add-evidence"), (["verify", "--help"], "usage: vcoc verify"),
                                        (["witness", "--help"], "usage: vcoc witness")])
def test_dispatch_reaches_each_tool(argv, prog, capsys):
    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert exc.value.code == 0 and capsys.readouterr().out.startswith(prog)


def test_no_action_opens_the_shell(monkeypatch):
    import vcoc.interactive.app as app
    called = []
    monkeypatch.setattr(app, "run_shell", lambda: called.append(True))
    main([])
    assert called


def test_root_shims_are_the_package_modules():
    import cli, verifier, witness
    import vcoc.cli, vcoc.verifier, vcoc.witness
    assert (cli, verifier, witness) == (vcoc.cli, vcoc.verifier, vcoc.witness)


def test_python_cli_py_still_runs():
    out = subprocess.run([sys.executable, str(ROOT / "cli.py"), "--help"], capture_output=True, text=True, cwd=ROOT)
    assert out.returncode == 0 and out.stdout.startswith("usage: vcoc ")


@pytest.mark.parametrize("argv", [["help"], ["--help"], ["-h"]])
def test_help_lists_every_action_and_the_tools(argv, capsys):
    main(argv)
    out = capsys.readouterr().out
    for name in ("init-keys", "add-evidence", "checkpoint", "migrate-merkle", "shell", "verify", "witness"):
        assert f"  {name} " in out
    assert "vcoc man" in out and "vcoc uninstall" in out


@pytest.mark.parametrize("name, head", [("log-event", "usage: vcoc log-event"), ("verify", "usage: vcoc verify"),
                                        ("witness", "usage: vcoc witness")])
def test_help_for_one_action(name, head, capsys):
    main(["help", name])
    assert capsys.readouterr().out.startswith(head)


def test_help_for_unknown_action_exits_2(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["help", "nope"])
    assert exc.value.code == 2 and "vcoc help" in capsys.readouterr().err


def test_man_holds_every_section_and_witness_sub_commands(capsys):
    main(["man"])  # stdout is captured, not a terminal: printed, no pager
    out = capsys.readouterr().out
    for head in ("usage: vcoc init-keys", "usage: vcoc export", "usage: vcoc verify", "usage: vcoc witness cosign"):
        assert head in out


def test_uninstall_uses_uv_or_pipx_for_their_tool_envs_and_pip_otherwise(monkeypatch, tmp_path):
    import vcoc.__main__ as m
    monkeypatch.setattr(m.shutil, "which", lambda name: name.upper())
    monkeypatch.setattr(m.sys, "prefix", str(tmp_path / "uv" / "tools" / "vcoc"))
    assert m._uninstall_command() == ["UV", "tool", "uninstall", "vcoc"]
    monkeypatch.setattr(m.sys, "prefix", str(tmp_path / "pipx" / "venvs" / "vcoc"))
    assert m._uninstall_command() == ["PIPX", "uninstall", "vcoc"]
    monkeypatch.setattr(m.sys, "prefix", str(tmp_path / "venv"))
    assert m._uninstall_command()[1:] == ["-m", "pip", "uninstall", "-y", "vcoc"]


def test_uninstall_asks_first_and_does_nothing_on_no(monkeypatch, capsys):
    import vcoc.__main__ as m
    ran = []
    monkeypatch.setattr("builtins.input", lambda prompt: "n")
    monkeypatch.setattr(m.subprocess, "Popen", lambda *a, **k: ran.append(a))
    monkeypatch.setattr(m.os, "execvp", lambda *a: ran.append(a))
    main(["uninstall"])
    assert not ran and "Nothing removed" in capsys.readouterr().out
