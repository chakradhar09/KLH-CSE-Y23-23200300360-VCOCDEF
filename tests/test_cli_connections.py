"""Task 7: every one-shot CLI command closes the SQLite connections it opens,
and check-evidence reads one row instead of the whole evidence index."""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import cli as cli_module
from vcoc import db


class _Tracked(sqlite3.Connection):
    opened: list = []

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.closed = False
        _Tracked.opened.append(self)

    def close(self):
        self.closed = True
        super().close()


@pytest.fixture
def tracked(monkeypatch):
    _Tracked.opened = []
    real = sqlite3.connect
    monkeypatch.setattr(sqlite3, "connect", lambda *a, **k: real(*a, factory=_Tracked, **k))
    return _Tracked.opened


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    f = tmp_path / "a.bin"
    f.write_bytes(b"alpha")
    folder = tmp_path / "case"
    folder.mkdir()
    (folder / "x.txt").write_bytes(b"x")
    (folder / "y.txt").write_bytes(b"y")
    cli_module.main(["init-keys"])
    return tmp_path, f, folder


def _assert_all_closed(opened):
    assert opened, "command opened no connection: the test is not exercising anything"
    assert all(c.closed for c in opened), f"{sum(not c.closed for c in opened)} connection(s) left open"


def _run(tracked, argv):
    tracked.clear()
    try:
        cli_module.main(argv)
    except SystemExit:
        pass
    _assert_all_closed(tracked)


def test_every_command_closes_its_connections(env, tracked, capsys):
    tmp, f, folder = env
    _run(tracked, ["add-evidence", "--file", str(f), "--evidence-id", "EV1"])
    _run(tracked, ["add-evidence", "--file", str(folder), "--evidence-id", "B1"])
    _run(tracked, ["add-evidence", "--file", str(folder), "--evidence-id", "B2", "--private-key", "private_key.pem"])
    _run(tracked, ["log-event", "--evidence-id", "EV1", "--actor", "me", "--action", "seen"])
    _run(tracked, ["check-evidence", "--evidence-id", "EV1"])
    _run(tracked, ["verify-chain"])
    _run(tracked, ["merkle-root"])
    _run(tracked, ["merkle-proof", "--evidence-id", "EV1"])
    _run(tracked, ["export", "--out-dir", str(tmp / "out")])
    assert "TAMPER" not in capsys.readouterr().out


def test_load_index_helpers_close_their_connection(env, tracked):
    cli_module.main(["add-evidence", "--file", str(env[1]), "--evidence-id", "EV1"])
    tracked.clear()
    cli_module._load_evidence_index(cli_module.DEFAULT_DB)
    cli_module._load_folder_index(cli_module.DEFAULT_DB)
    _assert_all_closed(tracked)


def test_check_evidence_reads_one_row_not_the_index(env, monkeypatch, capsys):
    cli_module.main(["add-evidence", "--file", str(env[1]), "--evidence-id", "EV1"])

    def boom(*a, **k):
        raise AssertionError("check-evidence must use db.get_evidence, not load the whole index")

    monkeypatch.setattr(db, "load_evidence_index", boom)
    cli_module.main(["check-evidence", "--evidence-id", "EV1"])
    assert "OK" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        cli_module.main(["check-evidence", "--evidence-id", "NOPE"])
    assert "Unknown evidence id" in capsys.readouterr().out
