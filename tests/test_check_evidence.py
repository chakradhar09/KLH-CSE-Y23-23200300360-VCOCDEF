"""cmd_check_evidence: uses the recorded source_path by default, and reports
a missing recorded file gracefully instead of crashing with FileNotFoundError."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import cli as cli_module


def _ns(**kwargs) -> argparse.Namespace:
    defaults = dict(
        file=None,
        evidence_id="EV001",
        evidence_index=cli_module.DEFAULT_EVIDENCE_INDEX,
    )
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def _register(tmp_path: Path, content: bytes = b"original content") -> Path:
    f = tmp_path / "evidence.bin"
    f.write_bytes(content)
    cli_module.cmd_add_evidence(
        argparse.Namespace(
            file=str(f),
            evidence_id="EV001",
            evidence_index=cli_module.DEFAULT_EVIDENCE_INDEX,
            folder_index=cli_module.DEFAULT_FOLDER_INDEX,
            log=cli_module.DEFAULT_LOG,
            private_key=None,
            actor=None,
        )
    )
    return f


def test_check_evidence_uses_recorded_source_path_by_default(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _register(tmp_path)

    cli_module.cmd_check_evidence(_ns())
    out = capsys.readouterr().out
    assert "OK" in out
    assert "matches recorded sha256" in out


def test_check_evidence_detects_tamper_via_recorded_source_path(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    f = _register(tmp_path)
    f.write_bytes(b"tampered content")

    with pytest.raises(SystemExit):
        cli_module.cmd_check_evidence(_ns())
    out = capsys.readouterr().out
    assert "TAMPER DETECTED" in out


def test_check_evidence_reports_missing_recorded_file_gracefully(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    f = _register(tmp_path)
    f.unlink()

    with pytest.raises(SystemExit):
        cli_module.cmd_check_evidence(_ns())
    out = capsys.readouterr().out
    assert "MISSING" in out
    assert "recorded path" in out
    assert str(f) in out


def test_check_evidence_explicit_file_override_still_works(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    _register(tmp_path)
    relocated = tmp_path / "relocated_copy.bin"
    relocated.write_bytes(b"original content")

    cli_module.cmd_check_evidence(_ns(file=str(relocated)))
    out = capsys.readouterr().out
    assert "OK" in out


def test_check_evidence_unknown_id_still_errors(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit):
        cli_module.cmd_check_evidence(_ns(evidence_id="NOPE"))
    out = capsys.readouterr().out
    assert "Unknown evidence id" in out
