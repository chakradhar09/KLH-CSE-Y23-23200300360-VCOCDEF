"""Folder-mode add-evidence: recursive registration + folder_index.json."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import cli as cli_module
from vcoc.ecdsa_signer import generate_keypair, save_keypair
from vcoc.hash_chain import HashChain


def _ns(**kwargs) -> argparse.Namespace:
    defaults = dict(
        evidence_index=cli_module.DEFAULT_EVIDENCE_INDEX,
        folder_index=cli_module.DEFAULT_FOLDER_INDEX,
        log=cli_module.DEFAULT_LOG,
        private_key=None,
    )
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def _make_folder(tmp_path: Path) -> Path:
    folder = tmp_path / "evidence_folder"
    (folder / "sub").mkdir(parents=True)
    (folder / "a.txt").write_bytes(b"file-a")
    (folder / "b.txt").write_bytes(b"file-b")
    (folder / "sub" / "c.txt").write_bytes(b"file-c")
    return folder


def test_folder_registers_every_file_with_correct_folder_id(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    folder = _make_folder(tmp_path)
    ns = _ns(file=str(folder), evidence_id="BATCH1")

    cli_module.cmd_add_evidence(ns)

    index = cli_module._load_evidence_index(ns.evidence_index)
    assert len(index) == 3
    for eid, rec in index.items():
        assert eid.startswith("BATCH1/")
        assert rec["folder_id"] == "BATCH1"
    assert set(index.keys()) == {
        "BATCH1/a.txt",
        "BATCH1/b.txt",
        "BATCH1/sub/c.txt",
    }


def test_folder_writes_folder_index_with_root_and_members(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    folder = _make_folder(tmp_path)
    ns = _ns(file=str(folder), evidence_id="BATCH1")

    cli_module.cmd_add_evidence(ns)

    folder_index = json.loads(Path(ns.folder_index).read_text(encoding="utf-8"))
    assert "BATCH1" in folder_index
    assert "root" in folder_index["BATCH1"]
    assert folder_index["BATCH1"]["member_ids"] == [
        "BATCH1/a.txt",
        "BATCH1/b.txt",
        "BATCH1/sub/c.txt",
    ]


def test_folder_reregistration_is_deterministic(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    folder = _make_folder(tmp_path)
    ns1 = _ns(file=str(folder), evidence_id="BATCH1", evidence_index="idx1.json", folder_index="fidx1.json")
    ns2 = _ns(file=str(folder), evidence_id="BATCH1", evidence_index="idx2.json", folder_index="fidx2.json")

    cli_module.cmd_add_evidence(ns1)
    cli_module.cmd_add_evidence(ns2)

    root1 = json.loads(Path("fidx1.json").read_text(encoding="utf-8"))["BATCH1"]["root"]
    root2 = json.loads(Path("fidx2.json").read_text(encoding="utf-8"))["BATCH1"]["root"]
    assert root1 == root2


def test_folder_skips_symlinks(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    folder = _make_folder(tmp_path)
    target = tmp_path / "outside.txt"
    target.write_bytes(b"outside")
    link = folder / "link.txt"
    try:
        link.symlink_to(target)
    except OSError:
        import pytest

        pytest.skip("symlinks not supported on this platform/permission level")

    ns = _ns(file=str(folder), evidence_id="BATCH1")
    cli_module.cmd_add_evidence(ns)

    index = cli_module._load_evidence_index(ns.evidence_index)
    assert "BATCH1/link.txt" not in index
    assert len(index) == 3  # only the 3 real files, symlink skipped


def test_empty_folder_raises_clear_error(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    empty = tmp_path / "empty_folder"
    empty.mkdir()
    ns = _ns(file=str(empty), evidence_id="BATCH1")

    with pytest.raises(SystemExit):
        cli_module.cmd_add_evidence(ns)


def test_folder_batch_logs_custody_event_when_keys_given(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    folder = _make_folder(tmp_path)
    signing_key, verifying_key = generate_keypair()
    save_keypair(signing_key, "private_key.pem", "public_key.pem")

    ns = _ns(file=str(folder), evidence_id="BATCH1", private_key="private_key.pem", log="custody_log.json")
    cli_module.cmd_add_evidence(ns)

    chain = HashChain.load("custody_log.json")
    assert len(chain.entries) == 1
    assert chain.entries[0].evidence_id == "BATCH1"
    assert chain.entries[0].action == "batch-register"
    ok, break_index, reason = chain.verify(verifying_key)
    assert ok, reason


def test_folder_batch_no_event_logged_without_keys(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    folder = _make_folder(tmp_path)
    ns = _ns(file=str(folder), evidence_id="BATCH1")

    cli_module.cmd_add_evidence(ns)  # must not crash

    assert not Path(ns.log).exists()


def test_single_file_add_evidence_unchanged(tmp_path, monkeypatch):
    """Existing single-file behavior must be identical: no folder_id set."""
    monkeypatch.chdir(tmp_path)
    f = tmp_path / "solo.bin"
    f.write_bytes(b"solo-file-contents")
    ns = _ns(file=str(f), evidence_id="EV001")

    cli_module.cmd_add_evidence(ns)

    index = cli_module._load_evidence_index(ns.evidence_index)
    assert index["EV001"]["folder_id"] is None
    assert not Path(ns.folder_index).exists()
