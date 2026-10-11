"""ECDSA signatures hash the signed message with SHA-256, not python-ecdsa's SHA-1 default. Logs signed the old way
still verify, are reported as legacy, and can be refused."""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

import pytest
from ecdsa import BadSignatureError
from ecdsa.util import sigdecode_string, sigencode_string

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import verifier
from vcoc.ecdsa_signer import generate_keypair, save_keypair, sign_message, signature_scheme, verify_signature
from vcoc.hash_chain import HashChain
from vcoc.models import CustodyEvent


def _legacy_signature(signing_key, message: bytes) -> str:
    """What sign_message produced before the fix: python-ecdsa's default hash, SHA-1."""
    return signing_key.sign(message, hashfunc=hashlib.sha1, sigencode=sigencode_string).hex()


def _chain(signing_key, legacy: tuple[int, ...] = (), events: int = 4) -> list[dict]:
    """Entries as dicts, with the signatures at the given indices replaced by legacy SHA-1 ones."""
    chain = HashChain()
    for i in range(events):
        chain.add_event(actor="J. Doe", action="reviewed", signing_key=signing_key, evidence_id=f"EV{i}")
    entries = [e.to_dict() for e in chain.entries]
    for i in legacy:
        entries[i]["signature"] = _legacy_signature(signing_key, entries[i]["entry_hash"].encode("utf-8"))
    return entries


def test_new_signatures_are_made_with_sha256_and_not_sha1():
    signing_key, verifying_key = generate_keypair()
    message = b"a" * 64
    signature = bytes.fromhex(sign_message(signing_key, message))

    assert verifying_key.verify(signature, message, hashfunc=hashlib.sha256, sigdecode=sigdecode_string)
    with pytest.raises(BadSignatureError):
        verifying_key.verify(signature, message, hashfunc=hashlib.sha1, sigdecode=sigdecode_string)
    assert signature_scheme(verifying_key, message, signature.hex()) == "sha256"


def test_legacy_sha1_signatures_still_verify_but_are_reported_and_can_be_refused():
    signing_key, verifying_key = generate_keypair()
    message = b"entry hash"
    legacy = _legacy_signature(signing_key, message)

    assert verify_signature(verifying_key, message, legacy)
    assert signature_scheme(verifying_key, message, legacy) == "sha1"
    assert not verify_signature(verifying_key, message, legacy, allow_legacy=False)
    assert signature_scheme(verifying_key, message, legacy, allow_legacy=False) is None


def test_wrong_key_wrong_message_and_garbage_do_not_verify_under_either_scheme():
    signing_key, verifying_key = generate_keypair()
    other_key, other_verifying = generate_keypair()
    message = b"m"
    good, legacy = sign_message(signing_key, message), _legacy_signature(signing_key, message)

    for signature in (good, legacy):
        assert not verify_signature(other_verifying, message, signature)
        assert not verify_signature(verifying_key, b"other", signature)
    assert signature_scheme(verifying_key, message, "not hex") is None
    assert signature_scheme(verifying_key, message, "") is None


def test_the_library_chain_accepts_legacy_signatures():
    signing_key, verifying_key = generate_keypair()
    chain = HashChain([CustodyEvent.from_dict(e) for e in _chain(signing_key, legacy=(1,))])

    assert chain.verify(verifying_key) == (True, None, "chain verified")
    assert all(r.ok for r in chain.verify_each(verifying_key))


def test_the_verifier_accepts_legacy_signatures_by_default_and_names_them():
    signing_key, verifying_key = generate_keypair()
    entries = _chain(signing_key, legacy=(0, 1))

    assert verifier.verify_chain(entries, verifying_key) == (True, None, "chain verified")
    assert all(r.ok for r in verifier.verify_each(entries, verifying_key))
    assert verifier.legacy_signature_indices(entries, verifying_key) == [0, 1]
    assert verifier.signature_scheme(entries[2], verifying_key) == "sha256"


def test_the_verifier_can_refuse_legacy_signatures_and_points_at_the_first_one():
    signing_key, verifying_key = generate_keypair()
    entries = _chain(signing_key, legacy=(2,))

    assert verifier.verify_chain(entries, verifying_key, allow_legacy=False) == (
        False,
        2,
        "signature verification failed",
    )
    assert not all(r.ok for r in verifier.verify_each(entries, verifying_key, allow_legacy=False))
    assert verifier.legacy_signature_indices(_chain(signing_key), verifying_key) == []


def test_the_verifier_command_prints_a_note_for_legacy_signatures_and_refuses_them_on_request(tmp_path):
    import json

    signing_key, _ = generate_keypair()
    save_keypair(signing_key, tmp_path / "priv.pem", tmp_path / "pub.pem")
    log = tmp_path / "log.json"
    log.write_text(json.dumps(_chain(signing_key, legacy=(0, 1))), encoding="utf-8")
    base = [sys.executable, str(REPO_ROOT / "verifier.py"), "--log", str(log), "--public-key", str(tmp_path / "pub.pem")]

    lenient = subprocess.run(base, capture_output=True, text=True)
    strict = subprocess.run([*base, "--reject-legacy-signatures"], capture_output=True, text=True)

    assert lenient.returncode == 0
    assert "NOTE: 2 of 4 entries carry a legacy SHA-1 signature (first: #0)" in lenient.stdout
    assert strict.returncode == 1
    assert "TAMPER DETECTED at entry #0: signature verification failed" in strict.stdout


def test_a_current_log_prints_no_legacy_note(tmp_path):
    import json

    signing_key, _ = generate_keypair()
    save_keypair(signing_key, tmp_path / "priv.pem", tmp_path / "pub.pem")
    log = tmp_path / "log.json"
    log.write_text(json.dumps(_chain(signing_key)), encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "verifier.py"), "--log", str(log), "--public-key", str(tmp_path / "pub.pem")],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "legacy" not in result.stdout
