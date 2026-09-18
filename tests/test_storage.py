import sqlite3

import pytest

from vcoc.hash_chain import HashChain
from vcoc.ecdsa_signer import generate_keypair
from vcoc.models import Evidence
from vcoc.storage import EncryptedStore, decrypt, encrypt, generate_key, load_key, save_key


def test_encrypt_decrypt_round_trip():
    key = generate_key()
    plaintext = b"sensitive forensic metadata"
    blob = encrypt(key, plaintext, associated_data=b"aad")
    assert decrypt(key, blob, associated_data=b"aad") == plaintext


def test_decrypt_fails_with_wrong_key():
    key = generate_key()
    other_key = generate_key()
    blob = encrypt(key, b"secret")
    with pytest.raises(Exception):
        decrypt(other_key, blob)


def test_decrypt_fails_on_tampered_ciphertext():
    key = generate_key()
    blob = bytearray(encrypt(key, b"secret payload"))
    blob[-1] ^= 0xFF  # flip a byte in the auth tag
    with pytest.raises(Exception):
        decrypt(key, bytes(blob))


def test_decrypt_fails_with_wrong_associated_data():
    key = generate_key()
    blob = encrypt(key, b"payload", associated_data=b"row-1")
    with pytest.raises(Exception):
        decrypt(key, blob, associated_data=b"row-2")


def test_save_and_load_key_round_trip(tmp_path):
    key = generate_key()
    path = tmp_path / "aes.key"
    save_key(key, path)
    assert load_key(path) == key


def test_load_key_rejects_wrong_size(tmp_path):
    path = tmp_path / "bad.key"
    path.write_bytes(b"too short")
    with pytest.raises(ValueError):
        load_key(path)


def test_store_evidence_round_trip(tmp_path):
    key = generate_key()
    store = EncryptedStore(tmp_path / "coc.db", key)
    evidence = Evidence(
        evidence_id="EV001",
        original_filename="disk.img",
        sha256="a" * 64,
        size_bytes=1024,
        added_at="2026-01-01T00:00:00+00:00",
    )
    store.put_evidence(evidence)
    fetched = store.get_evidence("EV001")
    assert fetched == evidence
    store.close()


def test_store_evidence_plaintext_not_in_raw_db_file(tmp_path):
    key = generate_key()
    db_path = tmp_path / "coc.db"
    store = EncryptedStore(db_path, key)
    store.put_evidence(
        Evidence(
            evidence_id="EV001",
            original_filename="secret_case_name.img",
            sha256="a" * 64,
            size_bytes=1024,
            added_at="2026-01-01T00:00:00+00:00",
        )
    )
    store.close()

    raw = db_path.read_bytes()
    assert b"secret_case_name.img" not in raw


def test_store_events_round_trip(tmp_path):
    key = generate_key()
    signing_key, _ = generate_keypair()
    chain = HashChain()
    chain.add_event(evidence_id="EV001", actor="J. Doe", action="collected", signing_key=signing_key)
    chain.add_event(evidence_id="EV001", actor="A. Smith", action="reviewed", signing_key=signing_key)

    store = EncryptedStore(tmp_path / "coc.db", key)
    for event in chain.entries:
        store.put_event(event)

    fetched = store.list_events()
    assert [e.to_dict() for e in fetched] == [e.to_dict() for e in chain.entries]
    store.close()


def test_get_missing_evidence_raises(tmp_path):
    store = EncryptedStore(tmp_path / "coc.db", generate_key())
    with pytest.raises(KeyError):
        store.get_evidence("does-not-exist")
    store.close()


def test_row_swap_tamper_detected_via_aad(tmp_path):
    """Copying one row's ciphertext blob onto another row's key must fail
    to decrypt, since evidence_id is bound in as AEAD associated data."""
    key = generate_key()
    store = EncryptedStore(tmp_path / "coc.db", key)
    store.put_evidence(
        Evidence("EV001", "a.img", "a" * 64, 10, "2026-01-01T00:00:00+00:00")
    )
    store.put_evidence(
        Evidence("EV002", "b.img", "b" * 64, 20, "2026-01-01T00:00:00+00:00")
    )

    conn = sqlite3.connect(str(tmp_path / "coc.db"))
    blob_ev001 = conn.execute("SELECT blob FROM evidence WHERE evidence_id='EV001'").fetchone()[0]
    conn.execute("UPDATE evidence SET blob = ? WHERE evidence_id='EV002'", (blob_ev001,))
    conn.commit()
    conn.close()

    with pytest.raises(Exception):
        store.get_evidence("EV002")
    store.close()
