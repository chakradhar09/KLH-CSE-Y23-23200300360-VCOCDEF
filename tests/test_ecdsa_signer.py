from vcoc.ecdsa_signer import generate_keypair, sign_message, verify_signature


def test_sign_and_verify_round_trip():
    signing_key, verifying_key = generate_keypair()
    message = b"custody-event-payload"
    signature = sign_message(signing_key, message)
    assert verify_signature(verifying_key, message, signature)


def test_verify_fails_on_tampered_message():
    signing_key, verifying_key = generate_keypair()
    signature = sign_message(signing_key, b"original message")
    assert not verify_signature(verifying_key, b"tampered message", signature)


def test_verify_fails_on_tampered_signature():
    signing_key, verifying_key = generate_keypair()
    message = b"original message"
    signature = sign_message(signing_key, message)
    tampered = ("0" if signature[0] != "0" else "1") + signature[1:]
    assert not verify_signature(verifying_key, message, tampered)


def test_verify_fails_with_wrong_key():
    signing_key, _ = generate_keypair()
    _, other_verifying_key = generate_keypair()
    message = b"original message"
    signature = sign_message(signing_key, message)
    assert not verify_signature(other_verifying_key, message, signature)


def test_save_and_load_keypair_round_trip(tmp_path):
    from vcoc.ecdsa_signer import load_signing_key, load_verifying_key, save_keypair

    signing_key, _ = generate_keypair()
    priv_path = tmp_path / "priv.pem"
    pub_path = tmp_path / "pub.pem"
    save_keypair(signing_key, priv_path, pub_path)

    loaded_signing_key = load_signing_key(priv_path)
    loaded_verifying_key = load_verifying_key(pub_path)

    message = b"round trip"
    signature = sign_message(loaded_signing_key, message)
    assert verify_signature(loaded_verifying_key, message, signature)


def test_private_key_is_owner_only_and_never_overwritten(tmp_path):
    import os
    import stat

    import pytest

    from vcoc.ecdsa_signer import generate_keypair, save_keypair

    priv, pub = tmp_path / "priv.pem", tmp_path / "pub.pem"
    save_keypair(generate_keypair()[0], priv, pub)
    if os.name != "nt":  # Windows has no mode bits for this; the folder's ACL applies
        assert stat.S_IMODE(priv.stat().st_mode) == 0o600
    before = priv.read_bytes()
    with pytest.raises(FileExistsError):
        save_keypair(generate_keypair()[0], priv, pub)
    assert priv.read_bytes() == before


def test_init_keys_refuses_to_replace_an_existing_pair(tmp_path, monkeypatch, capsys):
    import pytest

    import cli

    monkeypatch.chdir(tmp_path)
    cli.main(["init-keys"])
    with pytest.raises(SystemExit) as exc:
        cli.main(["init-keys"])
    assert exc.value.code == 1 and "already exists" in capsys.readouterr().out
