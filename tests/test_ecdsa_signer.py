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
