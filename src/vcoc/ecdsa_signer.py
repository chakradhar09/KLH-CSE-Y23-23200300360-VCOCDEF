
from __future__ import annotations

import hashlib
from pathlib import Path

from ecdsa import BadSignatureError, SigningKey, VerifyingKey
from ecdsa.util import sigdecode_string, sigencode_string

CURVE_NAME = "SECP256k1"


def generate_keypair() -> tuple[SigningKey, VerifyingKey]:
    signing_key = SigningKey.generate(curve=__import__("ecdsa").SECP256k1)
    return signing_key, signing_key.verifying_key


# ECDSA hashes the message before signing. python-ecdsa's default for that is SHA-1, which NIST does not allow for signature
# generation, so the hash is named here. Logs signed before this was fixed used the SHA-1 default: they still verify (as
# "sha1") unless allow_legacy=False. verifier.py keeps its own copy of this (it imports nothing from vcoc).
SIGNATURE_SCHEMES = (("sha256", hashlib.sha256), ("sha1", hashlib.sha1))


def sign_message(signing_key: SigningKey, message: bytes) -> str:
    signature = signing_key.sign(message, hashfunc=hashlib.sha256, sigencode=sigencode_string)
    return signature.hex()


def signature_scheme(
    verifying_key: VerifyingKey, message: bytes, signature_hex: str, allow_legacy: bool = True
) -> str | None:
    """The scheme the signature verifies under: 'sha256' (current), 'sha1' (legacy, only if allowed) or None."""
    try:
        signature = bytes.fromhex(signature_hex)
    except ValueError:
        return None
    for name, hashfunc in SIGNATURE_SCHEMES[: 2 if allow_legacy else 1]:
        try:
            if verifying_key.verify(signature, message, hashfunc=hashfunc, sigdecode=sigdecode_string):
                return name
        except (BadSignatureError, ValueError):
            continue
    return None


def verify_signature(verifying_key: VerifyingKey, message: bytes, signature_hex: str, allow_legacy: bool = True) -> bool:
    return signature_scheme(verifying_key, message, signature_hex, allow_legacy) is not None


def save_keypair(signing_key: SigningKey, private_path: str | Path, public_path: str | Path) -> None:
    Path(private_path).write_bytes(signing_key.to_pem())
    Path(public_path).write_bytes(signing_key.verifying_key.to_pem())


def load_signing_key(private_path: str | Path) -> SigningKey:
    return SigningKey.from_pem(Path(private_path).read_bytes())


def load_verifying_key(public_path: str | Path) -> VerifyingKey:
    return VerifyingKey.from_pem(Path(public_path).read_bytes())
