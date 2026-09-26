
from __future__ import annotations

from pathlib import Path

from ecdsa import BadSignatureError, SigningKey, VerifyingKey
from ecdsa.util import sigdecode_string, sigencode_string

CURVE_NAME = "SECP256k1"


def generate_keypair() -> tuple[SigningKey, VerifyingKey]:
    signing_key = SigningKey.generate(curve=__import__("ecdsa").SECP256k1)
    return signing_key, signing_key.verifying_key


def sign_message(signing_key: SigningKey, message: bytes) -> str:
    signature = signing_key.sign(message, sigencode=sigencode_string)
    return signature.hex()


def verify_signature(verifying_key: VerifyingKey, message: bytes, signature_hex: str) -> bool:
    try:
        return verifying_key.verify(
            bytes.fromhex(signature_hex),
            message,
            sigdecode=sigdecode_string,
        )
    except (BadSignatureError, ValueError):
        return False


def save_keypair(signing_key: SigningKey, private_path: str | Path, public_path: str | Path) -> None:
    Path(private_path).write_bytes(signing_key.to_pem())
    Path(public_path).write_bytes(signing_key.verifying_key.to_pem())


def load_signing_key(private_path: str | Path) -> SigningKey:
    return SigningKey.from_pem(Path(private_path).read_bytes())


def load_verifying_key(public_path: str | Path) -> VerifyingKey:
    return VerifyingKey.from_pem(Path(public_path).read_bytes())
