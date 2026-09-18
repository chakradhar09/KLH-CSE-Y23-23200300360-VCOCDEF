import hashlib

from vcoc.hashing import hash_bytes, hash_file, hash_hex_pair


def test_hash_bytes_matches_stdlib():
    data = b"forensic evidence artifact"
    assert hash_bytes(data) == hashlib.sha256(data).hexdigest()


def test_hash_file_matches_stdlib(tmp_path):
    content = b"a" * (2 * 1024 * 1024) + b"tail bytes"
    path = tmp_path / "evidence.bin"
    path.write_bytes(content)

    assert hash_file(path, chunk_size=4096) == hashlib.sha256(content).hexdigest()


def test_hash_file_detects_single_byte_change(tmp_path):
    path = tmp_path / "evidence.bin"
    path.write_bytes(b"original content")
    original_digest = hash_file(path)

    path.write_bytes(b"Original content")  # single byte flipped
    tampered_digest = hash_file(path)

    assert original_digest != tampered_digest


def test_hash_hex_pair_is_order_sensitive():
    a = hash_bytes(b"a")
    b = hash_bytes(b"b")
    assert hash_hex_pair(a, b) != hash_hex_pair(b, a)
