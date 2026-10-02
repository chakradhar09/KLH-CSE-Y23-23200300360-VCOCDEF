import hashlib
import tracemalloc

import pytest

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


BOUNDARY_SIZES = [0, 1, 65_535, 65_536, 65_537, 1_048_575, 1_048_576, 1_048_577, 5 * 1_048_576 + 3]


@pytest.mark.parametrize("size", BOUNDARY_SIZES)
def test_hash_file_digest_is_exact_at_read_size_boundaries(tmp_path, size):
    content = bytes(range(256)) * (size // 256) + bytes(range(size % 256))
    path = tmp_path / "b.bin"
    path.write_bytes(content)

    assert hash_file(path) == hashlib.sha256(content).hexdigest()


def test_hash_file_tiny_file_does_not_allocate_a_big_buffer(tmp_path):
    path = tmp_path / "tiny.bin"
    path.write_bytes(b"x" * 300)

    tracemalloc.start()
    try:
        hash_file(path)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()

    assert peak < 256 * 1024


def test_hash_file_large_file_memory_stays_near_one_chunk(tmp_path):
    path = tmp_path / "big.bin"
    path.write_bytes(b"\x07" * (8 * 1_048_576))

    tracemalloc.start()
    try:
        hash_file(path)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()

    assert peak < int(1.1 * 1_048_576) + 128 * 1024


@pytest.mark.parametrize("size", BOUNDARY_SIZES)
def test_hash_file_on_chunk_reports_increasing_bytes_ending_at_the_file_size(tmp_path, size):
    content = bytes(range(256)) * (size // 256) + bytes(range(size % 256))
    path = tmp_path / "b.bin"
    path.write_bytes(content)
    dones = []

    assert hash_file(path, on_chunk=dones.append) == hashlib.sha256(content).hexdigest()

    assert dones == sorted(set(dones))  # strictly increasing
    assert (dones[-1] if dones else 0) == size


def test_hash_file_on_chunk_exception_propagates(tmp_path):
    path = tmp_path / "b.bin"
    path.write_bytes(b"x" * 100)

    def stop(done):
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        hash_file(path, on_chunk=stop)
