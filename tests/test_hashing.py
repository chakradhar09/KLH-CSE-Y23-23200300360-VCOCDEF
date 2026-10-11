import hashlib
import tracemalloc

import pytest

from vcoc.hashing import hash_bytes, hash_file


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


def _big_file(tmp_path, name, size=300_000, seed=0):
    content = bytes((i * 7 + seed) % 251 for i in range(size))
    path = tmp_path / name
    path.write_bytes(content)
    return path, hashlib.sha256(content).hexdigest()


def test_hash_file_reuses_one_read_buffer_across_files(tmp_path):
    from vcoc import hashing

    a, da = _big_file(tmp_path, "a.bin", seed=1)
    b, db = _big_file(tmp_path, "b.bin", seed=2)

    assert hash_file(a) == da
    first = hashing._spare.buf
    assert hash_file(b) == db
    assert hashing._spare.buf is first


def test_hash_file_nested_call_from_on_chunk_does_not_share_the_buffer(tmp_path):
    a, da = _big_file(tmp_path, "a.bin", seed=1)
    b, db = _big_file(tmp_path, "b.bin", seed=2)
    inner = []

    def on_chunk(done):
        if not inner:
            inner.append(hash_file(b, chunk_size=1024 * 1024))

    assert hash_file(a, on_chunk=on_chunk) == da
    assert inner == [db]


def test_hash_file_keeps_the_buffer_when_on_chunk_raises(tmp_path):
    from vcoc import hashing

    a, da = _big_file(tmp_path, "a.bin", seed=1)

    def boom(done):
        raise RuntimeError("stop")

    hash_file(a)
    first = hashing._spare.buf
    with pytest.raises(RuntimeError):
        hash_file(a, on_chunk=boom)
    assert hashing._spare.buf is first
    assert hash_file(a) == da


def test_hash_file_is_correct_with_threads_hashing_at_once(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    files = [_big_file(tmp_path, f"f{i}.bin", seed=i) for i in range(8)]
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda f: hash_file(f[0]), files * 5))
    assert results == [digest for _, digest in files] * 5
