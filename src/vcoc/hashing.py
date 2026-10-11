
from __future__ import annotations

import hashlib
import os
import threading
from collections import deque
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

DEFAULT_CHUNK_SIZE = 1024 * 1024
_SMALL_READ = 64 * 1024
_spare = threading.local()  # one read buffer kept per thread: a fresh 1 MiB bytearray per file cost ~0.22 ms (5x the hashing)


def _take_buffer(size: int) -> bytearray:
    # Taken out of the slot while in use, so a hash_file called from an on_chunk callback gets its own buffer.
    buf = getattr(_spare, "buf", None)
    _spare.buf = None
    return buf if buf is not None and len(buf) == size else bytearray(size)


def hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_file(
    path: str | Path, chunk_size: int = DEFAULT_CHUNK_SIZE, on_chunk: Callable[[int], None] | None = None
) -> str:
    # One unbuffered small read covers most files without allocating a big buffer;
    # only files larger than that switch to reads into one reused chunk_size buffer.
    # on_chunk(done_bytes) runs after every read, so even one huge file reports progress.
    digest = hashlib.sha256()
    done = 0
    with open(path, "rb", buffering=0) as fh:
        head = fh.read(_SMALL_READ)
        more = len(head) == _SMALL_READ
        if not more:
            probe = fh.read(1)  # confirm EOF: a short read is not guaranteed to be the end
            head, more = head + probe, bool(probe)
        digest.update(head)
        done = len(head)
        if done and on_chunk is not None:
            on_chunk(done)
        if more:
            buf = _take_buffer(chunk_size)
            try:
                view = memoryview(buf)
                while n := fh.readinto(buf):
                    digest.update(view[:n])
                    done += n
                    if on_chunk is not None:
                        on_chunk(done)
            finally:
                _spare.buf = buf
    return digest.hexdigest()


# --- Opt-in parallel hashing (off unless VCOC_HASH_JOBS / --jobs says otherwise) ---------------------------------------
# Measured on 23,218 small files: 8 processes 9.8x, 8 threads only 1.4x; pinned to 2 CPUs processes gave 1.35x and every
# worker costs ~20 MiB, so the default stays 1 (a basic device gains little). Below PARALLEL_MIN_FILES a pool's start-up
# (spawn on Windows) costs more than it saves.
PARALLEL_MIN_FILES = 2000
BATCH_FILES = 500
BATCH_BYTES = 64 * 1024 * 1024
BIG_FILE = 256 * 1024 * 1024  # hashed by the caller instead, so it keeps byte-level progress


def default_jobs() -> int:
    try:
        return max(1, int(os.environ.get("VCOC_HASH_JOBS", "1")))
    except ValueError:
        return 1


def auto_jobs(file_count: int) -> int:
    """Pool size for a folder ingest: an explicit VCOC_HASH_JOBS wins (=1 turns the pool off); otherwise half the CPUs, at most
    8 (~20 MiB per worker), and 1 below PARALLEL_MIN_FILES. The same rule as verifier.auto_jobs (verifier.py imports nothing
    from vcoc, so it keeps its own copy: tests/test_parallel_hashing.py checks that the two agree)."""
    if "VCOC_HASH_JOBS" in os.environ:
        return default_jobs()
    if file_count < PARALLEL_MIN_FILES:
        return 1
    return max(1, min(8, (os.cpu_count() or 1) // 2))


def _hash_batch(paths: list[str]) -> list:
    out: list = []
    for path in paths:
        try:
            out.append(hash_file(path))
        except OSError as exc:
            out.append(exc)
    return out


def _units(entries: Iterable[tuple[str, int | None]]) -> Iterator[list[str] | None]:
    """Batches of paths cut by file count or bytes; None stands for one big file the caller hashes itself."""
    batch: list[str] = []
    nbytes = 0
    for path, size in entries:
        size = size or 0
        if size >= BIG_FILE:
            if batch:
                yield batch
                batch, nbytes = [], 0
            yield None
            continue
        batch.append(path)
        nbytes += size
        if len(batch) >= BATCH_FILES or nbytes >= BATCH_BYTES:
            yield batch
            batch, nbytes = [], 0
    if batch:
        yield batch


def hash_files(entries: Iterable[tuple[str, int | None]], jobs: int) -> Iterator[str | OSError | None]:
    """One result per (path, size) entry, IN INPUT ORDER: a hex digest, the OSError for an unreadable file, or None for a
    big file the caller must hash itself. Only a few batches are in flight at a time. Closing the generator (or an
    exception in the consumer) cancels the queued batches and waits for the running ones."""
    units = _units(entries)
    pool = ProcessPoolExecutor(max_workers=jobs)
    window: deque = deque()
    try:
        while True:
            while len(window) < 2 * jobs and (unit := next(units, False)) is not False:
                window.append(None if unit is None else pool.submit(_hash_batch, unit))
            if not window:
                return
            first = window.popleft()
            if first is None:
                yield None
            else:
                yield from first.result()
    finally:
        pool.shutdown(wait=True, cancel_futures=True)
