#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vcoc.hashing import hash_file
from vcoc.merkle import MerkleTree, verify_proof

DEFAULT_SIZES = [10, 100, 1000]
DEFAULT_FILE_SIZE_KB = 64


def generate_synthetic_files(directory: Path, count: int, file_size_kb: int) -> list[Path]:
    paths = []
    for i in range(count):
        path = directory / f"synthetic_evidence_{i:06d}.bin"
        path.write_bytes(os.urandom(file_size_kb * 1024))
        paths.append(path)
    return paths


def run_trial(count: int, file_size_kb: int) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)

        gen_start = time.perf_counter()
        files = generate_synthetic_files(tmp_path, count, file_size_kb)
        gen_time = time.perf_counter() - gen_start

        hash_start = time.perf_counter()
        digests = [hash_file(f) for f in files]
        hash_time = time.perf_counter() - hash_start

        build_start = time.perf_counter()
        tree = MerkleTree(digests)
        build_time = time.perf_counter() - build_start

        proof_index = count // 2
        proof_gen_start = time.perf_counter()
        proof = tree.get_proof(proof_index)
        proof_gen_time = time.perf_counter() - proof_gen_start

        verify_start = time.perf_counter()
        ok = verify_proof(digests[proof_index], proof, tree.root)
        verify_time = time.perf_counter() - verify_start

        return {
            "evidence_count": count,
            "file_size_kb": file_size_kb,
            "synthetic_data_generation_seconds": gen_time,
            "hashing_seconds": hash_time,
            "hashing_seconds_per_file": hash_time / count,
            "merkle_build_seconds": build_time,
            "merkle_proof_generation_seconds": proof_gen_time,
            "merkle_proof_verification_seconds": verify_time,
            "proof_verified": ok,
            "proof_size_steps": len(proof),
        }


_timing_depth = [0]  # > 0 while a timed call is running: nested timed calls are counted but not timed again


@contextlib.contextmanager
def _timed(owner, name: str, acc: dict):
    """Wrap owner.name so every call is counted and the outermost one's wall time is added to acc; restores the original.

    Nested timed calls add to `calls` only: e.g. Path.resolve() calls Path.stat() internally (Python 3.11), and that time
    belongs to resolve, so the phases never add up to more than the wall time.
    """
    original = getattr(owner, name)

    def wrapper(*args, **kwargs):
        outermost = _timing_depth[0] == 0
        _timing_depth[0] += 1
        start = time.perf_counter()
        try:
            return original(*args, **kwargs)
        finally:
            _timing_depth[0] -= 1
            acc["calls"] += 1
            if outermost:
                acc["seconds"] += time.perf_counter() - start

    setattr(owner, name, wrapper)
    try:
        yield
    finally:
        setattr(owner, name, original)


def peak_mib() -> float:
    """Peak resident memory of this process so far, in MiB (it only ever grows: run one trial per process for a clean number)."""
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [
                (n, ctypes.c_size_t)
                for n in ("PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage", "QuotaPagedPoolUsage",
                          "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage")
            ]

        counters = Counters(cb=ctypes.sizeof(Counters))
        kernel32, psapi = ctypes.windll.kernel32, ctypes.windll.psapi
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
        psapi.GetProcessMemoryInfo(kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb)
        return counters.PeakWorkingSetSize / 2**20
    import resource

    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss  # KiB on Linux, bytes on macOS
    return peak / (2**20 if sys.platform == "darwin" else 1024)


def apply_memory_cap(mib: int) -> None:
    """Cap this process's memory so a 32-bit-sized address space can be emulated: allocations past it raise MemoryError.

    Linux: RLIMIT_AS (address space). Windows: a job object with a per-process commit limit.
    """
    limit = mib * 2**20
    if sys.platform != "win32":
        import resource

        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
        return
    import ctypes
    from ctypes import wintypes

    class Basic(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                    ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD)]

    class Extended(ctypes.Structure):
        _fields_ = [("Basic", Basic), ("IoInfo", ctypes.c_uint64 * 6), ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    job = kernel32.CreateJobObjectW(None, None)
    info = Extended()
    info.Basic.LimitFlags = 0x100  # JOB_OBJECT_LIMIT_PROCESS_MEMORY
    info.ProcessMemoryLimit = limit
    ok = kernel32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info))  # ExtendedLimitInformation
    ok = ok and kernel32.AssignProcessToJobObject(job, kernel32.GetCurrentProcess())
    if not ok:
        raise OSError(f"could not apply the {mib} MiB memory cap (error {ctypes.get_last_error()})")


def run_verification(db_path: Path, jobs: int | None = None) -> dict:
    """_run_verification with `jobs` re-hash workers: handed over as VCOC_HASH_JOBS (what a user would set) for the duration
    of the run. None leaves the environment, and so the shell's own default, alone."""
    if jobs is None:
        return _run_verification(db_path)
    saved = os.environ.get("VCOC_HASH_JOBS")
    os.environ["VCOC_HASH_JOBS"] = str(jobs)
    try:
        return {**_run_verification(db_path), "jobs": jobs}
    finally:
        if saved is None:
            os.environ.pop("VCOC_HASH_JOBS", None)
        else:
            os.environ["VCOC_HASH_JOBS"] = saved


def _run_verification(db_path: Path) -> dict:
    """Run the shell's Verification > Evidence check on a COPY of `db_path` and report time, peak memory and redraw cost.

    The original database is only read (copied); the copy lives in a temporary directory.
    """
    import shutil

    from vcoc.interactive import verification_screen as vs

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        copy = str(Path(tmp) / "bench.db")
        shutil.copyfile(db_path, copy)
        start = time.perf_counter()
        rows, details = vs._run_evidence_check(db_path=copy)
        wall = time.perf_counter() - start

        total = len(rows)
        redraws = []
        for selected in (0, total // 2, total - 1, total // 3, total - 2):  # fresh window each time, like PgDn/End
            top = [0]
            t = time.perf_counter()
            vs._sidebar_text(rows, max(selected, 0), top, 30)
            details[max(selected, 0)]
            redraws.append(time.perf_counter() - t)
        return {
            "rows": total,
            "wall_seconds": wall,
            "rows_per_second": total / wall if wall else 0.0,
            "redraw_ms_max": max(redraws) * 1000,
            "peak_mib": peak_mib(),
        }


def print_verification_result(label: str, r: dict) -> None:
    jobs = f", jobs {r['jobs']}" if "jobs" in r else ""
    print(f"{label}: {r['rows']:,} rows, wall {r['wall_seconds']:.2f}s ({r['rows_per_second']:,.0f} rows/s{jobs})")
    print(f"  redraw   {r['redraw_ms_max']:8.1f} ms  (worst of 5 windows: start, middle, end, ...)")
    print(f"  peak     {r['peak_mib']:8.1f} MiB  (process peak so far)")


def run_folder_ingest(folder: Path) -> dict:
    """Register `folder` into a throwaway database with `cli._add_evidence_folder` and report where the time goes.

    Timers wrap hash_file, Path.stat, Path.resolve and the db writes (add_folder_members, finish_folder); "other" is the rest (walking, sorting, bookkeeping).
    Nothing is written outside a temporary directory, and `folder` is only read.
    """
    import cli
    from vcoc import db

    acc = {name: {"seconds": 0.0, "calls": 0} for name in ("hash", "stat", "resolve", "db")}
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        db_path = str(Path(tmp) / "bench.db")
        # A no-op progress hook = the shell's path: no per-file lines are printed (and captured into memory) like the CLI does.
        args = argparse.Namespace(
            file=str(folder), evidence_id="BENCH", db=db_path, private_key=None, actor=None, progress=lambda *a: None
        )
        with contextlib.ExitStack() as stack:
            stack.enter_context(_timed(cli, "hash_file", acc["hash"]))
            stack.enter_context(_timed(Path, "stat", acc["stat"]))
            stack.enter_context(_timed(Path, "resolve", acc["resolve"]))
            stack.enter_context(_timed(db, "add_folder_members", acc["db"]))
            stack.enter_context(_timed(db, "finish_folder", acc["db"]))
            start = time.perf_counter()
            with contextlib.redirect_stdout(io.StringIO()):
                cli._add_evidence_folder(args)
            wall = time.perf_counter() - start
        conn = db.connect(db_path)
        file_count, total_bytes = conn.execute("SELECT COUNT(*), COALESCE(SUM(size_bytes), 0) FROM evidence").fetchone()
        conn.close()

    parts = acc["hash"]["seconds"] + acc["stat"]["seconds"] + acc["resolve"]["seconds"] + acc["db"]["seconds"]
    return {
        "file_count": file_count,
        "total_bytes": total_bytes,
        "wall_seconds": wall,
        "hash_seconds": acc["hash"]["seconds"],
        "stat_seconds": acc["stat"]["seconds"],
        "stat_calls": acc["stat"]["calls"],
        "resolve_seconds": acc["resolve"]["seconds"],
        "resolve_calls": acc["resolve"]["calls"],
        "db_write_seconds": acc["db"]["seconds"],
        "other_seconds": wall - parts,
        "files_per_second": file_count / wall if wall else 0.0,
        "peak_mib": peak_mib(),
    }


def run_folder_ingest_trial(count: int, file_size_kb: int) -> dict:
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        generate_synthetic_files(Path(tmp), count, file_size_kb)
        return {"file_size_kb": file_size_kb, **run_folder_ingest(Path(tmp))}


def print_ingest_result(label: str, r: dict) -> None:
    print(
        f"{label}: {r['file_count']:,} files, {r['total_bytes'] / 2**20:,.1f} MiB, "
        f"wall {r['wall_seconds']:.2f}s ({r['files_per_second']:,.0f} files/s)"
    )
    print(f"  hash     {r['hash_seconds']:8.2f}s")
    print(f"  stat     {r['stat_seconds']:8.2f}s  ({r['stat_calls']:,} calls)")
    print(f"  resolve  {r['resolve_seconds']:8.2f}s  ({r['resolve_calls']:,} calls)")
    print(f"  db write {r['db_write_seconds']:8.2f}s")
    print(f"  other    {r['other_seconds']:8.2f}s  (walk, sort, bookkeeping)")
    print(f"  peak     {r['peak_mib']:8.1f} MiB  (process peak so far; one trial per process for a clean number)")


def _parse_ingest_spec(spec: str) -> tuple[int, int]:
    count, _, kb = spec.lower().partition("x")
    return int(count), int(kb)


def make_chart(results: list[dict], out_path: Path) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    counts = [r["evidence_count"] for r in results]
    hash_times = [r["hashing_seconds"] for r in results]
    build_times = [r["merkle_build_seconds"] for r in results]
    verify_times = [r["merkle_proof_verification_seconds"] for r in results]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.5))

    ax1.plot(counts, hash_times, marker="o", label="Hashing (SHA-256, all files)")
    ax1.plot(counts, build_times, marker="s", label="Merkle tree build")
    ax1.set_xlabel("Number of evidence files")
    ax1.set_ylabel("Time (seconds, log scale)")
    ax1.set_title("Hashing & Merkle Build Time vs. Evidence Count")
    ax1.set_xscale("log")
    ax1.set_yscale("log")
    ax1.legend()
    ax1.grid(True, alpha=0.3, which="both")

    ax2.plot(counts, verify_times, marker="^", color="darkgreen", label="Merkle proof verification")
    ax2.set_xlabel("Number of evidence files")
    ax2.set_ylabel("Time (seconds)")
    ax2.set_title("Merkle Proof Verification Time vs. Evidence Count\n(O(log n) expected)")
    ax2.set_xscale("log")
    ax2.ticklabel_format(axis="y", style="scientific", scilimits=(0, 0))
    ax2.legend()
    ax2.grid(True, alpha=0.3)

    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Performance/scale experiment")
    parser.add_argument("--sizes", type=int, nargs="+", default=DEFAULT_SIZES,
                         help="Evidence-set sizes to test (default: 10 100 1000)")
    parser.add_argument("--file-size-kb", type=int, default=DEFAULT_FILE_SIZE_KB,
                         help="Size of each synthetic evidence file in KB (default: 64)")
    parser.add_argument("--out", default=None, help="Write JSON results to this path")
    parser.add_argument("--chart", default=None, help="Write a PNG chart to this path")
    parser.add_argument(
        "--ingest", nargs="+", metavar="COUNTxKB", default=None,
        help="Benchmark folder ingest (add-evidence --file <folder>) on synthetic trees, e.g. 10000x4 100x5120",
    )
    parser.add_argument(
        "--ingest-folder", default=None, help="Benchmark folder ingest on a real folder (read-only, scratch database)"
    )
    parser.add_argument(
        "--verify-db", default=None, help="Benchmark Verification > Evidence on a copy of this database (read-only on it)"
    )
    parser.add_argument(
        "--jobs", type=int, default=None,
        help="With --verify-db: re-hash with this many worker processes (as VCOC_HASH_JOBS); default is the shell's own",
    )
    parser.add_argument(
        "--cap-mib", type=int, default=None,
        help="Cap this process's memory (emulates a small / 32-bit address space); allocations beyond it fail",
    )
    args = parser.parse_args(argv)
    if args.cap_mib:
        apply_memory_cap(args.cap_mib)

    if args.verify_db:
        print(f"Running the Evidence verification on a copy of {args.verify_db} ...")
        result = run_verification(Path(args.verify_db), jobs=args.jobs)
        print_verification_result(args.verify_db, result)
        if args.out:
            Path(args.out).write_text(json.dumps([{"trial": args.verify_db, **result}], indent=2), encoding="utf-8")
        return

    if args.ingest or args.ingest_folder:
        ingest_results = []
        for spec in args.ingest or []:
            count, kb = _parse_ingest_spec(spec)
            print(f"Running folder-ingest trial: {count:,} files x {kb} KB ...")
            ingest_results.append({"trial": spec, **run_folder_ingest_trial(count, kb)})
            print_ingest_result(spec, ingest_results[-1])
        if args.ingest_folder:
            print(f"Running folder-ingest on {args.ingest_folder} ...")
            ingest_results.append({"trial": args.ingest_folder, **run_folder_ingest(Path(args.ingest_folder))})
            print_ingest_result(args.ingest_folder, ingest_results[-1])
        if args.out:
            Path(args.out).write_text(json.dumps(ingest_results, indent=2), encoding="utf-8")
            print(f"{chr(10)}Wrote results -> {args.out}")
        return

    results = []
    for count in args.sizes:
        print(f"Running trial: {count} evidence files x {args.file_size_kb} KB ...")
        result = run_trial(count, args.file_size_kb)
        results.append(result)
        print(
            f"  hash={result['hashing_seconds']:.4f}s "
            f"build={result['merkle_build_seconds']:.6f}s "
            f"proof_gen={result['merkle_proof_generation_seconds']:.6f}s "
            f"verify={result['merkle_proof_verification_seconds']:.6f}s "
            f"verified={result['proof_verified']}"
        )

    print()
    print(f"{'Files':>8} {'Hash (s)':>10} {'Build (s)':>12} {'ProofGen (s)':>14} {'Verify (s)':>12}")
    for r in results:
        print(
            f"{r['evidence_count']:>8} {r['hashing_seconds']:>10.4f} "
            f"{r['merkle_build_seconds']:>12.6f} {r['merkle_proof_generation_seconds']:>14.6f} "
            f"{r['merkle_proof_verification_seconds']:>12.6f}"
        )

    if args.out:
        Path(args.out).write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"\nWrote results -> {args.out}")

    if args.chart:
        make_chart(results, Path(args.chart))
        print(f"Wrote chart -> {args.chart}")


if __name__ == "__main__":
    main()
