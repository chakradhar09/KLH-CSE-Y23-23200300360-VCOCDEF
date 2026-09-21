"""EncryptedStore key acquisition, dual-write mirror, and cross-store search.

No prompt_toolkit dependency -- everything here is a plain function, testable
without a terminal.
"""

from __future__ import annotations

from pathlib import Path

from vcoc.models import Evidence
from vcoc.storage import EncryptedStore, generate_key, load_key, save_key

DEFAULT_KEY_PATH = "vcoc.key"
DEFAULT_DB_PATH = "evidence_store.db"


def open_or_create_store(
    key_path: str = DEFAULT_KEY_PATH, db_path: str = DEFAULT_DB_PATH
) -> tuple[EncryptedStore | None, str]:
    """Open the encrypted store, creating a key if none exists yet.

    Returns (store, message). store is None if the caller should be asked
    for confirmation first (see confirm_and_open below) -- this function
    itself never prompts.
    """
    key_existed = Path(key_path).exists()
    if key_existed:
        key = load_key(key_path)
        store = EncryptedStore(db_path, key)
        return store, f"Opened store -> {db_path}"
    key = generate_key()
    save_key(key, key_path)
    store = EncryptedStore(db_path, key)
    return store, f"Wrote key -> {key_path}\nCreated store -> {db_path}"


def mirror_to_store(store: EncryptedStore, evidence: Evidence) -> str | None:
    """Mirror an evidence record into the encrypted store.

    Never raises -- returns an error message string on failure (non-fatal,
    one-directional: the JSON index write already happened and is never
    rolled back), or None on success.
    # ponytail: dual-write can desync if the mirror step fails; add an
    # explicit "reconcile" action later if that happens often in practice --
    # not needed for a single-custodian tool where the operator can just
    # re-run add-evidence.
    """
    try:
        store.put_evidence(evidence)
        return None
    except Exception as exc:  # noqa: BLE001 -- surfaced to the user, not swallowed
        return f"mirror failed: {exc}"


def search(index: dict, store: EncryptedStore | None, query: str) -> list[dict]:
    """Merge evidence_index.json + EncryptedStore records, tag, and filter.

    Each result dict: evidence_id, original_filename, index_sha256 (or None),
    store_sha256 (or None), tag (one of "mirrored", "index-only",
    "store-only", "DIVERGED").
    """
    merged: dict[str, dict] = {}
    for eid, rec in index.items():
        merged[eid] = {
            "evidence_id": eid,
            "original_filename": rec.get("original_filename", ""),
            "index_sha256": rec.get("sha256"),
            "store_sha256": None,
        }
    if store is not None:
        for evidence in store.list_evidence():
            entry = merged.setdefault(
                evidence.evidence_id,
                {
                    "evidence_id": evidence.evidence_id,
                    "original_filename": evidence.original_filename,
                    "index_sha256": None,
                    "store_sha256": None,
                },
            )
            entry["store_sha256"] = evidence.sha256
            if not entry["original_filename"]:
                entry["original_filename"] = evidence.original_filename

    results = []
    for entry in merged.values():
        idx_hash, store_hash = entry["index_sha256"], entry["store_sha256"]
        if idx_hash is not None and store_hash is not None:
            entry["tag"] = "mirrored" if idx_hash == store_hash else "DIVERGED"
        elif idx_hash is not None:
            entry["tag"] = "index-only"
        else:
            entry["tag"] = "store-only"
        results.append(entry)

    if query:
        q = query.lower()
        results = [
            r
            for r in results
            if q in r["evidence_id"].lower() or q in r["original_filename"].lower()
        ]
    results.sort(key=lambda r: r["evidence_id"])
    return results
