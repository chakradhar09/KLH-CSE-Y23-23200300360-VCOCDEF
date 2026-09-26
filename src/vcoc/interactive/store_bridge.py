
from __future__ import annotations

from pathlib import Path

from vcoc.models import Evidence
from vcoc.storage import EncryptedStore, generate_key, load_key, save_key

DEFAULT_KEY_PATH = "vcoc.key"
DEFAULT_DB_PATH = "evidence_store.db"


def open_or_create_store(
    key_path: str = DEFAULT_KEY_PATH, db_path: str = DEFAULT_DB_PATH
) -> tuple[EncryptedStore | None, str]:
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
    try:
        store.put_evidence(evidence)
        return None
    except Exception as exc:
        return f"mirror failed: {exc}"


def search(index: dict, store: EncryptedStore | None, query: str) -> list[dict]:
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
