"""Shared setup for the witness tests: a custodian with a growing custody log that can write checkpoints and proofs."""

from __future__ import annotations

import json
from pathlib import Path

from vcoc import checkpoint as checkpoint_module
from vcoc.ecdsa_signer import generate_keypair, save_keypair
from vcoc.hash_chain import HashChain


class Lab:
    """One custodian: a signing key, a custody log that grows with add(), and checkpoint/proof files in a directory."""

    def __init__(self, directory: Path, events: int = 0):
        self.dir = directory
        self.signing_key, self.verifying_key = generate_keypair()
        save_keypair(self.signing_key, directory / "custodian.pem", directory / "custodian.pub")
        self.pub = directory / "custodian.pub"
        self.chain = HashChain()
        self.add(events)

    def add(self, count: int = 1) -> None:
        for _ in range(count):
            self.chain.add_event(
                actor="J. Doe", action="reviewed", signing_key=self.signing_key, evidence_id=f"EV{len(self.chain.entries)}"
            )

    @property
    def entries(self) -> list[dict]:
        return [e.to_dict() for e in self.chain.entries]

    @property
    def hashes(self) -> list[str]:
        return [e.entry_hash for e in self.chain.entries]

    def checkpoint(self, name: str = "cp.json", since: int | None = None) -> tuple[Path, Path | None]:
        """Write a checkpoint of the log as it is now (and a consistency proof from size `since`)."""
        path = self.dir / name
        path.write_text(json.dumps(checkpoint_module.build_checkpoint(self.chain, self.signing_key)), encoding="utf-8")
        if since is None:
            return path, None
        proof_path = self.dir / f"{Path(name).stem}_proof.json"
        proof_path.write_text(json.dumps(checkpoint_module.consistency_proof_since(self.hashes, since)), encoding="utf-8")
        return path, proof_path

    def write_log(self, name: str = "log.json", entries: list[dict] | None = None) -> Path:
        path = self.dir / name
        path.write_text(json.dumps(self.entries if entries is None else entries), encoding="utf-8")
        return path
