#!/usr/bin/env python3
"""A witness for custody-log checkpoints: a small standalone tool run by an independent party (a supervisor, counsel).

The custodian sends a checkpoint (`cli.py checkpoint`), and for growth a consistency proof (`--since-size`). The witness
cosigns it only if it extends the last checkpoint this witness cosigned for that log, so it cannot be talked into signing a
rewritten or forked history, even when the custodian's signing key has been stolen. It keeps only (size, root) per log,
never the log itself. State and files are plain JSON; nothing goes over a network.

Like verifier.py it imports nothing from vcoc: the crypto rules are the verifier's, so there is no third copy of them.

    python witness.py init-key --key witness.pem --pub witness.pub
    python witness.py cosign --checkpoint cp.json [--proof proof.json] --state state.json --key witness.pem \\
        [--log-key custodian.pub] --out cosigned.json
    python witness.py show-state --state state.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import verifier  # noqa: E402
from ecdsa import SECP256k1, SigningKey, VerifyingKey  # noqa: E402
from ecdsa.der import UnexpectedDER  # noqa: E402
from ecdsa.util import sigencode_string  # noqa: E402

STATE_VERSION = 1


class Refused(Exception):
    """The witness will not do this (and has changed nothing)."""


def make_cosignature(signing_key: SigningKey, body: dict, witnessed_at: str) -> dict:
    witness_id = verifier.checkpoint_log_id(signing_key.verifying_key)
    message = verifier.cosignature_bytes(body, witness_id, witnessed_at)
    signature = signing_key.sign(message, hashfunc=hashlib.sha256, sigencode=sigencode_string)
    return {"witness_id": witness_id, "witnessed_at": witnessed_at, "signature": signature.hex()}


def _read_json(path: str | Path, what: str):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise Refused(f"cannot read {what} {path}: {exc}") from exc


def _load_key(path: str | Path, kind: type, what: str):
    try:
        return kind.from_pem(Path(path).read_bytes())
    except (OSError, ValueError, UnexpectedDER) as exc:
        raise Refused(f"cannot read {what} {path}: {exc}") from exc


def load_state(path: str | Path) -> dict:
    if not Path(path).exists():
        return {"v": STATE_VERSION, "logs": {}}
    state = _read_json(path, "the state file")
    if not isinstance(state, dict) or state.get("v") != STATE_VERSION or not isinstance(state.get("logs"), dict):
        raise Refused(f"the state file {path} is not a witness state file; not starting over (move it away to start fresh)")
    return state


def save_state(path: str | Path, state: dict) -> None:
    """Write the state atomically: a temp file in the same folder, then a rename. A failure leaves the old file as it was."""
    path = Path(path)
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except OSError as exc:
        if tmp is not None and Path(tmp).exists():
            Path(tmp).unlink()
        raise Refused(f"could not save the witness state to {path} ({exc}); nothing was cosigned") from exc


def check(state: dict, checkpoint, log_key_path: str | None, proof) -> tuple[str, VerifyingKey, bool]:
    """Decide whether to cosign. Returns (log id, the log's public key, whether the state must be updated); raises Refused."""
    body = checkpoint.get("body") if isinstance(checkpoint, dict) else None
    claimed = body.get("log_id") if isinstance(body, dict) else None
    known = state["logs"].get(claimed) if isinstance(claimed, str) else None
    if log_key_path:
        log_key = _load_key(log_key_path, VerifyingKey, "the custodian's public key")
    elif known:
        log_key = VerifyingKey.from_string(bytes.fromhex(known["log_key"]), curve=SECP256k1)
    else:
        raise Refused(
            "this witness has not seen this log before: give the custodian's public key with --log-key "
            "(it is trusted on first use, so get it from the custodian by another route)"
        )
    problem = verifier.checkpoint_signature_problem(checkpoint, log_key)
    if problem:
        raise Refused(problem)

    body = checkpoint["body"]
    log_id, size, root = body["log_id"], body["size"], body["root"]
    last = state["logs"].get(log_id)
    if last is None:
        return log_id, log_key, True
    seen_size, seen_root = last["size"], last["root"]
    if size < seen_size:
        raise Refused(f"rollback: this log is smaller ({size} entries) than the last size cosigned ({seen_size})")
    if size == seen_size:
        if root != seen_root:
            raise Refused(f"fork: a different root at size {size}, which this witness has already cosigned with another root")
        return log_id, log_key, False
    if proof is None:
        raise Refused(
            f"growth from size {seen_size} to {size} needs a consistency proof "
            f"(cli.py checkpoint --since-size {seen_size} --proof-out proof.json), and none was given"
        )
    if not isinstance(proof, dict) or proof.get("from_size") != seen_size or proof.get("to_size") != size or not isinstance(proof.get("proof"), list):
        raise Refused(f"the consistency proof must run from size {seen_size} to size {size}")
    if not verifier.verify_consistency(seen_size, size, seen_root, root, proof["proof"]):
        raise Refused(
            "the checkpoint does not extend the last one this witness cosigned: the consistency proof fails "
            "(the history was rewritten, or the proof is wrong)"
        )
    return log_id, log_key, True


def cmd_init_key(args: argparse.Namespace) -> None:
    for path in (args.key, args.pub):
        if Path(path).exists():
            raise Refused(f"{path} already exists; not overwriting a witness key")
    signing_key = SigningKey.generate(curve=SECP256k1)
    Path(args.key).write_bytes(signing_key.to_pem())
    Path(args.pub).write_bytes(signing_key.verifying_key.to_pem())
    print(f"Witness key pair written: {args.key} (keep secret), {args.pub} (give to whoever verifies)")
    print(f"Witness id: {verifier.checkpoint_log_id(signing_key.verifying_key)}")


def cmd_cosign(args: argparse.Namespace) -> None:
    checkpoint = _read_json(args.checkpoint, "the checkpoint")
    if not isinstance(checkpoint, dict):
        raise Refused(f"{args.checkpoint} is not a checkpoint file")
    proof = _read_json(args.proof, "the consistency proof") if args.proof else None
    state = load_state(args.state)
    log_id, log_key, update = check(state, checkpoint, args.log_key, proof)
    signing_key = _load_key(args.key, SigningKey, "the witness key")

    body = checkpoint["body"]
    cosignature = make_cosignature(signing_key, body, datetime.now(timezone.utc).isoformat())
    if update:  # state first: if it cannot be saved nothing is cosigned
        state["logs"][log_id] = {
            "size": body["size"],
            "root": body["root"],
            "log_key": log_key.to_string().hex(),
            "witnessed_at": cosignature["witnessed_at"],
            "checkpoint": {"body": body, "signature": checkpoint["signature"]},
        }
        save_state(args.state, state)
    earlier = checkpoint.get("cosignatures")
    others = [c for c in earlier if isinstance(c, dict) and c.get("witness_id") != cosignature["witness_id"]] if isinstance(earlier, list) else []
    cosigned = {"body": body, "signature": checkpoint["signature"], "cosignatures": [*others, cosignature]}
    try:
        Path(args.out).write_text(json.dumps(cosigned, indent=2), encoding="utf-8")
    except OSError as exc:
        raise Refused(f"cosigned, but could not write {args.out}: {exc}; run the same command again") from exc
    print(f"Cosigned log {log_id[:16]}... at size {body['size']} (root {body['root']}) -> {args.out}")
    print(f"  {len(cosigned['cosignatures'])} cosignature(s) in the file; this witness: {cosignature['witness_id']}")


def cmd_show_state(args: argparse.Namespace) -> None:
    state = load_state(args.state)
    if not state["logs"]:
        print(f"This witness has not cosigned anything yet (no logs recorded in {args.state}).")
        return
    for log_id, entry in sorted(state["logs"].items()):
        print(log_id)
        print(f"  size {entry['size']}, root {entry['root']}")
        print(f"  last cosigned {entry['witnessed_at']}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="witness.py", description="Witness for custody-log checkpoints")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init-key", help="Generate this witness's key pair (refuses to overwrite)")
    p.add_argument("--key", required=True, help="Where to write the private key (PEM)")
    p.add_argument("--pub", required=True, help="Where to write the public key (PEM)")
    p.set_defaults(func=cmd_init_key)

    p = sub.add_parser("cosign", help="Cosign a checkpoint if it extends the last one this witness cosigned")
    p.add_argument("--checkpoint", required=True, help="checkpoint.json from the custodian (may already carry other cosignatures)")
    p.add_argument("--proof", default=None, help="Consistency proof from the last cosigned size (needed when the log has grown)")
    p.add_argument("--state", required=True, help="This witness's state file (created on first use)")
    p.add_argument("--key", required=True, help="This witness's private key (PEM)")
    p.add_argument("--log-key", default=None, help="The custodian's public key (PEM): required the first time a log is seen")
    p.add_argument("--out", required=True, help="Where to write the cosigned checkpoint (may be the input file)")
    p.set_defaults(func=cmd_cosign)

    p = sub.add_parser("show-state", help="Show the last checkpoint this witness cosigned for each log")
    p.add_argument("--state", required=True)
    p.set_defaults(func=cmd_show_state)
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except Refused as exc:
        print(f"REFUSED: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
