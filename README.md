# Verifiable Chain-of-Custody for Digital Evidence Files

## Team Members

| S. No. | University ID | Name                           |
|--------|---|--------------------------------|
| 1      | 2320030360 | Chilakapati Srijaya Chakradhar |
| 2      | 2320030195 | Gogineni Nikhil Sai            |
| 3      | 2320030438 | Pusunuru Preetham              |

## Supervisor

**Dr. Archana Kalidindi**
- Assistant Professor, Department of Computer Science and Engineering

## Abstract

Digital forensic investigations depend on the integrity of evidence artifacts like disk images, memory dumps, browser caches, and log exports throughout their lifecycle from collection to analysis, yet conventional evidence-handling workflows offer no cryptographic guarantee of that integrity: once a file is stored or passed between analysts, there is no verifiable proof that it remains unaltered, nor an immutable record of who accessed or handled it and when. This project addresses that gap with a Verifiable Chain-of-Custody system built from first principles, in which each evidence file is hashed on intake and recorded as a leaf in a Merkle tree for efficient proof-of-inclusion verification, custody events such as transfer, access, or annotation are logged as ECDSA-signed, hash-linked entries forming an append-only chain without reliance on distributed consensus or public blockchain infrastructure, and an accompanying verifier tool independently recomputes the hash chain and Merkle proofs to confirm whether evidence or its custody history has been altered since collection, offering a lightweight, dependency-minimal approach to strengthening evidentiary trust in digital forensics.

## Setup and Execution Instructions

### Prerequisites

- Python 3.10+
- `pip`

### 1. Clone the repository

```bash
git clone https://github.com/chakradhar09/KLH-CSE-Y23-23200300360-VCOCDEF.git
cd verifiable-coc
```

### 2. Create a virtual environment (recommended)

```bash
python -m venv venv
source venv/bin/activate   # on Windows: venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

Key dependencies: `ecdsa` (digital signatures), `cryptography` (AES-GCM encryption at rest), `prompt_toolkit` (interactive shell, §12). `hashlib`, `json`, `sqlite3`, and `argparse` are part of the Python standard library and need no separate install.

### 4. Generate a signing keypair

```bash
python cli.py init-keys --private-key private_key.pem --public-key public_key.pem
```

### 5. Register a piece of evidence (hashes the file, adds it as a Merkle leaf)

```bash
python cli.py add-evidence --file sample.bin --evidence-id EV001
```

### 6. Log a custody event

```bash
python cli.py log-event --evidence-id EV001 --actor "J. Doe" --action "collected"
```

### 7. Verify the entire chain

```bash
python cli.py verify-chain --log custody_log.json --public-key public_key.pem
```

### 8. Generate and check a Merkle inclusion proof

```bash
python cli.py merkle-root --evidence-index evidence_index.json
python cli.py merkle-proof --evidence-id EV001 --out proof.json
```

### 9. Run the standalone verifier independently

```bash
python verifier.py --log custody_log.json --public-key public_key.pem --merkle-proof proof.json
```

The standalone verifier is intentionally decoupled from the logging CLI — it re-implements hash and signature recomputation from first principles (no shared code path with `cli.py`/`vcoc.hash_chain`), so it does not have to trust the logging system's own self-reported state.

### 10. Encrypted-at-rest storage (SQLite + AES-GCM)

```python
from vcoc.storage import EncryptedStore, generate_key, save_key
key = generate_key()
save_key(key, "aes.key")
store = EncryptedStore("custody.db", key)
```

Every row is stored as an AES-256-GCM ciphertext blob (nonce + tag included); the primary key is bound in as authenticated associated data, so copying one row's ciphertext onto another row fails to decrypt.

### 11. Tamper-simulation experiment

```bash
python scripts/tamper_simulation.py --out tamper_results.json
```

Builds a clean chain, then applies four single-point corruptions (payload field, signature, and hash-link tampering) one at a time and confirms the standalone verifier catches every one at the correct entry.

### 12. Interactive shell

```bash
python cli.py shell
```

An arrow-key-driven menu over the same 7 subcommands above, for investigators
who'd rather navigate a menu than type full commands. It's a thin wrapper —
every action calls the same unmodified `cmd_*` functions as the one-shot CLI,
so results and files written are identical either way.

```
┌─ Verifiable Chain-of-Custody — Interactive Shell ───────────────────┐
│   ▸ 1  Add evidence                                                 │
│     2  Search / browse evidence                                     │
│     3  Check evidence integrity                                     │
│     4  Log custody event                                            │
│     5  Verify chain                                                 │
│     6  Merkle root                                                  │
│     7  Merkle proof                                                 │
│     8  Generate keypair (init-keys)                                 │
│     9  Quit                                                         │
├──────────────────────────────────────────────────────────────────── │
│ ↑/↓ navigate   1-9 jump   Enter select   Esc/q quit                 │
└──────────────────────────────────────────────────────────────────── ┘
```

- `evidence_index.json` stays the single source of truth for every command,
  exactly as in the one-shot CLI.
- The first time you add evidence, the shell offers to create `vcoc.key` +
  `evidence_store.db` — an optional AES-GCM-encrypted SQLite mirror of the
  index (via `storage.EncryptedStore`, §10). Decline and the shell works on
  `evidence_index.json` alone, same as before.
- If you keep the mirror, **Search / browse evidence** and every
  evidence-picker screen filter both sources live as you type, and tag each
  match `[mirrored]`, `[index-only]`, `[store-only]`, or `[DIVERGED]` (same
  ID, different hash — surfaced, never silently resolved).
- `verifier.py` is untouched and has no code path through the shell — its
  independence from the logging system is unaffected.
- **Key-pair setup on first use:** the first time you select **Log custody
  event** or **Verify chain**, the shell checks whether the configured
  private/public key files exist. If not, it prompts for their locations
  (offering to generate a fresh pair at the chosen path via the same
  `init-keys` logic if nothing is found there) and remembers the paths in
  `shell_config.json` for future sessions. If a configured key file is later
  deleted or moved, the shell notices and re-prompts rather than failing
  silently.
- **Path autofill:** every prompt that collects a file or directory path
  (evidence file, key paths, Merkle-proof output) shows matching
  files/folders from the filesystem as you type — `Tab`/`↓` to browse
  matches, `Enter` to select a file or descend into a directory. Typing a
  path with no filesystem match still works; it's submitted as typed.

Full architecture, sequence diagrams, and a worked example session are in
[`Doc/CLI_Interactive_Shell_Architecture.md`](Doc/CLI_Interactive_Shell_Architecture.md).

### Running tests

```bash
pytest
```

80 tests cover hashing, Merkle proof correctness (including odd-leaf-count trees), hash-chain tamper detection, ECDSA sign/verify, encrypted storage (including AEAD row-binding), the end-to-end tamper-simulation CLI, headless smoke tests for the interactive shell, pure-function coverage of the shell's EncryptedStore bridge (key acquisition, dual-write mirror success/failure, cross-store search merge/tag/divergence), the shell config file (round-trip, corrupt-file handling), filesystem path autofill, and the key-pair confirmation gate (missing/cached/deleted-key scenarios).

## Current Phase Status

**Phase:** PRC-II (Project Review – 2) — **Core implementation complete**

Completed so far:
- PRC-I: problem statement, objectives, 10-source literature survey, research gap identification, project abstract
- Core modules implemented and unit-tested: `hashing.py` (SHA-256), `merkle.py` (tree + inclusion proofs), `hash_chain.py` (append-only, hash-linked, ECDSA-signed custody log), `ecdsa_signer.py`
- `cli.py` (init-keys, add-evidence, log-event, verify-chain, merkle-root, merkle-proof, shell) and a standalone `verifier.py` that independently re-derives every hash/signature check
- Scope extensions: SQLite storage with AES-256-GCM encryption at rest (`storage.py`), a tamper-simulation experiment harness (`scripts/tamper_simulation.py`), and an interactive shell (`vcoc.interactive`, §12) over the same one-shot commands, with a persisted key-pair setup gate and filesystem path autofill
- 80 unit/integration tests, including tamper-detection scenarios for payload, signature, and hash-link corruption, headless shell smoke tests, pure-function store-bridge coverage, and the shell's config/autofill/key-gate coverage

### Repository Layout

```
src/vcoc/             Core library (hashing, merkle, hash_chain, ecdsa_signer, storage, models)
src/vcoc/interactive/ Interactive shell (menu, forms, live search, EncryptedStore bridge)
cli.py                CLI entry point (incl. `shell` subcommand)
verifier.py           Standalone, independently-implemented verifier
scripts/              Experiment harnesses (tamper_simulation.py)
tests/                pytest suite
```

**Next milestone:** Experimental results (performance/scale, tamper-detection results table) and paper draft for PRC-II submission.

## Standards Referenced
- **Python-ecdsa documentation**
- **ISO/IEC 27037:2012** — Guidelines for identification, collection, acquisition, and preservation of digital evidence
- **NIST SP 800-86** — Guide to Integrating Forensic Techniques into Incident Response

## Further Reading

Full annotated literature summaries and the verified reference list are in the companion document **`Research_Summary_and_References.pdf`**.
