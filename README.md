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

### 1. Clone (or download) the repository

```bash
git clone https://github.com/chakradhar09/KLH-CSE-Y23-23200300360-VCOCDEF.git
cd verifiable-coc
```

Alternatively, download the ZIP from the repository's **Code → Download ZIP** button and extract it.

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

Key dependencies: `ecdsa` (digital signatures), `cryptography` (AES-GCM encryption at rest), `prompt_toolkit` (interactive shell). `hashlib`, `json`, `sqlite3`, and `argparse` are part of the Python standard library and need no separate install.

### 3. Run the interactive shell

```bash
python cli.py shell
```

This is the primary way to use the system — an arrow-key-driven menu that covers every operation (registering evidence, logging custody events, verifying the chain, generating keys, etc.) without needing to type individual CLI flags. On first use it will prompt you to generate a signing keypair and, optionally, set up encrypted storage.

```
┌─ Verifiable Chain-of-Custody — Interactive Shell ───────────────────┐
│   ▸ 1  Add evidence                                                 │
│     2  Check evidence integrity                                     │
│     3  Log custody event                                            │
│     4  Verify chain                                                 │
│     5  Merkle root                                                  │
│     6  Merkle proof                                                 │
│     7  Generate keypair (init-keys)                                 │
│     8  Verification (chain / evidence / merkle)                     │
│     0  Quit                                                         │
├──────────────────────────────────────────────────────────────────── │
│ ↑/↓ navigate   1-8,0 jump   Enter select   Esc/q quit               │
└──────────────────────────────────────────────────────────────────── ┘
```

Evidence-scoped actions (Check evidence, Log custody event, Merkle proof) open a live
search/filter picker instead of a blank text prompt — type a partial evidence ID or
filename to narrow the list.

**Multi-file custody events:** "Log custody event" lets you select more than one
evidence record before confirming (Space toggles a row, Enter confirms the
selection). Selecting two or more records logs a single custody event covering
all of them — one signature, one hash-chain entry — and additionally prompts for
an optional case number, tag, and notes. The equivalent one-shot command repeats
`--evidence-id`:

```bash
python cli.py log-event --evidence-id EV001 --evidence-id EV002 \
  --actor "J. Doe" --action seized --case-number C-001 --tag "disk+memory"
```

Existing single-evidence custody events (one `--evidence-id`, or selecting just
one record in the shell) are unaffected — same format as before.

**Verify chain**: the one-shot command (`python cli.py verify-chain`) lists
every custody entry after the pass/fail summary — index, action, evidence
id(s), actor, both hashes, a truncated signature, and per-entry OK/TAMPER
status. In the shell, menu item 4 opens a dedicated sidebar+detail screen
(one row per custody event, ↑/↓ to navigate, Ctrl-R/F5 to refresh) showing
the same per-entry detail — not a static text dump.

Everything below explains what each menu option / underlying module actually does.

## What the Sections and Functions Do

### Core library (`src/vcoc/`)

- **`hashing.py`** — computes the SHA-256 hash of an evidence file. This is the fingerprint recorded at intake and recomputed on every later check.
- **`merkle.py`** — builds a Merkle tree over all registered evidence hashes and produces/verifies inclusion proofs, so you can prove a specific file was part of the evidence set at a given point without re-hashing everything.
- **`hash_chain.py`** — the custody log itself: an append-only, hash-linked chain of events (collected, transferred, accessed, etc.), where each entry embeds the hash of the previous one so any edit or deletion breaks the chain visibly.
- **`ecdsa_signer.py`** — signs each custody log entry with an ECDSA private key and verifies signatures with the matching public key, so entries can't be forged or altered without invalidating the signature.
- **`storage.py`** — optional encrypted-at-rest storage: an AES-256-GCM-encrypted SQLite database that mirrors the evidence index. Each row's primary key is bound in as authenticated associated data, so ciphertext can't be copied between rows.
- **`models.py`** — shared data structures (evidence records, custody events) used across the library. `CustodyEvent` supports two shapes: legacy single-`evidence_id` entries (unchanged, still hash/verify exactly as before) and newer multi-evidence entries (`evidence_ids` list, plus optional `case_number`/`tag`/`notes`).
- **`visualize.py`** — pure data-shaping (no HTML) that normalizes the custody log and evidence/folder indexes into consistent chain-entry and Merkle-tree structures, shared by `cli.py`'s `verify-chain`/`merkle-root` output and the interactive Verification screen.
- **`interactive/`** — the interactive shell implementation:
  - `menu.py` — renders the arrow-key menu shown above and dispatches to the same command functions the one-shot CLI uses.
  - `forms.py` — guided input prompts (evidence file, actor, action, etc.) with filesystem path autofill.
  - `evidence_search.py` — live search/filter across the evidence index and (if enabled) the encrypted store, tagging results as `[mirrored]`, `[index-only]`, `[store-only]`, or `[DIVERGED]`.
  - `verification_screen.py` — drives the "check evidence integrity" and "verify chain" menu options.
  - `store_bridge.py` — keeps the plaintext evidence index and the optional encrypted SQLite mirror in sync.
  - `config.py` — reads/writes `shell_config.json`, which remembers key-pair paths and storage preferences between sessions.

### Entry points

- **`cli.py`** — the command-line entry point. `python cli.py shell` launches the interactive shell; the same file also exposes one-shot subcommands (`init-keys`, `add-evidence`, `log-event`, `check-evidence`, `verify-chain`, `merkle-root`, `merkle-proof`) that the shell calls under the hood, for scripting/automation use.
- **`verifier.py`** — a standalone verifier, intentionally decoupled from `cli.py`. It re-implements hash and signature recomputation from first principles (no shared code path with `vcoc.hash_chain`), so it can independently confirm whether evidence or its custody history has been altered, without trusting the logging system's own self-reported state.
- **`scripts/tamper_simulation.py`** — an experiment harness that builds a clean chain, applies single-point corruptions (payload, signature, hash-link), and confirms the standalone verifier catches every one.

### Running tests

```bash
pytest
```

154 tests cover hashing, Merkle proof correctness (including nested/folder-batch proofs), hash-chain tamper detection, ECDSA sign/verify, encrypted storage, the tamper-simulation harness, multi-evidence custody events, the provenance HTML export, and the interactive shell (menu, forms, store bridge, config, search, multi-select, key-pair setup).

Full architecture, sequence diagrams, and a worked example session for the interactive shell are in
[`Doc/CLI_Interactive_Shell_Architecture.md`](Doc/CLI_Interactive_Shell_Architecture.md).

## Current Phase Status

**Phase:** PRC-II (Project Review – 2) — **Core implementation complete**

Completed so far:
- PRC-I: problem statement, objectives, 10-source literature survey, research gap identification, project abstract
- Core modules implemented and unit-tested: `hashing.py` (SHA-256), `merkle.py` (tree + inclusion proofs), `hash_chain.py` (append-only, hash-linked, ECDSA-signed custody log), `ecdsa_signer.py`
- `cli.py` (init-keys, add-evidence, log-event, verify-chain, merkle-root, merkle-proof, shell) and a standalone `verifier.py` that independently re-derives every hash/signature check
- Scope extensions: SQLite storage with AES-256-GCM encryption at rest (`storage.py`), a tamper-simulation experiment harness (`scripts/tamper_simulation.py`), and an interactive shell (`vcoc.interactive`) over the same one-shot commands, with a persisted key-pair setup gate and filesystem path autofill
- 80 unit/integration tests, including tamper-detection scenarios for payload, signature, and hash-link corruption, headless shell smoke tests, pure-function store-bridge coverage, and the shell's config/autofill/key-gate coverage

### Repository Layout

```
src/vcoc/             Core library (hashing, merkle, hash_chain, ecdsa_signer, storage, models, visualize)
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
