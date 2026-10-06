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

This is the primary way to use the system — an arrow-key-driven menu that covers every operation (registering evidence, logging custody events, verifying the chain, generating keys, etc.) without needing to type individual CLI flags. On first use it will prompt you to generate a signing keypair.

```
┌─────────────| Verifiable Chain-of-Custody — Interactive Shell |──────────────┐
│  ╭─────╮                                                                     │
│  │ ◆━◆ │  VCoC  Verifiable Chain-of-Custody                                  │
│  ╰──▼──╯  for digital evidence files                                         │
│                                                                              │
│ DB vcoc.db  │  214 items  │  chain ● CLEAN · verified 22:40                  │
│──────────────────────────────────────────────────────────────────────────────│
│                                                                              │
│▸ 1  Add evidence                                                             │
│  2  Check evidence integrity                                                 │
│  3  Log custody event                                                        │
│  4  Verify chain                                                             │
│  5  Merkle root                                                              │
│  6  Merkle proof                                                             │
│  7  Generate keypair                                                         │
│  8  Verification (chain / evidence / merkle)                                 │
│  9  Quit                                                                     │
│                                                                              │
│↑/↓ navigate   1-9,0 jump   Enter select   Esc/q quit                         │
└──────────────────────────────────────────────────────────────────────────────┘
```

The line under the logo is the **status header**. It reports the *last known* result of a chain verification on this
machine; it never runs one. The result is saved in `shell_config.json` when Verify chain (or the Verification screen's
Chain tab) finishes, together with how many custody events and evidence items existed at that moment:

| Header | Meaning |
|---|---|
| `● CLEAN · verified 22:40` | Every custody event checked out, and nothing has been added since |
| `◐ STALE · 3 new since 22:40` | Evidence or custody events were added after that verification: verify again |
| `✖ TAMPER · event #4 · 22:40` | The last verification found a broken event (stays until the next verification) |
| `○ not verified yet` | No verification has been run for this database from this shell |

The menu frame turns amber when stale and red on tamper. The header is a convenience, not evidence: the authoritative
checks are Verify chain, the Verification screen and the standalone `verifier.py`. It reads the database through a
read-only connection (it never creates or changes it); measured on a database with 92,879 evidence rows it adds about
2 ms the first time the menu appears in a session and under 0.1 ms afterwards.

Evidence-scoped actions (Check evidence, Log custody event, Merkle proof) open a live
search/filter picker instead of a blank text prompt — type a partial evidence ID or
filename to narrow the list.

#### Look and terminal support

The shell colors verdicts (`OK` green, `TAMPER` bold red), tints the selected row, and shows a shield logo that
collapses on short terminals (three lines from 24 rows, one line from 16, none below). Colors only reinforce the words;
every verdict is also text, so nothing depends on seeing color. The look adapts to the terminal it finds:

| Terminal | What it gets |
|---|---|
| Windows Terminal, VS Code, modern Windows 10/11 consoles, ConEmu, Git Bash | Unicode shapes, truecolor |
| Linux/macOS terminals (`xterm-256color` and similar) | Unicode shapes, 256 colors |
| 16-color terminals | Unicode shapes where the locale allows, basic ANSI colors |
| Linux virtual console (`TERM=linux`) | ASCII shapes, bright ANSI colors (its "bright black" is nearly invisible) |
| Windows older than 10 1809 without a modern terminal | ASCII shapes, basic ANSI colors |
| `NO_COLOR` set, or a terminal without color | Bold and reverse only, no color codes |

Settings (all optional): `VCOC_THEME=dark|light|high-contrast|plain` (default `dark`; use `light` on a light
background), `NO_COLOR=1` (no color), `VCOC_ASCII=1` (force ASCII shapes) or `VCOC_ASCII=0` (force Unicode),
`PROMPT_TOOLKIT_COLOR_DEPTH=DEPTH_4_BIT` (force a color depth). The palettes were checked for readability (at least
4.5:1 for text, 3:1 for lines) against common terminal backgrounds such as Campbell, VS Code, One Dark, Ubuntu and
Solarized; `tests/test_theme_matrix.py` simulates each terminal in the table above.

Some help lines were shortened to fit an 80-column terminal, so they no longer mention every key. These keys also work:
Home and End (first/last row) and F5 (refresh) on the Verification and search screens.

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

**Storage:** all state lives in one SQLite file, `vcoc.db` (custody log, evidence records, folder batches).
To hand a third party something they can verify without trusting this tool, export and run the standalone verifier:

```bash
python cli.py export --out-dir out
python verifier.py --log out/custody_log.json --public-key public_key.pem \
  --evidence-index out/evidence_index.json --folder-index out/folder_index.json
```

`export` also writes `anchor.json` and prints it: the custody-log head hash and the Merkle root. Keep a copy somewhere
outside the database (a ticket, an email, a printout). The store is tamper-evident, not tamper-proof: if someone later
rewrites it or cuts the log short, it no longer matches the copy you kept. To check, add `--anchor anchor.json` (the
copy you kept) to the `verifier.py` command: it fails if the log was cut short or rewritten, and, together with
`--evidence-index`, if the Merkle root changed. A log that only grew since the anchor still passes.

**Many files, spare cores:** folder registration (Add evidence, `python cli.py add-evidence --file <folder>`) and the
shell's Verification > Evidence re-hash choose their worker processes by themselves: with 2,000 or more files they use
half your CPUs, at most 8 (about 20 MiB each); below that, or on a 1-3 CPU machine, they stay single-process. Results are
identical. On a 420,557-file / 19.6 GB folder (warm cache, 32 CPUs) registering took 43 s with 8 workers (it was 240-450 s
single-process), and re-hashing a 419,900-file database took 36 s instead of 203 s (4 workers: 67 s). The loading screens
show the worker count and files per second. Set `VCOC_HASH_JOBS=1` (or `--jobs 1`) to keep a run single-process, or another
number to choose the count; `python verifier.py ... --jobs N` (the standalone verifier) stays single-process unless asked.
Every file is still re-hashed from disk; nothing is cached.

Everything below explains what each menu option / underlying module actually does.

## What the Sections and Functions Do

### Core library (`src/vcoc/`)

- **`hashing.py`** — computes the SHA-256 hash of an evidence file. This is the fingerprint recorded at intake and recomputed on every later check.
- **`merkle.py`** — builds a Merkle tree over all registered evidence hashes and produces/verifies inclusion proofs, so you can prove a specific file was part of the evidence set at a given point without re-hashing everything.
- **`hash_chain.py`** — the custody log itself: an append-only, hash-linked chain of events (collected, transferred, accessed, etc.), where each entry embeds the hash of the previous one so any edit or deletion breaks the chain visibly.
- **`ecdsa_signer.py`** — signs each custody log entry with an ECDSA private key and verifies signatures with the matching public key, so entries can't be forged or altered without invalidating the signature.
- **`db.py`** — the single store: one SQLite file (`vcoc.db`, stdlib `sqlite3`) with `custody_log`, `evidence`, and `folders` tables. Everything is plain columns so the hash chain stays independently verifiable and queryable; `custody_log` is append-only (SQL triggers reject `UPDATE`/`DELETE`). `python cli.py export --out-dir DIR` regenerates `custody_log.json`, `evidence_index.json`, and `folder_index.json` for `verifier.py` or a third-party auditor.
- **`storage.py`** — AES-256-GCM helpers plus an `EncryptedStore` (encrypted SQLite blobs, row key bound as associated data). No longer used by the CLI or shell; kept for the storage-overhead experiment (`scripts/storage_overhead.py`).
- **`models.py`** — shared data structures (evidence records, custody events) used across the library. `CustodyEvent` supports two shapes: legacy single-`evidence_id` entries (unchanged, still hash/verify exactly as before) and newer multi-evidence entries (`evidence_ids` list, plus optional `case_number`/`tag`/`notes`).
- **`visualize.py`** — pure data-shaping (no HTML) that normalizes the custody log and evidence/folder indexes into consistent chain-entry and Merkle-tree structures, shared by `cli.py`'s `verify-chain`/`merkle-root` output and the interactive Verification screen.
- **`interactive/`** — the interactive shell implementation:
  - `menu.py` — renders the arrow-key menu shown above and dispatches to the same command functions the one-shot CLI uses.
  - `forms.py` — guided input prompts (evidence file, actor, action, etc.) with filesystem path autofill.
  - `evidence_search.py` — live search/filter over the evidence table by partial ID or filename.
  - `verification_screen.py` — drives the "check evidence integrity" and "verify chain" menu options.
  - `config.py` — reads/writes `shell_config.json`, which remembers key-pair paths and the last chain-verification result between sessions.
  - `theme.py` — the shell's look: palettes (dark, light, high-contrast, plain), the color rules that turn a screen's text into styled fragments without changing it, the ASCII fallback, the shield logo, the progress bar and marquee. Pure: no files, database or network.
  - `status.py` — the main menu's status header: read-only database counts compared with the last recorded verification.
  - `loading.py` — the full-screen "working" screen with live progress, the block progress bar and Esc-to-cancel.

### Entry points

- **`cli.py`** — the command-line entry point. `python cli.py shell` launches the interactive shell; the same file also exposes one-shot subcommands (`init-keys`, `add-evidence`, `log-event`, `check-evidence`, `verify-chain`, `merkle-root`, `merkle-proof`, `export`) that the shell calls under the hood, for scripting/automation use.
- **`verifier.py`** — a standalone verifier, intentionally decoupled from `cli.py`. It re-implements hash and signature recomputation from first principles (no shared code path with `vcoc.hash_chain`), so it can independently confirm whether evidence or its custody history has been altered, without trusting the logging system's own self-reported state.
- **`scripts/tamper_simulation.py`** — an experiment harness that builds a clean chain, applies single-point corruptions (payload, signature, hash-link), and confirms the standalone verifier catches every one.

### Running tests

```bash
pytest
```

180 tests cover hashing, Merkle proof correctness (including nested/folder-batch proofs), hash-chain tamper detection, ECDSA sign/verify, encrypted storage, the tamper-simulation harness, multi-evidence custody events, the provenance HTML export, and the interactive shell (menu, forms, config, search, multi-select, key-pair setup).

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
src/vcoc/             Core library (hashing, merkle, hash_chain, ecdsa_signer, db, storage, models, visualize)
src/vcoc/interactive/ Interactive shell (menu, forms, live search, verification screens)
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
