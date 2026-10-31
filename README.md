# Verifiable Chain-of-Custody for Digital Evidence Files

[![CI](https://github.com/chakradhar09/KLH-CSE-Y23-23200300360-VCOCDEF/actions/workflows/ci.yml/badge.svg)](https://github.com/chakradhar09/KLH-CSE-Y23-23200300360-VCOCDEF/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/chakradhar09/KLH-CSE-Y23-23200300360-VCOCDEF)](https://github.com/chakradhar09/KLH-CSE-Y23-23200300360-VCOCDEF/releases)

**Current release: v4.0.0.** Witness-cosigned checkpoints, an RFC 6962 Merkle tree with consistency proofs, SHA-256
signatures and process-pool hashing. Databases made by v3.x need `python cli.py migrate-merkle` once (see
[Upgrading an older database](#upgrading-an-older-database)). Release notes are on the
[Releases](https://github.com/chakradhar09/KLH-CSE-Y23-23200300360-VCOCDEF/releases) page.

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

- Python 3.10+ (CI runs 3.11)
- `pip`

### 1. Clone (or download) the repository

```bash
git clone https://github.com/chakradhar09/KLH-CSE-Y23-23200300360-VCOCDEF.git
cd KLH-CSE-Y23-23200300360-VCOCDEF
```

Alternatively, download the ZIP from the repository's **Code → Download ZIP** button and extract it.

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

Key dependencies: `ecdsa` (digital signatures), `prompt_toolkit` (interactive shell), `cryptography` (only for the AES-GCM storage-overhead experiment; the store itself is not encrypted), `matplotlib` (paper figures). `hashlib`, `json`, `sqlite3`, and `argparse` are part of the Python standard library and need no separate install.

### 3. Run the interactive shell

```bash
python cli.py shell
```

This is the primary way to use the system — an arrow-key-driven menu that covers every operation (registering evidence, logging custody events, verifying the chain, generating keys, etc.) without needing to type individual CLI flags. On first use it will prompt you to generate a signing keypair.

```
┌─────────────| Verifiable Chain-of-Custody — Interactive Shell |──────────────┐
│ ▛▀▌▐██                                                                       │
│ ▌ ▌▐██  VCoC  Verifiable Chain-of-Custody                                    │
│ ▝▚▌▐▛▘  for digital evidence files                                           │
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
│  9  Write checkpoint for witnesses                                           │
│  0  Verify against cosigned checkpoint                                       │
│     Quit                                                                     │
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
| `✖ SHORTENED · 2 events gone since 22:40` | The custody log has fewer events than the most ever verified: its newest events were deleted. The rest still verify, so only this comparison can see it. A new database (different first event) does not trigger it; to reset it deliberately, delete `last_verify` from `shell_config.json` |
| `○ not verified yet` | No verification has been run for this database from this shell |

Beside the chain verdict the header shows the **last evidence check** (the Verification screen's Evidence tab, which re-hashes
every file against its recorded sha256). It is saved the same way and is independent of the chain verdict. When both fit
on the line the chain text is shortened first:

| Header | Meaning |
|---|---|
| `files ● ALL GREEN` | Every file matched its recorded hash, is logged in the custody log, and nothing was added since |
| `files ✖ 3 TAMPERED` | 3 files no longer match their recorded hash (stays until the next check); the worst kind is shown |
| `files ◐ 12 NOT LOGGED` / `5 UNVERIFIABLE` | No tampering, but files no custody event names, or files that are missing or have no recorded source path |
| `files ◐ STALE · 4 new` | Evidence or custody events were added after the check (a new event can log a file that was not logged) |
| `files ○ unchecked` | No evidence check has been run for this database from this shell |

Nothing re-verifies by itself: the header only changes when you run Verify chain, open the Verification screen (it checks the
chain first, and again each time you return to its Chain tab) or run its Evidence tab (Ctrl-R re-runs it). The Evidence tab
lists one category at a time: `All / All green / Tampered / Not logged / Unverifiable / Logged`, and `f` steps through them. A heading
row (with a divider under it) names the current category, counts its files and says what it means. *Unverifiable* is a file
the check could not re-hash (the source file is missing, or no source path was recorded), so it can be neither proven
unchanged nor shown tampered.
The menu frame turns amber when either is stale and red when either is tampered. The header is a convenience, not evidence: the authoritative
checks are Verify chain, the Verification screen and the standalone `verifier.py`. It reads the database through a
read-only connection (it never creates or changes it); measured on a database with 92,879 evidence rows it adds about
2 ms the first time the menu appears in a session and under 0.1 ms afterwards.

Evidence-scoped actions (Check evidence, Log custody event, Merkle proof) open a live
search/filter picker instead of a blank text prompt — type a partial evidence ID or
filename to narrow the list.

#### Look and terminal support

The shell colors verdicts (`OK` green, `TAMPER` bold red), tints the selected row, and shows a shield logo that
collapses on short terminals (three lines from 24 rows, one line from 18, none below). Colors only reinforce the words;
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

**Witness-cosigned checkpoints (so the anchor does not depend on the custodian):** a *checkpoint* is a signed commitment to the
custody log (its size and a Merkle root over its entries). One or more independent *witnesses* (a supervisor, opposing counsel)
cosign it, but only after checking that it extends the last checkpoint they signed. A rewrite, a truncation or a fork of what
a witness has already cosigned then cannot be passed off, even by someone who stole the custodian's signing key. Everything moves
as files (email, USB); there is no network.

```bash
# 1. each witness, once: make a key pair; send witness.pub to the custodian and to whoever verifies
python witness.py init-key --key witness.pem --pub witness.pub

# 2. custodian, at intake and at each milestone: write a checkpoint (from the second one on, add a proof from the size the
#    witness last cosigned, shown by `python witness.py show-state --state witness_state.json`)
python cli.py checkpoint --out checkpoint.json
python cli.py checkpoint --out checkpoint.json --since-size 4 --proof-out proof.json

# 3. each witness: cosign (the first time, also give the custodian's public key, which is then trusted and remembered)
python witness.py cosign --checkpoint checkpoint.json --proof proof.json --state witness_state.json \
  --key witness.pem --log-key public_key.pem --out cosigned.json     # the next witness cosigns cosigned.json

# 4. anyone: check the log against the cosigned checkpoint, requiring 2 of the witnesses you trust
python cli.py export --out-dir out
python verifier.py --log out/custody_log.json --public-key public_key.pem --checkpoint cosigned.json \
  --witness-key witness1.pub --witness-key witness2.pub --quorum 2 --evidence-index out/evidence_index.json
```

From the interactive shell, steps 2 and 4 are menu items: **9 Write checkpoint for witnesses** writes the checkpoint (and,
given the size the witnesses last cosigned, the consistency proof) and prints the `witness.py cosign` command to send with
it; **0 Verify against cosigned checkpoint** checks the log against the file the witnesses send back (witness keys and quorum
are remembered). The menu header then shows how much of the log is cosigned, for example
`witness ◐ 212 of 214 entries cosigned · 2 not yet`. Cosigning stays in `witness.py`, on the witness's own machine.

A witness answers `REFUSED: rollback` (the log is smaller than what it signed), `REFUSED: fork` (a different root at a size it
already signed), or `REFUSED: the checkpoint does not extend ...` (the proof does not connect the old state to the new one).
Each leaves its state file and the output untouched, and each is a reason to ask the custodian what happened. The verifier
reports `NOT WITNESSED` when fewer than the quorum of trusted witnesses signed, and `TAMPER DETECTED` when the log no longer
contains what the checkpoint committed to (or, with `--evidence-index`, when the evidence set changed). A checkpoint protects
what it covers: entries added afterwards are unwitnessed until the next one, and a witness trusts a log the first time it sees
it. Measured costs and the attack scenarios are in `scripts/witness_scenarios.py` (`python scripts/witness_scenarios.py`).

Key custody: a witness keeps `witness.pem` (its private key) and its state file to itself, and backs the state file up, because
a witness that loses it has to trust the next log it sees on first sight again. Never email a private key; only `*.pub` files
travel. The custodian's public key must reach each witness by a route other than the checkpoint itself (hand it over at intake),
since a witness trusts it the first time it is given. If a witness's private key may have leaked, stop counting it in the
verifier's `--witness-key` list and have a new witness take over.

#### Upgrading an older database

**Merkle tree rules, schema version 2 (v4.0.0):** the Merkle tree now follows RFC 6962, so the root stored for each registered folder changed. A database made before that is refused by every command that reads or writes a folder root (`merkle-root`, `merkle-proof`, `export`, registering a folder, the Verification screen) with a message telling you to run:

```bash
python cli.py migrate-merkle            # --db FILE for another database
```

It recomputes each folder's root from its members. Before replacing a root it checks the stored one against the members under the old rules; if any folder does not match, nothing is written and the command stops (`--force` converts anyway, but find out why first). The custody log, the signatures and the evidence rows are not touched, so `verify-chain` works before and after. Anchors, exports and Merkle proofs made before the upgrade used the old rules: `verifier.py` says so ("not a tamper finding") instead of comparing them; export and generate them again. Converting a database with two folders of about 416,000 files each took 5.4 s.

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

- **`hashing.py`** — computes the SHA-256 hash of an evidence file. This is the fingerprint recorded at intake and recomputed on every later check. Files are streamed through one reused read buffer, and large batches are hashed in a process pool.
- **`merkle.py`** — builds a Merkle tree over all registered evidence hashes and produces/verifies inclusion proofs, so you can prove a specific file was part of the evidence set at a given point without re-hashing everything. The tree follows RFC 6962 (Certificate Transparency): a leaf is hashed as `SHA-256(0x00 ‖ digest)`, an inner node as `SHA-256(0x01 ‖ left ‖ right)`, and a lone node at the end of a level moves up unchanged. The prefixes stop an inner node being passed off as a leaf, and `[a, b, c]` and `[a, b, c, c]` no longer share a root.
- **`hash_chain.py`** — the custody log itself: an append-only, hash-linked chain of events (collected, transferred, accessed, etc.), where each entry embeds the hash of the previous one so any edit or deletion breaks the chain visibly.
- **`checkpoint.py`** — builds the signed checkpoint of the custody log (its size, an RFC 6962 root over the entries' `entry_hash` values, the chain head, the evidence root and a time) and the consistency proof from an earlier size, for the witnesses.
- **`ecdsa_signer.py`** — signs each custody log entry with an ECDSA private key (the signed message is hashed with SHA-256) and verifies signatures with the matching public key, so entries can't be forged or altered without invalidating the signature. Entries signed by earlier versions used `python-ecdsa`'s default, SHA-1; they still verify, `verifier.py` reports how many there are, and `--reject-legacy-signatures` refuses them.
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
  - `status.py` — the main menu's status header: read-only database counts compared with the last recorded chain verification and evidence check.
  - `loading.py` — the full-screen "working" screen with live progress, the block progress bar and Esc-to-cancel.

### Entry points

- **`cli.py`** — the command-line entry point. `python cli.py shell` launches the interactive shell; the same file also exposes one-shot subcommands (`init-keys`, `add-evidence`, `log-event`, `check-evidence`, `verify-chain`, `merkle-root`, `merkle-proof`, `export`, `checkpoint`, `migrate-merkle`) that the shell calls under the hood, for scripting/automation use.
- **`witness.py`** — a standalone witness for custody-log checkpoints, run by an independent party (`init-key`, `cosign`, `show-state`). It cosigns a checkpoint only if it extends the last one it signed for that log, and imports `verifier.py` for its crypto rather than `vcoc`.
- **`verifier.py`** — a standalone verifier, intentionally decoupled from `cli.py`. It re-implements hash and signature recomputation from first principles (no shared code path with `vcoc.hash_chain`), so it can independently confirm whether evidence or its custody history has been altered, without trusting the logging system's own self-reported state.
- **`scripts/`** — the experiment harnesses behind the paper's tables:
  - `tamper_simulation.py` builds a clean chain, applies single-point corruptions (payload, signature, hash-link), and confirms the standalone verifier catches every one; `tamper_extended.py` adds truncation, deletion, reordering and a stolen-key rewrite, with and without an anchor.
  - `witness_scenarios.py` runs the 12 attacks against `witness.py` and `verifier.py` and measures checkpoint, proof and cosignature costs.
  - `performance_scale.py` and `storage_overhead.py` measure hashing, Merkle and storage costs; `paper_figures.py` redraws the result plots and `build_ieee_docx.py` builds the IEEE `.docx` from `Doc/Research_Paper_v3.md`.

### Running tests

```bash
pytest
```

1,686 tests cover hashing (serial and process-pool), Merkle proof correctness (including nested/folder-batch proofs and RFC 6962 consistency proofs), hash-chain tamper detection, ECDSA sign/verify, the SQLite single store and its append-only guard, the tamper-simulation harness, multi-evidence custody events, the verifier anchor, checkpoints and the witness's refusals and quorum rules, the provenance HTML export, and the interactive shell (menu, forms, config, search, multi-select, key-pair setup, themes and the terminal matrix, loading screens, the status header, the Evidence categories and the screen stage).

On every push and pull request to `main`, [CI](.github/workflows/ci.yml) runs `ruff check --select F` (pyflakes), the test
suite and `pip-audit`. The audit ignores one `ecdsa` advisory (PYSEC-2026-1325, the Minerva timing attack) that has no
upstream fix; it goes away when signing moves to the `cryptography` package.

Full architecture, sequence diagrams, and a worked example session for the interactive shell are in
[`Doc/CLI_Interactive_Shell_Architecture.md`](Doc/CLI_Interactive_Shell_Architecture.md).

## Current Status (v4.0.0)

Completed so far:
- PRC-I: problem statement, objectives, 10-source literature survey, research gap identification, project abstract
- Core system: SHA-256 hashing with a process pool, an RFC 6962 Merkle tree with inclusion, nested (folder) and consistency proofs, an append-only hash-linked custody log signed with ECDSA (secp256k1, SHA-256), one append-only SQLite store, and multi-evidence custody events
- Tamper evidence beyond the chain: an exported anchor, and witness-cosigned checkpoints (`checkpoint`, `witness.py`, quorum checks in `verifier.py`) that catch a truncation or a stolen-key rewrite of anything the witnesses have cosigned
- A standalone `verifier.py` that shares no code with the logger, and an interactive shell over the same commands
- Experiments: 4 basic and 7 extended tamper scenarios, 12 witness attack scenarios (8 stopped, 4 reported as limits), and scaling, storage and re-hash measurements
- Research paper v3 ([`Doc/Research_Paper_v3.md`](Doc/Research_Paper_v3.md), IEEE format in `Doc/Research_Paper_v3_IEEE.docx`, current draft as [`Doc/Research_Paper_Draft.pdf`](Doc/Research_Paper_Draft.pdf)) and a prior-art scan ([`Doc/Novelty_Scan.md`](Doc/Novelty_Scan.md))
- 1,686 passing tests and CI (lint, tests, dependency audit)

### Repository Layout

```
src/vcoc/             Core library (hashing, merkle, checkpoint, hash_chain, ecdsa_signer, db, storage, models, visualize)
src/vcoc/interactive/ Interactive shell (menu, forms, live search, verification and checkpoint screens)
cli.py                CLI entry point (incl. `shell`, `export`, `checkpoint`, `migrate-merkle`)
witness.py            Standalone witness that cosigns checkpoints
verifier.py           Standalone, independently-implemented verifier
scripts/              Experiment harnesses and paper build scripts
tests/                pytest suite
Doc/                  Research paper, novelty scan, design and review documents
.github/workflows/    CI
```

## Standards Referenced
- **Python-ecdsa documentation**
- **ISO/IEC 27037:2012** — Guidelines for identification, collection, acquisition, and preservation of digital evidence
- **NIST SP 800-86** — Guide to Integrating Forensic Techniques into Incident Response

## Further Reading

Full annotated literature summaries and the verified reference list are in the companion document [`Doc/Research_Summary_and_References.pdf`](Doc/Research_Summary_and_References.pdf). The current paper draft is [`Doc/Research_Paper_Draft.pdf`](Doc/Research_Paper_Draft.pdf).
