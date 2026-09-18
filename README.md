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

Key dependencies: `ecdsa` (digital signatures), `cryptography` (AES-GCM encryption at rest). `hashlib`, `json`, `sqlite3`, and `argparse` are part of the Python standard library and need no separate install.

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

### Running tests

```bash
pytest
```

45 tests cover hashing, Merkle proof correctness (including odd-leaf-count trees), hash-chain tamper detection, ECDSA sign/verify, encrypted storage (including AEAD row-binding), and the end-to-end tamper-simulation CLI.

## Current Phase Status

**Phase:** PRC-II (Project Review – 2) — **Core implementation complete**

Completed so far:
- PRC-I: problem statement, objectives, 10-source literature survey, research gap identification, project abstract
- Core modules implemented and unit-tested: `hashing.py` (SHA-256), `merkle.py` (tree + inclusion proofs), `hash_chain.py` (append-only, hash-linked, ECDSA-signed custody log), `ecdsa_signer.py`
- `cli.py` (init-keys, add-evidence, log-event, verify-chain, merkle-root, merkle-proof) and a standalone `verifier.py` that independently re-derives every hash/signature check
- Scope extensions: SQLite storage with AES-256-GCM encryption at rest (`storage.py`), and a tamper-simulation experiment harness (`scripts/tamper_simulation.py`)
- 45 unit/integration tests, including tamper-detection scenarios for payload, signature, and hash-link corruption

### Repository Layout

```
src/vcoc/          Core library (hashing, merkle, hash_chain, ecdsa_signer, storage, models)
cli.py             CLI entry point
verifier.py        Standalone, independently-implemented verifier
scripts/           Experiment harnesses (tamper_simulation.py)
tests/             pytest suite
```

**Next milestone:** Experimental results (performance/scale, tamper-detection results table) and paper draft for PRC-II submission.

## Standards Referenced
- **Python-ecdsa documentation**
- **ISO/IEC 27037:2012** — Guidelines for identification, collection, acquisition, and preservation of digital evidence
- **NIST SP 800-86** — Guide to Integrating Forensic Techniques into Incident Response

## Further Reading

Full annotated literature summaries and the verified reference list are in the companion document **`Research_Summary_and_References.pdf`**.
