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

> Implementation is in progress per the roadmap below. The steps here reflect intended usage as each module comes online.

### Prerequisites

- Python 3.x
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

Key dependencies: `python-ecdsa` (digital signatures). `hashlib`, `json`, and `argparse` are part of the Python standard library and need no separate install.

### 4. Log a custody event

```bash
python cli.py log-event --evidence-id EV001 --actor "J. Doe" --action "collected"
```

### 5. Verify the entire chain

```bash
python cli.py verify-chain --log custody_log.json
```

### 6. Run the standalone verifier independently

```bash
python verifier.py --log custody_log.json
```

The standalone verifier is intentionally decoupled from the logging CLI — it independently recomputes the hash chain and Merkle proofs from scratch, so it does not have to trust the logging system's own self-reported state.

### Running tests

```bash
pytest
```

## Current Phase Status

**Phase:** PRC-I (Project Review – 1) — **Planning complete**

Completed so far:
- Problem statement, objectives, and 10-source literature survey finalized
- Research gap identified: no surveyed system combines hash chaining, Merkle trees, and ECDSA signing in a standalone, non-blockchain tool purpose-built for forensic evidence custody
- Project abstract formally submitted (A.Y. 2026–2027)
- 6-week, learning-integrated implementation roadmap finalized (see below)

### Roadmap

| Week | Focus              | Build                                                                        |
|---|--------------------|------------------------------------------------------------------------------|
| 1 | Foundations        | Design custody log schema (evidence ID, actor, action, timestamp, prev-hash) |
| 2 | Hash chaining      | Implement `hash_chain.py`                                                    |
| 3 | Merkle trees       | Implement `merkle_tree.py`                                                   |
| 4 | ECDSA signing      | Implement `ecdsa_signer.py`                                                  |
| 5 | CLI integration    | Build `cli.py` (log-event, verify-chain, export-proof)                       |
| 6 | Verifier + testing | Build `verifier.py`; test tampering scenarios; prep PRC-II demo              |

**Next milestone:** PRC-II — working hash-chain and Merkle tree modules, initial ECDSA signing/verification, and preliminary tampering-detection test results.

## Standards Referenced
- **Python-ecdsa documentation**
- **ISO/IEC 27037:2012** — Guidelines for identification, collection, acquisition, and preservation of digital evidence
- **NIST SP 800-86** — Guide to Integrating Forensic Techniques into Incident Response

## Further Reading

Full annotated literature summaries and the verified reference list are in the companion document **`Research_Summary_and_References.pdf`**.
