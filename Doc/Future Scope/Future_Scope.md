# Future Scope
### Verifiable Chain-of-Custody for Digital Evidence Files — PRC-II Planning

**Team 21** | Chilakapati Srijaya Chakradhar, Gogineni Nikhil Sai, Pusunuru Preetham
**Supervisor:** Dr. Archana Kalidindi, Assistant Professor, CSE

---

## Purpose

The following are proposed as **future scope** — directions the project can be extended into beyond the current build, ahead of PRC-II — without diluting the core thesis: **distributed consensus is not required for single-custodian forensic integrity.** They are grouped so that a small, learning-integrated subset can be selected for the next phase rather than attempted all at once.

---

## 1. Cryptographic Enhancements

| Extension | What it adds | Fit with thesis |
|---|---|---|
| **RFC 3161 trusted timestamping** | Periodically anchor the Merkle root with a Time Stamp Authority (TSA) for externally-verifiable "existed at time T" proof | **Strongest fit** — reinforces the thesis directly: external anchoring without needing blockchain/consensus infrastructure |
| **Multi-signature / threshold signing** | Require 2-of-3 custodians (e.g., investigator + lab supervisor + evidence officer) to co-sign a custody transfer | Strengthens single-custodian-lab realism without adding consensus |
| **HSM/TPM-backed key storage** | Store ECDSA private keys in a hardware security module or software TPM emulator instead of flat files | Good comparative-analysis / future-work section |
| **Post-quantum signature option** | Add a comparison of ECDSA vs. a PQC scheme (e.g., Dilithium) | Forward-looking analysis; doesn't require full implementation |

## 2. Storage / Backend

- **SQLite backend** — replace flat-file JSON custody logs with a proper schema for evidence items, custody events, and signatures. Still single-machine, still no distributed infrastructure — consistent with the "Option A: custom chain, no Web3" architecture.
- **Encrypted-at-rest metadata** — AES-GCM encryption for sensitive case details.

## 3. Interface Layer

- **REST API wrapper (FastAPI)** — exposes the hash-chain/Merkle engine so it's reusable by a future web dashboard.
- **Web dashboard** — visualizes the custody chain and Merkle tree integrity status (green/red indicators). Strong demo material for PRC-II.
- **RBAC (role-based access control)** — separate roles for investigator, lab admin, and auditor.

## 4. Forensic-Domain-Specific Modules

- **Multi-evidence-type support** — disk images (E01/dd), memory dumps, pcap network captures, mobile extractions, each with type-specific metadata extraction.
- **NSRL hash-set cross-referencing** — compare file hashes against NIST's known-file database to flag/exclude standard OS files during analysis.
- **Automated custody report generator** — auto-produce a court-ready PDF/DOCX chain-of-custody report from the log.
- **QR-code evidence tagging** — link physical evidence bags to their digital custody record via QR code.

## 5. Compliance / Audit

- Formal mapping table showing how each system component satisfies specific clauses of **ISO/IEC 27037:2012** and **NIST SP 800-86** — strengthens the feasibility/innovation case.
- Tamper-evidence audit trail exportable in a legally admissible format.

## 6. Testing / Validation

- **Tamper-simulation test suite** — programmatically corrupt a record and demonstrate the hash chain/Merkle tree catching it. Strong, concrete demo material for PRC-II.
- **CI pipeline** (GitHub Actions) — runs the tamper-simulation and other tests automatically.

## 7. Optional Hybrid Extension (frame carefully)

- **External anchoring via OpenTimestamps or a public blockchain** — periodically publish just the Merkle root externally for tamper-proofing beyond the lab's trust boundary. Worth presenting as an *optional, non-required* enhancement — it reinforces rather than contradicts the core argument, since consensus infrastructure is only needed for external anchoring, not for the custody system itself to function.

---

## Suggested Next Step

Select **2–3 extensions** that best fit a learning-integrated 6-week timeline (balancing new-technology learning curve against build time), then translate the selection into an updated project plan and PRC-II slide outline.

**Candidates that pair especially well together:**
- RFC 3161 timestamping + tamper-simulation test suite (small footprint, directly reinforces the thesis, strong demo value)
- SQLite backend + REST API wrapper + minimal web dashboard (visual, demoable, moderate build effort)
- ISO/IEC 27037 & NIST SP 800-86 compliance mapping (low build effort, strengthens the academic/report side)
