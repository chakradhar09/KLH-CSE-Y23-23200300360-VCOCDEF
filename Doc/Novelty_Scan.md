# Novelty scan: Verifiable Chain-of-Custody for Digital Evidence Files

*Generated: 2026-10-08 | Method: targeted prior-art scan (not a systematic, scoping or other formal review) | About 20 sources cited, 9 pages fetched plus a 10-page survey read in full | Confidence: Medium for "no forensic custody system uses witness cosigning", High for "the underlying mechanisms are not new"*

## Executive summary

Nearly every mechanism in the project is established prior art. Hash-linked timestamping dates from 1991, hash-chained forensic audit logs from 1999, Merkle history trees with consistency proofs from 2009, and witness cosigning of transparency-log checkpoints from 2016, with a close match to our threat model in the Sigsum design. What we can defend as new is narrower: **applying the transparency-log and witness toolkit to a single-custodian forensic chain of custody, as a working non-blockchain system, with an evaluation that states what it does not stop.** In the sources I could reach, no forensic chain-of-custody system uses witness cosigning. That is a statement about my search, which used a general web search tool and not IEEE Xplore, ACM DL or Scopus. It is not proof, and the closest work is very recent (two items from the last two weeks). The paper should drop any wording that sounds like a new mechanism and say plainly that it is an application.

## 1. Claim-by-claim assessment

| # | Claim in our paper | Closest prior art | Assessment |
|---|---|---|---|
| 1 | A custody record can get blockchain-grade tamper evidence from hashing, hash-linking, Merkle trees and signatures, with no consensus | [Haber & Stornetta (1991)](https://www.gwern.net/doc/bitcoin/1991-haber.pdf) (hash-linked timestamps); [Schneier & Kelsey (1999)](https://www.schneier.com/academic/archives/1999/05/secure_audit_logs_to.html) (hash-chained audit logs for computer forensics); Crosby & Wallach (2009); [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) | **Not new as an idea.** What is defensible is the *gap in the custody literature*: [the 2024 survey](https://sefcom.asu.edu/publications/CoC-SoK-tps2024.pdf) finds academic work concentrated on blockchain, rates system-oriented tools low on verifiability, and asks for "tailored and optimized systems" with less overhead |
| 2 | A verifier that shares no code with the logger | Software projects describe the same practice ([aevum-verify](https://pypi.org/project/aevum-verify/) and arXiv preprints on agent-evidence bundles; seen in search summaries only, not opened); not found in forensic custody work | **Engineering practice, not a contribution.** Present it as a design principle with a measured cost (duplicated logic), not as novel |
| 3 | A hash chain cannot see tail truncation or a key-holder's rewrite; an exported anchor can | [TYPO3 nr-vault ADR-034 (2026-07-30)](https://docs.typo3.org/p/netresearch/nr-vault/0.15/en-us/Developer/Adr/ADR-034-AuditChainTipAnchor.html) states the limit, the anchor, and that records after the last anchor stay unprotected; vendor pages claim hourly external anchoring ([Genie9](https://genie9.com/products/sentinel/govern/evidence), marketing copy only) | **Known.** The paper's own wording ("closes a gap") is fine, but it is a known limitation that we measure, not discover |
| 4 | **Witness-cosigned checkpoints, with consistency proofs, for a custody log** | Mechanism: [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162), [C2SP tlog-cosignature](https://github.com/C2SP/C2SP/blob/tlog-cosignature/v1.0.0/tlog-cosignature.md), [transparency.dev witness article](https://blog.transparency.dev/can-i-get-a-witness-network), [CoSi (Syta et al., 2016)](https://arxiv.org/abs/1503.08768), [Sigsum](https://git.sigsum.org/log-go/about/?h=v0.2.0). Closest application: an open [design issue for a software audit log (opened 2026-10-01)](https://github.com/samvallad33/vestige/issues/401) | **Mechanism not new. Application to forensic custody: nothing found.** Sigsum's stated threat model (attacker controls the signer key, the log key and a threshold of witnesses) is the one we use. Expect a reviewer to say "this is Sigsum for chain of custody" |
| 5 | File-based, offline witness with trust on first use, plus an evaluation with a limits table | None found | **Small but defensible design point.** The explicit limits (window after the last checkpoint, first-sight trust, quorum theft) are the honest part |
| 6 | Two-hop (nested) Merkle proofs for folders | [ECo-Bag (2024)](https://pure.korea.ac.kr/en/publications/eco-bag-an-elastic-container-based-on-merkle-tree-as-a-universal-/) (Merkle-tree evidence container); an [AFF4 Merkle extension](https://dfrws.org/wp-content/uploads/2020/06/2020_USA_pres-revisiting_the_linear_hash-1.pdf) | **Not novel.** Do not list it as a contribution |
| 7 | RFC 6962 leaf/node prefixes, no odd-node duplication | RFC 6962; [CVE-2012-2459](https://mirror.b10c.me/bitcoin-bitcoin/19598/) | **A correction of our own earlier design, not a result.** Keep it as a short lesson |
| 8 | Process-pool hashing and the benchmark findings (buffer allocation, CPU slowdown) | Standard practice | **A methodological lesson**, not novelty |

## 2. The closest work, and why it matters

- **Sigsum / C2SP / transparency.dev** are the real precedent for claim 4: witnesses that cosign a checkpoint only after verifying a consistency proof, built for logs of signed software checksums. The paper currently cites C2SP and transparency.dev; it should add Sigsum and CoSi and describe our work as an adaptation.
- **The 2024 survey** (Nath, Summers, Baek, Ahn, TPS-ISA) is the best evidence for the gap. I read all ten pages: it does not mention transparency logs, consistency proofs or witnesses, and it recommends lighter, tailored systems.
- **Very recent items** (A2A-CaseVerify, [arXiv:2609.33914](https://arxiv.org/abs/2609.33914), 2026-09-27, offline Merkle-linked case-evidence verifier for agent workflows; the vestige issue above) are not forensic custody, but they show the neighbouring ideas moving fast. Re-run this scan the week you submit.
- **Vendors** (Knogin: signed custody entries, hourly timestamp tokens; Genie9: Merkle anchoring) show that non-blockchain, signed, anchored custody records exist in practice. I could not verify either design from public documentation, so the paper can say they exist but cannot compare against them.

## 3. What this means for the paper

1. **Reword the central claim** from "we built the tamper-evidence part of a blockchain" to: *"for a single custodian, the transparency-log toolkit (hash chain and Merkle tree, consistency proofs, witness cosigning) provides the properties the blockchain custody literature wants, and we evaluate what it does and does not stop."*
2. **Reorder the contributions:** (1) the application and the gap it fills; (2) the evaluation including the four limits; (3) the engineering lessons. Remove the nested folder proof and the independent verifier from the list of contributions.
3. **Add to Related Work:** Haber & Stornetta 1991, Schneier & Kelsey 1999, CoSi 2016, Sigsum, SCITT (the IETF transparency-service drafts), the 2024 survey, ECo-Bag and the AFF4 Merkle extension.
4. **Add a comparison table** of systems against five properties: no blockchain, signed actors, truncation detection, independent witnesses, independent verifier. It makes the gap visible and keeps the claim honest.
5. **Keep the hedge** already in the paper ("we found no prior system; that is a statement about our search").

## 4. Gaps in this scan

- Search tool: general web search only. Not run: IEEE Xplore, ACM DL, Scopus, Google Scholar. Suggested exact queries for those: `"chain of custody" AND ("transparency log" OR "witness cosign*" OR "consistency proof")`, `"digital forensics" AND "signed tree head"`, and the same with `Sigsum`.
- Vendor claims (Knogin, Genie9) are marketing copy; unverified. Haber & Stornetta, Schneier & Kelsey, Crosby & Wallach and the Sigsum threat model were confirmed from search summaries and the publishers' or projects' own pages, not by reading the full papers.
- The survey was read in full, but I did not re-read the ten papers behind our own related-work section.
- No prior art search was done for the evaluation methodology (attack-scenario tables), so I make no claim there.

## Sources

1. [Digital Evidence Chain of Custody: Navigating New Realities (TPS-ISA 2024)](https://sefcom.asu.edu/publications/CoC-SoK-tps2024.pdf) — survey; no transparency-log or witness content; calls for lighter systems.
2. [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) and [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162) — consistency proofs.
3. [C2SP tlog-cosignature](https://github.com/C2SP/C2SP/blob/tlog-cosignature/v1.0.0/tlog-cosignature.md); [transparency.dev](https://blog.transparency.dev/can-i-get-a-witness-network) — witness cosigning.
4. [CoSi, arXiv:1503.08768](https://arxiv.org/abs/1503.08768) — decentralized witness cosigning (Syta et al., 2016).
5. [Sigsum](https://git.sigsum.org/log-go/about/?h=v0.2.0) — witnessed log of signed checksums; same threat model.
6. [Haber & Stornetta (1991)](https://www.gwern.net/doc/bitcoin/1991-haber.pdf); [Schneier & Kelsey (1999)](https://www.schneier.com/academic/archives/1999/05/secure_audit_logs_to.html) — earliest hash-linked and forensic audit logs.
7. [TYPO3 ADR-034](https://docs.typo3.org/p/netresearch/nr-vault/0.15/en-us/Developer/Adr/ADR-034-AuditChainTipAnchor.html) — truncation limit and anchor, practitioner.
8. [ECo-Bag](https://pure.korea.ac.kr/en/publications/eco-bag-an-elastic-container-based-on-merkle-tree-as-a-universal-/); [DFRWS 2020 AFF4 hashing](https://dfrws.org/wp-content/uploads/2020/06/2020_USA_pres-revisiting_the_linear_hash-1.pdf) — Merkle evidence containers.
9. [vestige issue #401](https://github.com/samvallad33/vestige/issues/401); [A2A-CaseVerify](https://arxiv.org/abs/2609.33914) — recent neighbouring work.
10. [Genie9](https://genie9.com/products/sentinel/govern/evidence), [Knogin](https://knogin.com/en/developers/evidence-custody-transfer) — vendor claims (unverified).
11. [Verifiable Observation of Permissioned Ledgers](https://arxiv.org/abs/2012.07339), [B-CoC](https://arxiv.org/pdf/1807.10359), [ForensiBlock](https://arxiv.org/pdf/2308.03927) — related ledger and blockchain custody work.

## Methodology

15 search queries (3 in extended mode), 9 page fetches (two of them survey-PDF fetches that did not parse, so the PDF itself was read), and a full read of the survey's 10 pages. Items known only from search summaries are marked as such. Sub-questions: (1) does witness cosigning or a transparency log appear in forensic custody work; (2) is non-blockchain hash-chained custody already published; (3) do truncation and anchoring appear in the logging literature; (4) are Merkle evidence containers and folder proofs already known; (5) is an independent no-shared-code verifier an established practice. Claims were graded by source type: peer-reviewed and standards, then preprints and design issues, then vendor and practitioner pages.
