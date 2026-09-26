import copy

import pytest

from vcoc.ecdsa_signer import generate_keypair
from vcoc.hash_chain import GENESIS_HASH, HashChain


def build_chain(signing_key, n=4):
    chain = HashChain()
    for i in range(n):
        chain.add_event(evidence_id=f"EV{i:03d}", actor="J. Doe", action="reviewed", signing_key=signing_key)
    return chain


def test_first_entry_links_to_genesis():
    signing_key, _ = generate_keypair()
    chain = HashChain()
    entry = chain.add_event(evidence_id="EV000", actor="J. Doe", action="collected", signing_key=signing_key)
    assert entry.prev_hash == GENESIS_HASH


def test_entries_link_sequentially():
    signing_key, _ = generate_keypair()
    chain = build_chain(signing_key)
    for i in range(1, len(chain.entries)):
        assert chain.entries[i].prev_hash == chain.entries[i - 1].entry_hash


def test_clean_chain_verifies():
    signing_key, verifying_key = generate_keypair()
    chain = build_chain(signing_key)
    ok, break_index, _ = chain.verify(verifying_key)
    assert ok
    assert break_index is None


def test_tampered_payload_is_detected():
    signing_key, verifying_key = generate_keypair()
    chain = build_chain(signing_key)
    chain.entries[2].actor = "Mallory"  # entry_hash/signature now stale

    ok, break_index, reason = chain.verify(verifying_key)
    assert not ok
    assert break_index == 2
    assert "entry_hash" in reason


def test_tampered_prev_hash_is_detected():
    signing_key, verifying_key = generate_keypair()
    chain = build_chain(signing_key)
    chain.entries[3].prev_hash = "f" * 64

    ok, break_index, reason = chain.verify(verifying_key)
    assert not ok
    assert break_index == 3
    assert "prev_hash" in reason


def test_tampered_signature_is_detected():
    signing_key, verifying_key = generate_keypair()
    chain = build_chain(signing_key)
    sig = chain.entries[1].signature
    chain.entries[1].signature = ("0" if sig[0] != "0" else "1") + sig[1:]

    ok, break_index, reason = chain.verify(verifying_key)
    assert not ok
    assert break_index == 1
    assert "signature" in reason


def test_save_and_load_round_trip(tmp_path):
    signing_key, verifying_key = generate_keypair()
    chain = build_chain(signing_key)
    path = tmp_path / "log.json"
    chain.save(path)

    loaded = HashChain.load(path)
    ok, _, _ = loaded.verify(verifying_key)
    assert ok
    assert [e.to_dict() for e in loaded.entries] == [e.to_dict() for e in chain.entries]


def test_wrong_verifying_key_fails_all_signatures():
    signing_key, _ = generate_keypair()
    _, wrong_verifying_key = generate_keypair()
    chain = build_chain(signing_key)

    ok, break_index, reason = chain.verify(wrong_verifying_key)
    assert not ok
    assert break_index == 0
    assert "signature" in reason


def test_deepcopy_independent_chains_do_not_alias():
    signing_key, _ = generate_keypair()
    chain = build_chain(signing_key)
    clone = copy.deepcopy(chain)
    clone.entries[0].actor = "changed"
    assert chain.entries[0].actor != "changed"


def test_add_event_multi_evidence_ids_appends_one_entry():
    signing_key, verifying_key = generate_keypair()
    chain = HashChain()
    entry = chain.add_event(
        evidence_ids=["EV001", "EV002"],
        actor="J. Doe",
        action="seized",
        signing_key=signing_key,
    )
    assert len(chain.entries) == 1
    assert entry.evidence_ids == ["EV001", "EV002"]
    ok, break_index, _ = chain.verify(verifying_key)
    assert ok
    assert break_index is None


def test_add_event_requires_exactly_one_of_evidence_id_or_evidence_ids():
    signing_key, _ = generate_keypair()
    chain = HashChain()
    with pytest.raises(ValueError):
        chain.add_event(actor="J. Doe", action="seized", signing_key=signing_key)


def test_add_event_rejects_both_evidence_id_and_evidence_ids():
    signing_key, _ = generate_keypair()
    chain = HashChain()
    with pytest.raises(ValueError):
        chain.add_event(
            evidence_id="EV001",
            evidence_ids=["EV001", "EV002"],
            actor="J. Doe",
            action="seized",
            signing_key=signing_key,
        )


def test_mixed_shape_chain_verifies_end_to_end():
    signing_key, verifying_key = generate_keypair()
    chain = HashChain()
    chain.add_event(evidence_id="EV001", actor="J. Doe", action="collected", signing_key=signing_key)
    chain.add_event(
        evidence_ids=["EV002", "EV003"], actor="J. Doe", action="seized", signing_key=signing_key
    )
    chain.add_event(evidence_id="EV004", actor="A. Smith", action="reviewed", signing_key=signing_key)

    ok, break_index, _ = chain.verify(verifying_key)
    assert ok
    assert break_index is None


def test_verify_each_clean_chain_all_entries_ok():
    """Task 26: verify_each() reports per-entry status, additive to verify()'s
    existing (ok, break_index, reason) contract."""
    signing_key, verifying_key = generate_keypair()
    chain = build_chain(signing_key)

    results = chain.verify_each(verifying_key)
    assert len(results) == len(chain.entries)
    assert all(r.ok for r in results)
    for i, r in enumerate(results):
        assert r.index == i


def test_verify_each_tampered_entry_marks_only_that_entry_and_downstream():
    """A tampered entry_hash breaks that entry (bad payload) and every
    entry after it (their prev_hash no longer matches what actually chains
    from the tampered entry's real recomputed hash) -- entries strictly
    before the tamper point must still report ok."""
    signing_key, verifying_key = generate_keypair()
    chain = build_chain(signing_key, n=5)
    chain.entries[2].actor = "Mallory"

    results = chain.verify_each(verifying_key)
    assert results[0].ok
    assert results[1].ok
    assert not results[2].ok
    assert not results[3].ok
    assert not results[4].ok


def test_verify_each_result_has_reason_for_broken_entries():
    signing_key, verifying_key = generate_keypair()
    chain = build_chain(signing_key, n=3)
    chain.entries[1].actor = "Mallory"

    results = chain.verify_each(verifying_key)
    assert results[1].reason
    assert "entry_hash" in results[1].reason


def test_verify_each_matches_verify_break_index_on_first_broken_entry():
    signing_key, verifying_key = generate_keypair()
    chain = build_chain(signing_key, n=4)
    chain.entries[2].actor = "Mallory"

    ok, break_index, _ = chain.verify(verifying_key)
    results = chain.verify_each(verifying_key)
    first_broken = next(i for i, r in enumerate(results) if not r.ok)
    assert first_broken == break_index
