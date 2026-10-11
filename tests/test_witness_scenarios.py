"""scripts/witness_scenarios.py runs attacks against the real witness and verifier code and measures the cost. The expected
outcome of every scenario is pinned here, so the table in the paper cannot drift from the code. Scenarios the design does
not stop are part of the table on purpose: they are its stated limits."""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import witness_scenarios as ws

# name -> (stopped, stopped by)
EXPECTED = {
    "honest_log": (False, None),
    "stolen_key_rewrite": (True, "verifier"),
    "truncate_below_checkpoint": (True, "verifier"),
    "delete_entries_after_checkpoint": (False, None),
    "rewrite_entries_after_checkpoint": (False, None),
    "fork_shown_to_witness": (True, "witness"),
    "rollback_shown_to_witness": (True, "witness"),
    "rewrite_then_grow": (True, "witness"),
    "forged_cosignatures": (True, "verifier"),
    "one_witness_of_two_required": (True, "verifier"),
    "evidence_removed_from_index": (True, "verifier"),
    "witness_keys_also_stolen": (False, None),
    "rewrite_before_first_witnessing": (False, None),
}


@pytest.fixture(scope="module")
def rows():
    return ws.run_scenarios()


def test_every_scenario_ends_as_pinned(rows):
    assert {r["name"]: (r["stopped"], r["stopped_by"]) for r in rows} == EXPECTED


def test_scenarios_run_in_the_documented_order_without_duplicates(rows):
    assert [r["name"] for r in rows] == list(EXPECTED)


def test_every_row_says_what_the_attacker_did_and_what_happened(rows):
    for row in rows:
        assert set(row) >= {"name", "attack", "stopped", "stopped_by", "detail", "limit"}, row["name"]
        assert len(row["attack"]) > 20 and len(row["detail"]) > 10, row["name"]


def test_what_the_design_does_not_stop_is_flagged_as_a_limit(rows):
    limits = {r["name"] for r in rows if r["limit"]}

    assert limits == {name for name, (stopped, _) in EXPECTED.items() if not stopped and name != "honest_log"}


def test_the_honest_control_passes_the_whole_verification(rows):
    control = next(r for r in rows if r["name"] == "honest_log")

    assert control["stopped"] is False and "OK" in control["detail"]


def test_a_witness_that_refuses_leaves_the_conflict_visible(rows):
    late = next(r for r in rows if r["name"] == "rewrite_before_first_witnessing")

    assert "fork" in late["detail"]  # the forged history was cosigned, but the honest custodian is then refused


@pytest.mark.parametrize("n", [100, 1000])
def test_metrics_report_every_cost_and_stay_logarithmic(n):
    m = ws.measure(n)

    assert m["entries"] == n
    assert 300 <= m["checkpoint_bytes"] <= 1500
    assert m["cosigned_bytes_two_witnesses"] > m["checkpoint_bytes"]
    assert 1 <= m["proof_steps"] <= 2 * math.ceil(math.log2(n))
    assert m["proof_bytes"] > 0
    for key in ("tree_build_ms", "proof_generation_us", "proof_verification_us", "verifier_rebuild_ms", "cosign_first_sight_ms", "cosign_growth_ms"):
        assert m[key] > 0, key


def test_the_script_writes_a_json_report(tmp_path, capsys):
    out = tmp_path / "report.json"

    ws.main(["--out", str(out), "--sizes", "100", "500"])

    report = json.loads(out.read_text(encoding="utf-8"))
    assert [r["name"] for r in report["scenarios"]] == list(EXPECTED)
    assert [m["entries"] for m in report["metrics"]] == [100, 500]
    printed = capsys.readouterr().out
    assert "stolen_key_rewrite" in printed and "NOT stopped" in printed
