"""Tests for the approval-binding attack suite (area: attacks).

These validate the matrix's shape and integrity and re-run the executable probes
so the headline findings are reproducible. Targets that are not present (clones /
AUDIT envs missing) degrade to n/a rows rather than failing the suite.
"""
import json
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RESULTS = os.path.join(ROOT, "attacks", "results")
MATRIX_JSON = os.path.join(RESULTS, "matrix.json")

sys.path.insert(0, ROOT)
from attacks.targets import ATTACKS, TARGETS  # noqa: E402
from attacks.common import OUTCOMES  # noqa: E402


def _gen():
    # Regenerating needs the third-party clones under attacks/.targets (see attacks/README.md).
    # Without them, test the committed matrix instead of overwriting it with a partial one.
    if not os.path.isdir(os.path.join(ROOT, "attacks", ".targets")):
        return
    env = dict(os.environ, LC_ALL="C.UTF-8")
    subprocess.run([sys.executable, os.path.join(ROOT, "attacks", "run_all.py")],
                   cwd=ROOT, env=env, check=True, capture_output=True, text=True, timeout=600)


@pytest.fixture(scope="module")
def matrix():
    _gen()
    with open(MATRIX_JSON, encoding="utf-8") as f:
        return json.load(f)


def test_matrix_has_meta_and_rows(matrix):
    assert "meta" in matrix and "rows" in matrix
    assert matrix["meta"]["asu_commit"], "ASU commit must be recorded for reproducibility"
    assert len(matrix["rows"]) >= 12


def test_every_row_is_well_formed(matrix):
    for r in matrix["rows"]:
        assert r["target"] in TARGETS, r["target"]
        assert r["attack_id"] in ATTACKS, r["attack_id"]
        assert r["outcome"] in OUTCOMES, r
        # A row claiming vulnerability or partial must carry evidence or an explanatory note.
        if r["outcome"] in ("vulnerable", "partial"):
            assert r["evidence"] or r["note"], r
        # Fairness: n/a must explain why; never silently blank.
        if r["outcome"] == "n/a":
            assert r["note"], r


def test_full_target_x_attack_coverage(matrix):
    seen = {(r["target"], r["attack_id"]) for r in matrix["rows"]}
    for t in TARGETS:
        for ab in ATTACKS:
            assert (t, ab) in seen, f"missing cell {t} x {ab}"


def test_evidence_paths_exist(matrix):
    for r in matrix["rows"]:
        if r["evidence"]:
            p = os.path.join(ROOT, r["evidence"])
            assert os.path.isfile(p), f"missing evidence {r['evidence']} for {r['target']}/{r['attack_id']}"


def test_executed_claims_only_when_executed(matrix):
    # If a row says executed, it must not be an n/a placeholder.
    for r in matrix["rows"]:
        if r["executed"]:
            assert r["outcome"] != "n/a" or r["note"], r


def test_asu_commit_stamp_matches_git(matrix):
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    meta = matrix["meta"]
    stamp = meta["asu_commit"]
    assert stamp.startswith(head), (stamp, head)
    assert stamp.endswith("-dirty") == bool(meta["tree"]["dirty"])
    assert meta["targets"]["asu"]["commit"] == stamp


def test_every_asu_cell_maps_to_executed_tests(matrix):
    """No ASU cell is 'executed' without named tests that actually ran (no derived claims)."""
    from attacks.probes.asu_probe import AB_TESTS
    asu = {r["attack_id"]: r for r in matrix["rows"] if r["target"] == "asu"}
    assert set(asu) == set(ATTACKS)
    for ab, r in asu.items():
        ids = AB_TESTS[ab]
        assert ids, f"{ab} has no mapped test"
        for nid in ids:
            path = nid.split("::")[0]
            assert os.path.isfile(os.path.join(ROOT, path)), nid
            assert nid in r["repro"], (ab, nid)
        if r["executed"]:
            assert r["outcome"] != "n/a"
        else:
            assert r["outcome"] == "n/a" and "INDETERMINATE" in r["note"], r


def test_derived_and_static_rows_are_not_marked_executed(matrix):
    for r in matrix["rows"]:
        if r["target"] == "frameworks" and r["outcome"] != "n/a":
            assert not r["executed"] and r["note"].startswith("DERIVED"), r
        if r["target"] == "openclaw":
            assert not r["executed"], r


