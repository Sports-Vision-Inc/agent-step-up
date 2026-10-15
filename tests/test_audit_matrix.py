"""Tests for the AUDIT harness outputs.

These run in the main environment (stdlib + pytest only). They validate the shape
and integrity of the generated matrix and that the probe scripts exist. The heavy
per-runtime probes run in isolated venvs via `python audit/run_all.py`; a subset is
re-executed here only when those venvs are present (so CI without them still passes).
"""
import json
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
AUDIT = os.path.join(ROOT, "audit")
RESULTS = os.path.join(AUDIT, "results")

VALID_OUTCOMES = {"pass", "fail", "partial", "na", "not_run"}
TESTS = {
    "T1_P1_agent_independence",
    "T2_P2_effect_binding",
    "T3_P3_single_use",
    "T4_P4_trusted_rendering",
    "T5_P5_non_repudiation",
    "T6_P7_flood_resistance",
}
EXECUTED_RUNTIMES = {
    "openai-agents", "langgraph", "google-adk", "agno", "pydantic-ai",
    "crewai", "autogen-agentchat", "smolagents", "mcp", "openclaw",
}


def load_matrix():
    path = os.path.join(RESULTS, "matrix.json")
    if not os.path.exists(path):
        pytest.skip("matrix.json not generated yet; run `python audit/run_all.py`")
    with open(path) as f:
        return json.load(f)


def test_matrix_exists_and_is_list():
    rows = load_matrix()
    assert isinstance(rows, list)
    assert len(rows) >= 6 * 4, "expected at least 4 runtimes x 6 tests"


def test_rows_have_required_keys_and_valid_outcomes():
    rows = load_matrix()
    for r in rows:
        for k in ("runtime", "version", "test", "outcome", "evidence", "explanation"):
            assert k in r, f"row missing {k}: {r}"
        assert r["outcome"] in VALID_OUTCOMES, f"bad outcome {r['outcome']} in {r}"
        assert r["explanation"].strip(), f"empty explanation in {r}"


def test_each_executed_runtime_has_all_six_tests():
    rows = load_matrix()
    by_rt = {}
    for r in rows:
        by_rt.setdefault(r["runtime"], set()).add(r["test"])
    present = [rt for rt in EXECUTED_RUNTIMES if rt in by_rt]
    assert len(present) >= 4, f"fewer than 4 executed runtimes present: {present}"
    for rt in present:
        # a crashed probe collapses to a single ALL row; that is acceptable but flagged
        if "ALL" in by_rt[rt]:
            continue
        assert TESTS.issubset(by_rt[rt]), f"{rt} missing tests: {TESTS - by_rt[rt]}"


def test_non_na_outcomes_reference_evidence_files_that_exist():
    rows = load_matrix()
    checked = 0
    for r in rows:
        ev = r.get("evidence") or ""
        if not ev or r["outcome"] in ("not_run", "na"):
            continue
        if ev.endswith(".log"):
            path = os.path.join(AUDIT, ev)
            assert os.path.exists(path), f"evidence missing for {r['runtime']}/{r['test']}: {ev}"
            assert os.path.getsize(path) > 0, f"empty evidence: {ev}"
            checked += 1
    assert checked > 0, "no evidence files were checked"


def test_proprietary_clis_are_marked_not_run():
    rows = load_matrix()
    clis = {r["runtime"]: r for r in rows if r["runtime"] in {"claude-code", "codex-cli", "cursor"}}
    assert set(clis) == {"claude-code", "codex-cli", "cursor"}
    for rt, r in clis.items():
        assert r["outcome"] == "not_run"
        assert os.path.exists(os.path.join(AUDIT, "local_probes", f"{rt}.md"))


def test_all_probe_scripts_exist():
    for sub in ("openai_agents", "langgraph", "google_adk", "agno", "pydantic_ai",
                "crewai", "autogen", "smolagents", "mcp", "openclaw"):
        assert os.path.exists(os.path.join(AUDIT, "probes", sub, "probe.py")), sub


def test_known_signature_results_are_stable():
    """Guard the headline, reproducible findings (corrected per docs/critique/audit.md) so a
    regression is caught. These reflect the uniform criteria: P1 FAIL by construction (dagger);
    P2 via the capability ladder; P3 uniform (rollback) criterion; openclaw capped at PART-s."""
    rows = load_matrix()
    idx = {(r["runtime"], r["test"]): r["outcome"] for r in rows}
    marker = {(r["runtime"], r["test"]): r.get("marker") for r in rows}
    expect = {
        # P1 fails for every in-process SDK HITL, BY CONSTRUCTION (marker=dagger).
        ("openai-agents", "T1_P1_agent_independence"): "fail",
        ("langgraph", "T1_P1_agent_independence"): "fail",
        # P2 effect-binding: openai-agents resists the documented resume API (L2) -> PASS.
        ("openai-agents", "T2_P2_effect_binding"): "pass",
        # langgraph/agno/pydantic-ai substitute at L2 -> FAIL (same capability).
        ("langgraph", "T2_P2_effect_binding"): "fail",
        ("agno", "T2_P2_effect_binding"): "fail",
        ("pydantic-ai", "T2_P2_effect_binding"): "fail",
        # google-adk is bound against the resumer but not a session-store writer -> PART.
        ("google-adk", "T2_P2_effect_binding"): "partial",
        # P3 single use: rollback double-executes across the SDKs -> PART(STATE), uniformly.
        ("pydantic-ai", "T3_P3_single_use"): "partial",
        ("openai-agents", "T3_P3_single_use"): "partial",
        ("langgraph", "T3_P3_single_use"): "partial",
        ("google-adk", "T3_P3_single_use"): "partial",
        ("agno", "T3_P3_single_use"): "partial",
        # MCP server-held args: shown == executed -> PASS (not FAIL).
        ("mcp", "T2_P2_effect_binding"): "pass",
        # openclaw cells are static reviews, capped below PASS.
        ("openclaw", "T4_P4_trusted_rendering"): "partial",
        ("openclaw", "T2_P2_effect_binding"): "partial",
        # new documented-gate rows.
        ("autogen-agentchat (CodeExecutorAgent.approval_func)", "T2_P2_effect_binding"): "pass",
        ("autogen-agentchat (CodeExecutorAgent.approval_func)", "T3_P3_single_use"): "pass",
        ("crewai (before_tool_call gate)", "T3_P3_single_use"): "pass",
    }
    for key, want in expect.items():
        if key in idx:  # only assert when that probe ran
            assert idx[key] == want, f"{key} expected {want}, got {idx[key]}"
    # P1 FAILs must be marked by-construction (dagger), not reported as measured results.
    for rt in ("openai-agents", "langgraph", "google-adk", "agno", "pydantic-ai", "mcp"):
        key = (rt, "T1_P1_agent_independence")
        if key in idx and idx[key] == "fail":
            assert marker.get(key) == "dagger", f"{rt} P1 FAIL must carry marker=dagger"
    # no openclaw cell is reported as PASS (static review cannot establish a property holds).
    for (rt, test), oc in idx.items():
        if rt == "openclaw":
            assert oc != "pass", f"openclaw {test} is PASS but is a static review"


def test_p1_rows_carry_measurable_columns():
    """AUD-1: every P1 row exposes the measurable sub-fields (out-of-process resume; ships
    separate-principal approver), so P1 is not merely the definitional FAIL."""
    rows = load_matrix()
    checked = 0
    for r in rows:
        if r["test"] != "T1_P1_agent_independence" or r["outcome"] == "not_run":
            continue
        if r["outcome"] == "na":
            continue
        p1 = r.get("p1")
        assert p1, f"{r['runtime']} P1 row missing measurable p1 columns"
        assert p1.get("oop_resume") in ("Y", "N", "n/a"), r["runtime"]
        assert p1.get("separate_principal_approver") in ("no", "non-default", "default", "n/a"), r["runtime"]
        checked += 1
    assert checked >= 6


def test_p2_rows_report_a_uniform_capability_ladder():
    """AUD-2: every effect-bound P2 row (pass/partial/fail) reports an L1/L2/L3 ladder."""
    rows = load_matrix()
    checked = 0
    for r in rows:
        if r["test"] != "T2_P2_effect_binding" or r["outcome"] in ("na", "not_run"):
            continue
        if r.get("marker") == "static":  # static reviews are capped and not laddered
            continue
        lv = r.get("levels")
        assert lv and all(k in lv for k in ("L1", "L2", "L3")), \
            f"{r['runtime']} P2 row missing L1/L2/L3 ladder"
        checked += 1
    assert checked >= 5


# ------- optional live re-execution when an isolated venv is available -------

def _env_python(env):
    p = os.path.join(AUDIT, ".envs", env, "bin", "python")
    return p if os.path.exists(p) else None


@pytest.mark.parametrize("env,script", [
    ("openai_agents", "openai_agents"),
    ("langgraph", "langgraph"),
    ("pydantic_ai", "pydantic_ai"),
])
def test_probe_reexecutes_cleanly_if_env_present(env, script):
    py = _env_python(env)
    if not py:
        pytest.skip(f"isolated env {env} not present")
    probe = os.path.join(AUDIT, "probes", script, "probe.py")
    p = subprocess.run([py, probe], capture_output=True, text=True, timeout=600)
    assert p.stdout.strip(), f"{script} produced no stdout: {p.stderr[-500:]}"
    rows = json.loads(p.stdout)
    assert {r["test"] for r in rows} == TESTS
    assert all(r["outcome"] in VALID_OUTCOMES for r in rows)
