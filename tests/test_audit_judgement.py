"""Audit polish checks (independent-checker findings on the previous audit revision).

1. Every probe row whose outcome is a hard-coded literal is a JUDGEMENT ('J'): it must
   pass judgement="<rationale>" to row(); the generated matrix marks it, excludes it from
   the measured counts, and carries the rationale.
2. google-adk P2 L2 is measured by actually sending mismatched confirmations through the
   real InMemoryRunner (per-variant results recorded in the row).
3. google-adk P3 applies the same rollback criterion as the other SDKs.
4. The matrix shows agno version dependence (sweep table for P2/P3).

Stdlib + pytest only. Live re-execution happens only when the isolated venv exists.
"""
import ast
import glob
import json
import os
import re
import subprocess

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
AUDIT = os.path.join(ROOT, "audit")
PROBES = os.path.join(AUDIT, "probes")
RESULTS = os.path.join(AUDIT, "results")


def _probe_files():
    files = sorted(glob.glob(os.path.join(PROBES, "*", "probe.py")))
    assert files, "no probe scripts found"
    return files


def _row_calls(path):
    tree = ast.parse(open(path).read())
    for n in ast.walk(tree):
        if (isinstance(n, ast.Call) and getattr(n.func, "id", None) == "row"
                and len(n.args) >= 4):
            yield n


def test_every_literal_outcome_is_declared_a_judgement():
    missing = []
    for p in _probe_files():
        for call in _row_calls(p):
            out = call.args[3]
            if not (isinstance(out, ast.Constant) and isinstance(out.value, str)):
                continue  # computed from an observed value
            if out.value == "not_run":
                continue  # not a verdict about the property
            kw = {k.arg: k.value for k in call.keywords}
            j = kw.get("judgement")
            ok = isinstance(j, ast.Constant) and isinstance(j.value, str) and j.value.strip()
            if not ok:
                missing.append(f"{os.path.relpath(p, ROOT)}:{call.lineno} "
                               f"{ast.unparse(call.args[2])}={out.value}")
    assert not missing, "literal outcomes without a judgement rationale: " + "; ".join(missing)


def test_common_row_marks_judgement_cells():
    import importlib.util
    spec = importlib.util.spec_from_file_location("audit_common",
                                                  os.path.join(PROBES, "common.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    r = mod.row("x", "1", "T5_P5_non_repudiation", "fail", "", "unsigned",
                judgement="API review")
    assert r["marker"] == "J" and r["markers"] == ["J"]
    assert r["judgement"] is True and r["counted"] is False
    assert r["rationale"] == "API review" and "API review" in r["explanation"]
    d = mod.row("x", "1", "T1_P1_agent_independence", "fail", "", "by construction",
                marker="dagger", counted=False, judgement="definitional")
    assert d["marker"] == "dagger" and d["markers"] == ["dagger", "J"]
    plain = mod.row("x", "1", "T2_P2_effect_binding", "pass", "", "measured")
    assert "judgement" not in plain and "markers" not in plain


def _matrix():
    path = os.path.join(RESULTS, "matrix.json")
    if not os.path.exists(path):
        pytest.skip("matrix.json not generated")
    with open(path) as f:
        return json.load(f)


def test_matrix_judgement_cells_are_marked_and_not_counted():
    rows = _matrix()
    j = [r for r in rows if r.get("judgement")]
    assert j, "no judgement cells in the matrix"
    for r in j:
        assert "J" in (r.get("markers") or []), r["runtime"] + r["test"]
        assert r.get("counted") is False
        assert (r.get("rationale") or "").strip()
    # every P4 and P5 cell that is not not_run is a judgement on every runtime
    for r in rows:
        if r["test"] in ("T4_P4_trusted_rendering", "T5_P5_non_repudiation") \
                and r["outcome"] not in ("not_run",) and r["runtime"] != "smolagents":
            assert r.get("judgement"), f"{r['runtime']} {r['test']} should be [J]"


def test_matrix_md_counts_exclude_judgement_cells():
    md_path = os.path.join(RESULTS, "matrix.md")
    if not os.path.exists(md_path):
        pytest.skip("matrix.md not generated")
    md = open(md_path).read()
    assert "[J]" in md and "JUDGEMENT" in md
    rows = _matrix()
    by_test = {}
    for r in rows:
        if r.get("marker") in ("dagger", "static", "J") or r.get("judgement") \
                or r.get("counted") is False:
            continue
        by_test.setdefault(r["test"], {}).setdefault(r["outcome"], 0)
        by_test[r["test"]][r["outcome"]] += 1
    for test, prop in (("T4_P4_trusted_rendering", "P4"), ("T5_P5_non_repudiation", "P5"),
                       ("T2_P2_effect_binding", "P2")):
        t = by_test.get(test, {})
        line = (f"- **{prop}**: PASS {t.get('pass', 0)} · PART {t.get('partial', 0)} · "
                f"FAIL {t.get('fail', 0)} · n/a {t.get('na', 0)}")
        assert line in md, f"count line mismatch for {prop}: expected {line!r}"


def _row(rows, rt, test):
    for r in rows:
        if r["runtime"] == rt and r["test"] == test:
            return r
    pytest.skip(f"{rt} {test} not in matrix")


def test_google_adk_p2_l2_is_measured_through_the_runner():
    r = _row(_matrix(), "google-adk", "T2_P2_effect_binding")
    lv = r.get("levels") or {}
    variants = lv.get("L2_variants") or {}
    assert len(variants) >= 3, "mismatched confirmations were not actually sent"
    for name, v in variants.items():
        assert "executed" in v and "substituted" in v, name
    any_sub = any(v["substituted"] for v in variants.values())
    if any_sub:
        assert r["outcome"] == "fail"
    else:
        assert lv["L2"].startswith("resist") and r["outcome"] in ("pass", "partial")
    assert not r.get("judgement"), "the ADK P2 cell must be measured, not a judgement"


def test_google_adk_p3_uses_the_uniform_rollback_criterion():
    rows = _matrix()
    r = _row(rows, "google-adk", "T3_P3_single_use")
    lv = r.get("levels") or {}
    assert lv.get("rollback") in ("double-exec", "resist"), lv.get("rollback")
    assert lv.get("cross_call") in ("reused", "resist")
    # same verdict rule as the other SDK rows
    if lv["same_call"] == "re-exec" or lv["cross_call"] == "reused":
        assert r["outcome"] == "fail"
    elif lv["rollback"] == "double-exec":
        assert r["outcome"] == "partial" and r.get("qualifier") == "STATE"
    else:
        assert r["outcome"] == "pass"


def test_agno_version_sweep_is_shown_in_the_matrix():
    sp = os.path.join(RESULTS, "agno_sweep.json")
    if not os.path.exists(sp):
        pytest.skip("agno sweep not generated")
    sweep = json.load(open(sp))
    versions = [e["version"] for e in sweep]
    for env, ver in (("agno_309", "3.0.9"), ("agno_3010", "3.0.10"), ("agno", "3.1.3")):
        if os.path.exists(os.path.join(AUDIT, ".envs", env, "bin", "python")):
            assert ver in versions, f"agno {ver} missing from sweep"
    for e in sweep:
        assert e["T2_P2_effect_binding"]["outcome"] in ("pass", "partial", "fail", "not_run")
        assert e["T3_P3_single_use"]["outcome"] in ("pass", "partial", "fail", "not_run")
    md = open(os.path.join(RESULTS, "matrix.md")).read()
    assert "Version dependence: agno sweep (P2, P3)" in md
    for v in versions:
        assert re.search(rf"^\| {re.escape(v)} \|", md, re.M), f"sweep row for {v} missing"


def test_google_adk_probe_reexecutes_if_env_present():
    py = os.path.join(AUDIT, ".envs", "google_adk", "bin", "python")
    if not os.path.exists(py):
        pytest.skip("google_adk venv not present")
    p = subprocess.run([py, os.path.join(PROBES, "google_adk", "probe.py")],
                       capture_output=True, text=True, timeout=600,
                       env={**os.environ, "AUDIT_EVIDENCE_TAG": "_pytest"})
    try:
        rows = {r["test"]: r for r in json.loads(p.stdout)}
    finally:
        for f in glob.glob(os.path.join(RESULTS, "evidence", "google_adk_pytest_*.log")):
            os.remove(f)
    m = {r["test"]: r for r in _matrix() if r["runtime"] == "google-adk"}
    for t in ("T2_P2_effect_binding", "T3_P3_single_use"):
        assert rows[t]["outcome"] == m[t]["outcome"], t
        assert rows[t]["levels"] == m[t]["levels"], t
