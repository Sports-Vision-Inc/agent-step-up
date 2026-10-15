#!/usr/bin/env python3
"""AUDIT harness orchestrator.

Runs every runtime probe in its own isolated venv/node_modules (under audit/.envs,
gitignored) and aggregates the SPEC-3 property results into:
  - audit/results/matrix.json
  - audit/results/matrix.md

Each probe is a standalone script that prints a JSON list of row dicts
(runtime, version, test, outcome, evidence, explanation). A probe that fails to
run is recorded with outcome=not_run and the captured error.

Usage:  python audit/run_all.py            # run all
        python audit/run_all.py openclaw   # run selected probes by name
"""
import json
import os
import subprocess
import sys

AUDIT = os.path.dirname(os.path.abspath(__file__))
ENVS = os.path.join(AUDIT, ".envs")
PROBES = os.path.join(AUDIT, "probes")
RESULTS = os.path.join(AUDIT, "results")
os.makedirs(RESULTS, exist_ok=True)

# name -> python interpreter that has the pinned runtime installed.
# openclaw's probe is static analysis of the shipped npm bundle, run on system python.
PY = lambda env: os.path.join(ENVS, env, "bin", "python")
PROBE_RUNNERS = {
    "openai-agents":     (PY("openai_agents"),  os.path.join(PROBES, "openai_agents", "probe.py")),
    "langgraph":         (PY("langgraph"),      os.path.join(PROBES, "langgraph", "probe.py")),
    "google-adk":        (PY("google_adk"),     os.path.join(PROBES, "google_adk", "probe.py")),
    "agno":              (PY("agno"),           os.path.join(PROBES, "agno", "probe.py")),
    "pydantic-ai":       (PY("pydantic_ai"),    os.path.join(PROBES, "pydantic_ai", "probe.py")),
    "crewai":            (PY("crewai"),         os.path.join(PROBES, "crewai", "probe.py")),
    "autogen-agentchat": (PY("autogen"),        os.path.join(PROBES, "autogen", "probe.py")),
    "smolagents":        (PY("smolagents"),     os.path.join(PROBES, "smolagents", "probe.py")),
    "mcp":               (PY("mcp"),            os.path.join(PROBES, "mcp", "probe.py")),
    "openclaw":          (sys.executable,       os.path.join(PROBES, "openclaw", "probe.py")),
}

# Tests in canonical order, and the property each maps to.
TESTS = [
    ("T1_P1_agent_independence", "P1 Agent-independence"),
    ("T2_P2_effect_binding",     "P2 Effect-binding"),
    ("T3_P3_single_use",         "P3 Freshness/single-use"),
    ("T4_P4_trusted_rendering",  "P4 Trusted rendering"),
    ("T5_P5_non_repudiation",    "P5 Non-repudiation"),
    ("T6_P7_flood_resistance",   "P7 Flood resistance"),
]

# CLIs we deliberately do NOT run here (proprietary); see audit/local_probes/.
NOT_RUN_CLIS = ["claude-code", "codex-cli", "cursor"]


def run_probe(name):
    interp, script = PROBE_RUNNERS[name]
    if not os.path.exists(interp):
        return [_not_run_row(name, f"interpreter missing: {interp}")]
    if not os.path.exists(script):
        return [_not_run_row(name, f"probe script missing: {script}")]
    try:
        p = subprocess.run([interp, script], capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        return [_not_run_row(name, "probe timed out after 600s")]
    if p.returncode != 0 and not p.stdout.strip():
        err = (p.stderr or "").strip().splitlines()[-5:]
        return [_not_run_row(name, "probe crashed: " + " | ".join(err))]
    try:
        rows = json.loads(p.stdout)
    except json.JSONDecodeError:
        err = (p.stderr or "").strip().splitlines()[-5:]
        return [_not_run_row(name, "probe produced no JSON: " + " | ".join(err))]
    return rows


def _not_run_row(name, why):
    return {"runtime": name, "version": "?", "test": "ALL", "outcome": "not_run",
            "evidence": "", "explanation": why}


# Extra agno envs for the version sweep (created with uv venv; see deps/audit.txt).
AGNO_SWEEP_ENVS = ["agno_309", "agno_3010", "agno"]
# Loopjacking's published affected range for the AgentOS remote-continue substitution.
LOOPJACKING_RANGE = ((2, 5, 6), (3, 0, 9))


def _vtuple(v):
    try:
        return tuple(int(x) for x in v.split(".")[:3])
    except ValueError:
        return None


def sweep_agno_versions(main_rows):
    """Version dependence (shown in matrix.md): re-run the SAME agno probe (identical P2/P3
    criteria, including the real-HTTP AgentOS harness) in each installed agno venv and keep
    its T2/T3 rows. The headline env ("agno") reuses the rows already measured in this run.
    Sweep evidence is written under a per-env tag so it never overwrites the headline logs;
    the probe also appends a one-line AgentOS summary to agno_agentos_versions.log."""
    script = os.path.join(PROBES, "agno", "probe.py")
    out = []
    for env in AGNO_SWEEP_ENVS:
        if env == "agno":
            rows = [r for r in main_rows if r.get("runtime") == "agno"]
        else:
            interp = PY(env)
            if not os.path.exists(interp):
                continue
            try:
                p = subprocess.run([interp, script], capture_output=True, text=True, timeout=600,
                                   env={**os.environ, "AUDIT_EVIDENCE_TAG": f"_sweep_{env}"})
                rows = json.loads(p.stdout)
            except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
                print(f"[sweep] {env}: {type(e).__name__}", file=sys.stderr)
                continue
        by_t = {r["test"]: r for r in rows}
        if "T2_P2_effect_binding" not in by_t:
            continue
        ver = by_t["T2_P2_effect_binding"].get("version", "?")
        vt = _vtuple(ver)
        entry = {"env": env, "version": ver,
                 "in_loopjacking_range": bool(vt and LOOPJACKING_RANGE[0] <= vt <= LOOPJACKING_RANGE[1])}
        for t in ("T2_P2_effect_binding", "T3_P3_single_use"):
            r = by_t.get(t, {})
            entry[t] = {k: r.get(k) for k in ("outcome", "qualifier", "marker", "levels",
                                               "evidence")}
        out.append(entry)
        print(f"[sweep] {env}: agno=={ver} P2={entry['T2_P2_effect_binding']['outcome']} "
              f"P3={entry['T3_P3_single_use']['outcome']}", file=sys.stderr)
    out.sort(key=lambda e: _vtuple(e["version"]) or (0,))
    with open(os.path.join(RESULTS, "agno_sweep.json"), "w") as f:
        json.dump(out, f, indent=2)
    return out


def main():
    selected = sys.argv[1:] or list(PROBE_RUNNERS)
    all_rows = []
    for name in selected:
        if name not in PROBE_RUNNERS:
            print(f"unknown probe: {name}", file=sys.stderr)
            continue
        print(f"[run] {name} ...", file=sys.stderr)
        rows = run_probe(name)
        all_rows.extend(rows)
        oc = {}
        for r in rows:
            oc[r["outcome"]] = oc.get(r["outcome"], 0) + 1
        print(f"      {dict(oc)}", file=sys.stderr)

    # add the not-run proprietary CLIs as explicit rows
    for cli in NOT_RUN_CLIS:
        all_rows.append({
            "runtime": cli, "version": "n/a", "test": "ALL", "outcome": "not_run",
            "evidence": f"local_probes/{cli}.md",
            "explanation": "proprietary CLI; not executed here. Manual/local test procedure "
                           f"in audit/local_probes/{cli}.md (run by the author on their Mac)."})

    # Agno AgentOS remote-continue / @approval version sweep (records whether the remote
    # substitution reproduces inside and outside Loopjacking's published range 2.5.6-3.0.9).
    sweep = sweep_agno_versions(all_rows) if "agno" in selected else None
    if sweep is None:
        sp = os.path.join(RESULTS, "agno_sweep.json")
        if os.path.exists(sp):
            with open(sp) as f:
                sweep = json.load(f)

    with open(os.path.join(RESULTS, "matrix.json"), "w") as f:
        json.dump(all_rows, f, indent=2)

    write_markdown(all_rows, sweep or [])
    print(f"[done] {len(all_rows)} rows -> results/matrix.json + results/matrix.md", file=sys.stderr)


def _cell(r):
    """Outcome symbol + marker: FAIL† (by construction), PART-s (static review)."""
    sym = {"pass": "PASS", "fail": "FAIL", "partial": "PART", "na": "n/a",
           "not_run": "not_run"}
    if not r:
        return "?"
    s = sym.get(r["outcome"], r["outcome"])
    marker = r.get("marker")
    markers = r.get("markers") or ([marker] if marker else [])
    j = "[J]" if ("J" in markers or r.get("judgement")) else ""
    if marker == "dagger":
        return s + "\u2020" + j      # FAIL† : definitional, excluded from counts
    if marker == "static":
        return ((s + "-s") if r["outcome"] == "partial" else (s + "ˢ")) + j
    q = r.get("qualifier")
    if r["outcome"] == "partial" and q in ("INT", "STORE", "STATE", "LOW"):
        s = f"PART/{q}" if q == "INT" else f"PART({q})"
    return s + j


def _ordered_runtimes(by_rt):
    order = []
    for rt in PROBE_RUNNERS:
        if rt in by_rt:
            order.append(rt)
            # any new gate rows that share this runtime's prefix go right after it
            for other in by_rt:
                if other != rt and other.startswith(rt) and other not in order:
                    order.append(other)
    for rt in by_rt:
        if rt not in order and rt not in NOT_RUN_CLIS:
            order.append(rt)
    return order


def write_markdown(rows, sweep=()):
    by_rt = {}
    versions = {}
    for r in rows:
        by_rt.setdefault(r["runtime"], {})[r["test"]] = r
        if r.get("version") not in (None, "?"):
            versions[r["runtime"]] = r["version"]

    order = _ordered_runtimes(by_rt)
    lines = []
    lines.append("# ASU runtime audit matrix")
    lines.append("")
    lines.append("Measured SPEC-3 properties of each runtime's documented human-approval / "
                 "confirmation mechanism. Generated by `python audit/run_all.py`.")
    lines.append("")
    lines.append("Outcome legend: **PASS** = property holds · **FAIL** = property missing · "
                 "**PART** = holds only partially · **n/a** = no such mechanism / not applicable · "
                 "**not_run** = not executed.")
    lines.append("")
    lines.append("Markers: **†** = fails BY CONSTRUCTION under SPEC-3's host-adversarial threat "
                 "model (not a measured per-runtime result; EXCLUDED from any \u201cN of M\u201d "
                 "count) · **-s / ˢ** = static source review only, never executed (capped below "
                 "PASS) · **PART/INT** = holds only if the integrator renders from the structured "
                 "data · **PART(STORE)** = bound against the resumer but not a backing-store "
                 "writer · **PART(STATE)** = single use is relative to run state; a rollback "
                 "replays · **PART(LOW)** = low-severity gap · **[J]** = JUDGEMENT: the "
                 "outcome is a hard-coded literal chosen by the auditor from source/doc/API "
                 "review (rationale in the row), not selected by an observed experimental "
                 "value; EXCLUDED from the measured counts like † cells.")
    lines.append("")
    lines.append("Columns P1-P7 correspond to tests T1-T6 (see each probe docstring).")
    lines.append("")

    header = "| Runtime | Version | " + " | ".join(t[1].split()[0] for t in TESTS) + " |"
    sep = "|" + "---|" * (len(TESTS) + 2)
    lines.append(header)
    lines.append(sep)
    for rt in order:
        ver = versions.get(rt, "?")
        allrow = by_rt[rt].get("ALL")
        cells = [_cell(by_rt[rt].get(test) or allrow) for test, _ in TESTS]
        lines.append(f"| {rt} | {ver} | " + " | ".join(cells) + " |")
    for cli in NOT_RUN_CLIS:
        if cli in by_rt:
            lines.append(f"| {cli} | n/a | " + " | ".join(["not_run"] * len(TESTS)) + " |")
    lines.append("")

    # property key
    lines.append("### Property key")
    for test, prop in TESTS:
        lines.append(f"- **{prop.split()[0]}** ({test}): {prop[len(prop.split()[0])+1:]}")
    lines.append("")

    # Counts that EXCLUDE dagger / static / not_run cells.
    lines.append("### Measured counts (excluding † by-construction, [J] judgement and static cells)")
    for test, prop in TESTS:
        tally = {"pass": 0, "fail": 0, "partial": 0, "na": 0}
        for rt in order:
            r = by_rt[rt].get(test)
            if (not r or r.get("marker") in ("dagger", "static", "J") or r.get("judgement")
                    or "J" in (r.get("markers") or []) or r.get("counted") is False):
                continue
            if r["outcome"] in tally:
                tally[r["outcome"]] += 1
        lines.append(f"- **{prop.split()[0]}**: PASS {tally['pass']} · PART {tally['partial']} · "
                     f"FAIL {tally['fail']} · n/a {tally['na']}")
    lines.append("")
    lines.append("P1 is reported as FAIL† for every in-process runtime by construction and is "
                 "therefore not counted; see the measurable P1 columns below. P4 and P5 cells "
                 "are API/source-review judgements ([J]) on every runtime, so their measured "
                 "counts are (near) empty by design.")
    lines.append("")
    jcells = [(rt, test) for rt in order for test, _ in TESTS
              if by_rt[rt].get(test) and (by_rt[rt][test].get("judgement")
                                          or "J" in (by_rt[rt][test].get("markers") or []))]
    lines.append(f"Judgement cells ([J], not counted): {len(jcells)}.")
    lines.append("")

    # Measurable P1 columns (AUD-1).
    lines.append("### P1 measurable columns")
    lines.append("")
    lines.append("| Runtime | Out-of-process resume | Ships separate-principal approver |")
    lines.append("|---|---|---|")
    for rt in order:
        r = by_rt[rt].get("T1_P1_agent_independence")
        p1 = (r or {}).get("p1") if r else None
        if not p1:
            continue
        lines.append(f"| {rt} | {p1.get('oop_resume','?')} | "
                     f"{p1.get('separate_principal_approver','?')} |")
    lines.append("")

    # P2 capability ladder (AUD-2).
    lines.append("### P2 capability ladder (L1 approver edit · L2 resume API · L3 store writer)")
    lines.append("")
    lines.append("| Runtime | L1 | L2 | L3 | Verdict |")
    lines.append("|---|---|---|---|---|")
    for rt in order:
        r = by_rt[rt].get("T2_P2_effect_binding")
        lv = (r or {}).get("levels") if r else None
        if not lv or not all(k in lv for k in ("L1", "L2", "L3")):
            continue
        def _esc(x):
            return str(x).replace("|", "\\|")
        lines.append(f"| {rt} | {_esc(lv['L1'])} | {_esc(lv['L2'])} | {_esc(lv['L3'])} | "
                     f"{_cell(r)} |")
    lines.append("")

    # P3 uniform criterion, per sub-test (same criterion on every runtime).
    lines.append("### P3 uniform criterion (same_call · rollback · cross_call)")
    lines.append("")
    lines.append("| Runtime | same_call | rollback | cross_call | Verdict |")
    lines.append("|---|---|---|---|---|")
    for rt in order:
        r = by_rt[rt].get("T3_P3_single_use")
        lv = (r or {}).get("levels") if r else None
        if not lv or not all(k in lv for k in ("same_call", "rollback", "cross_call")):
            continue
        def _e(x):
            return str(x).replace("|", "\\|")
        lines.append(f"| {rt} | {_e(lv['same_call'])} | {_e(lv['rollback'])} | "
                     f"{_e(lv['cross_call'])} | {_cell(r)} |")
    lines.append("")

    # Version dependence: agno sweep (P2/P3), same probe + criteria on every version.
    if sweep:
        lines.append("### Version dependence: agno sweep (P2, P3)")
        lines.append("")
        lines.append("Same agno probe and criteria re-run in each installed agno release "
                     "(AgentOS remote continue over real HTTP for P2 L2 and P3 same_call; "
                     "in-process rollback for P3). Loopjacking's published affected range is "
                     "AgentOS 2.5.6-3.0.9; 3.1.3 is the latest release measured.")
        lines.append("")
        lines.append("| agno | In Loopjacking range | P2 | P2 L2 (remote continue) | P3 | "
                     "P3 same_call | P3 rollback |")
        lines.append("|---|---|---|---|---|---|---|")
        for e in sweep:
            t2 = e.get("T2_P2_effect_binding") or {}
            t3 = e.get("T3_P3_single_use") or {}
            l2 = (t2.get("levels") or {}).get("L2", "?")
            l3 = t3.get("levels") or {}
            lines.append(f"| {e['version']} | {'yes' if e.get('in_loopjacking_range') else 'no'} | "
                         f"{_cell(t2)} | {l2} | {_cell(t3)} | {l3.get('same_call','?')} | "
                         f"{l3.get('rollback','?')} |")
        lines.append("")
        def _dep(t):
            vals = {_cell(e.get(t) or {}) for e in sweep}
            return "version-DEPENDENT" if len(vals) > 1 else "the same on every measured release"
        lines.append(f"The headline matrix row reports agno {versions.get('agno', '?')}. Across "
                     f"the sweep the P2 verdict is {_dep('T2_P2_effect_binding')}; the P3 "
                     f"verdict is {_dep('T3_P3_single_use')}.")
        lines.append("")

    # detailed rows
    lines.append("## Per-test detail")
    lines.append("")
    for rt in order:
        lines.append(f"### {rt} {versions.get(rt,'')}")
        lines.append("")
        lines.append("| Test | Outcome | Mechanism | Explanation | Evidence |")
        lines.append("|---|---|---|---|---|")
        allrow = by_rt[rt].get("ALL")
        for test, _ in TESTS:
            r = by_rt[rt].get(test) or allrow
            if not r:
                continue
            expl = r["explanation"].replace("|", "\\|").replace("\n", " ")
            mech = str(r.get("mechanism", "")).replace("|", "\\|")
            ev = r.get("evidence", "") or ""
            lines.append(f"| {test} | {_cell(r)} | {mech} | {expl} | {ev} |")
        lines.append("")

    with open(os.path.join(RESULTS, "matrix.md"), "w") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
