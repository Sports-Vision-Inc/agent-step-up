#!/usr/bin/env python3
"""Run every formal model/lemma and write formal/results.json.

Engines:
  * tamarin  -- unbounded proofs of formal/tamarin/*.spthy (revision 2, D-005).
                This is the default and the only engine whose rows go into
                results.json. Without tamarin-prover every job is recorded as
                "not_run" -- never as verified.
  * maude    -- LEGACY bounded search over formal/maude/*.maude, which encode
                the pre-D-005 (revision 1) rules: v1 challenge with nonce,
                separate grant ceremony, no explanation box, no enrollment or
                ceremony-control adversary. Kept as a bounded cross-check of
                the core binding/consumption rules only; run with
                `--only maude` (writes wherever --out points).

Result values: verified | falsified | timeout | verified_bounded | not_run | error.
For exists-trace (sanity) lemmas "verified" means a witness trace was found.
A Tamarin run whose output reports a failed wellformedness check is recorded
as "error" (results on ill-formed theories are not guaranteed sound), and the
script exits non-zero on any error or mismatch.

Usage: python3 formal/run_all.py [--timeout S] [--only maude|tamarin] [--quick]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

HERE = Path(__file__).resolve().parent
MAUDE_DIR = HERE / "maude"
TAMARIN_DIR = HERE / "tamarin"
TRACE_DIR = HERE / "traces"
RESULTS = HERE / "results.json"

EFFECTS = "eff(c1, x1) ; eff(c1, x2) ; eff(c2, x1)"

# Hypotheses (formal/README.md "Assumptions"):
#   H1 human decides from trusted fields only (no DecidesOnExplanation)
#   H2 enrollment closed (no EnrollmentOpen)
#   H3 honest rendering origin (no CeremonyControl)
H_ALL = ["H1", "H2", "H3"]

# Expected Tamarin outcomes (design intent). "holds" = verified,
# "fails" = falsified. Every lemma in every model must be listed: a lemma
# missing from this table is reported as an error.
EXPECTED: Dict[str, Dict[str, str]] = {
    "asu": {
        "exec_possible": "holds", "grant_exec_possible": "holds", "judge_possible": "holds",
        "L1_effect_binding": "holds", "L1_sig_binding": "holds", "L2_single_use": "holds",
        "L3_agent_independence": "holds", "L4_non_repudiation": "holds",
        "L4c_consent_nonrepudiation": "holds",
        "L5_grant_scope": "holds", "L5b_grant_max_uses": "holds",
        # strengthened-adversary attack variants (same theory, one hypothesis dropped)
        "X1_L1_effect_binding_noH1": "fails", "X1_L3_agent_independence_noH1": "fails",
        "X2_L4c_consent_nonrepudiation_noH3": "fails", "X2_L1_effect_binding_noH3": "fails",
        "X3_L1_effect_binding_open_enrollment": "fails",
        "X3_L1_sig_binding_open_enrollment": "fails",
        "X3_L4_non_repudiation_open_enrollment": "fails",
        "X3_L5_grant_scope_open_enrollment": "fails",
    },
    "v1_unbound": {"exec_possible": "holds", "L1_effect_binding": "fails", "L1_sig_binding": "fails",
                   "L2_single_use": "holds", "L3_agent_independence": "holds"},
    "v2_narration": {"exec_possible": "holds", "judge_possible": "holds",
                     "L1_effect_binding": "fails", "L1_sig_binding": "holds", "L2_single_use": "holds",
                     "L3_agent_independence": "fails", "L4_non_repudiation": "holds"},
    "v3_replay": {"exec_possible": "holds", "judge_possible": "holds",
                  "L1_effect_binding": "holds", "L1_sig_binding": "holds", "L2_single_use": "fails",
                  "L3_agent_independence": "holds", "L4_non_repudiation": "holds"},
    "v4_totp_relay": {"exec_possible": "holds", "L1_effect_binding": "fails", "L2_single_use": "holds",
                      "L3_agent_independence": "fails"},
    "v4b_chat_confirm": {"exec_possible": "holds", "L1_effect_binding": "fails", "L2_single_use": "holds",
                         "L3_agent_independence": "fails"},
    "v5_mac": {"exec_possible": "holds", "judge_possible": "holds",
               "L1_effect_binding": "holds", "L1_sig_binding": "holds", "L2_single_use": "holds",
               "L3_agent_independence": "holds", "L4_non_repudiation": "fails"},
}

# Which hypotheses each ASU lemma assumes (recorded in results.json).
HYPOTHESES: Dict[str, List[str]] = {
    "L1_effect_binding": H_ALL, "L1_sig_binding": ["H2"], "L2_single_use": [],
    "L3_agent_independence": H_ALL, "L4_non_repudiation": ["H2"],
    "L4c_consent_nonrepudiation": H_ALL, "L5_grant_scope": H_ALL, "L5b_grant_max_uses": [],
    "X1_L1_effect_binding_noH1": ["H2", "H3"], "X1_L3_agent_independence_noH1": ["H2", "H3"],
    "X2_L4c_consent_nonrepudiation_noH3": ["H1", "H2"], "X2_L1_effect_binding_noH3": ["H1", "H2"],
    "X3_L1_effect_binding_open_enrollment": ["H1", "H3"],
    "X3_L1_sig_binding_open_enrollment": [],
    "X3_L4_non_repudiation_open_enrollment": [],
    "X3_L5_grant_scope_open_enrollment": ["H1", "H3"],
}

# LEGACY Maude table (revision-1 rules; see module docstring).
MAUDE_EXPECTED: Dict[str, Dict[str, str]] = {
    "asu": {"L1_effect_binding": "holds", "L1_sig_binding": "holds", "L2_single_use": "holds",
            "L3_agent_independence": "holds", "L4_non_repudiation": "holds",
            "L5_grant_scope": "holds", "L5b_grant_max_uses": "holds",
            "exec_possible": "holds", "grant_exec_possible": "holds", "judge_possible": "holds"},
    "v1_unbound": {"L1_effect_binding": "fails", "L1_sig_binding": "fails", "L2_single_use": "holds",
                   "L3_agent_independence": "holds", "L4_non_repudiation": "fails",
                   "exec_possible": "holds", "judge_possible": "holds"},
    "v2_narration": {"L1_effect_binding": "fails", "L1_sig_binding": "holds", "L2_single_use": "holds",
                     "L3_agent_independence": "fails", "L4_non_repudiation": "holds",
                     "exec_possible": "holds", "judge_possible": "holds"},
    "v3_replay": {"L1_effect_binding": "holds", "L1_sig_binding": "holds", "L2_single_use": "fails",
                  "L3_agent_independence": "holds", "L4_non_repudiation": "holds",
                  "exec_possible": "holds", "judge_possible": "holds"},
    "v4_totp_relay": {"L1_effect_binding": "fails", "L2_single_use": "holds",
                      "L3_agent_independence": "fails", "exec_possible": "holds"},
    "v4b_chat_confirm": {"L1_effect_binding": "fails", "L2_single_use": "holds",
                         "L3_agent_independence": "fails", "exec_possible": "holds"},
    "v5_mac": {"L1_effect_binding": "holds", "L1_sig_binding": "holds", "L2_single_use": "holds",
               "L3_agent_independence": "holds", "L4_non_repudiation": "fails",
               "exec_possible": "holds", "judge_possible": "holds"},
}

WF_FAIL = re.compile(r"wellformedness check(?:s)? failed", re.I)

# Maude jobs: (model, lemma, predicate, kind, B, X, scopes)
# kind "safety": search for a state satisfying the bad-predicate.
# kind "exists": search for a witness state.
CORE = (3, 3, "mt")            # 3 approvals, 3 executions, grants disabled
WITH_GRANTS = (2, 3, "c1 ; c2")  # 2 approvals/grants, grants enabled
VARIANT = (2, 3, "mt")


def maude_jobs(quick: bool = False) -> List[dict]:
    core = (2, 3, "mt") if quick else CORE
    jobs = []

    def add(model, lemma, pred, kind, bound):
        jobs.append(dict(model=model, lemma=lemma, pred=pred, kind=kind,
                         B=bound[0], X=bound[1], scopes=bound[2]))

    for lemma, pred in [("L1_effect_binding", "badL1"), ("L1_sig_binding", "badL1sig"),
                        ("L2_single_use", "badL2"), ("L3_agent_independence", "badL3"),
                        ("L4_non_repudiation", "badL4sig")]:
        add("asu", lemma, pred, "safety", core)
        add("asu", lemma, pred, "safety", WITH_GRANTS)
    add("asu", "L5_grant_scope", "badL5", "safety", WITH_GRANTS)
    add("asu", "L5b_grant_max_uses", "badL5b", "safety", WITH_GRANTS)
    add("asu", "exec_possible", "okSane", "exists", core)
    add("asu", "judge_possible", "okJudgeSig", "exists", core)
    add("asu", "grant_exec_possible", "okGrant", "exists", WITH_GRANTS)

    common = [("L1_effect_binding", "badL1"), ("L1_sig_binding", "badL1sig"),
              ("L2_single_use", "badL2"), ("L3_agent_independence", "badL3")]
    for lemma, pred in common + [("L4_non_repudiation", "badL4sess")]:
        add("v1_unbound", lemma, pred, "safety", VARIANT)
    for lemma, pred in common + [("L4_non_repudiation", "badL4sig")]:
        add("v2_narration", lemma, pred, "safety", VARIANT)
    for lemma, pred in common + [("L4_non_repudiation", "badL4sig")]:
        add("v3_replay", lemma, pred, "safety", VARIANT)
    for m in ("v4_totp_relay", "v4b_chat_confirm"):
        for lemma, pred in [("L1_effect_binding", "badL1"), ("L2_single_use", "badL2"),
                            ("L3_agent_independence", "badL3")]:
            add(m, lemma, pred, "safety", VARIANT)
    # V5: only the non-repudiation lemma is meaningful in the Maude encoding
    # (the bounded intruder does not synthesise MACs for the gateway's verify
    # rule after key leakage; see README "Limits").
    add("v5_mac", "L4_non_repudiation", "badL4mac", "safety", VARIANT)
    for m in MAUDE_EXPECTED:
        if m == "asu":
            continue
        add(m, "exec_possible", "okSane", "exists", VARIANT)
    add("v5_mac", "judge_possible", "okJudgeMac", "exists", VARIANT)
    return jobs


def find_maude() -> Optional[str]:
    for cand in (HERE / "bin" / "maude", HERE / "bin" / "maude.linux64"):
        if cand.exists() and os.access(cand, os.X_OK):
            return str(cand)
    return shutil.which("maude")


def find_tamarin() -> Optional[str]:
    cand = HERE / "bin" / "tamarin-prover"
    if cand.exists() and os.access(cand, os.X_OK):
        return str(cand)
    return shutil.which("tamarin-prover")


def _maude_run(maude: str, script: str, timeout: float) -> str:
    proc = subprocess.run([maude, "-no-banner", "-no-advise"], input=script,
                          capture_output=True, text=True, timeout=timeout, cwd=MAUDE_DIR)
    return proc.stdout + proc.stderr


def run_maude_job(maude: str, job: dict, timeout: float) -> dict:
    init = f"init({job['B']}, {job['X']}, {job['scopes']})"
    search = (f"search [1] {init} =>* C:Config such that {job['pred']}(C:Config) .\n")
    script = f"load {MAUDE_DIR / job['model']}.maude\n{search}quit\n"
    bound = (f"maude bounded search: <= {job['B']} approvals/grants, <= {job['X']} executions, "
             f"effects {{{EFFECTS}}}, grants {'enabled' if job['scopes'] != 'mt' else 'disabled'}")
    rec = dict(model=job["model"], lemma=job["lemma"], engine="maude", bound=bound,
               kind=job["kind"], predicate=job["pred"])
    t0 = time.monotonic()
    try:
        out = _maude_run(maude, script, timeout)
    except subprocess.TimeoutExpired:
        rec.update(result="timeout", seconds=round(time.monotonic() - t0, 3))
        return rec
    rec["seconds"] = round(time.monotonic() - t0, 3)
    if re.search(r"^(Warning|Error)", out, re.M):
        rec.update(result="error", detail=out[-2000:])
        return rec
    m_states = re.search(r"states: (\d+)", out)
    rec["states"] = int(m_states.group(1)) if m_states else None
    sol = re.search(r"Solution 1 \(state (\d+)\)", out)
    if "No solution." in out:
        rec["result"] = "verified_bounded" if job["kind"] == "safety" else "falsified"
        if job["kind"] == "exists":
            rec["note"] = "no witness within bound"
    elif sol:
        rec["result"] = "falsified" if job["kind"] == "safety" else "verified"
        # second pass for the path (state numbers are deterministic)
        n = sol.group(1)
        script2 = (f"load {MAUDE_DIR / job['model']}.maude\n{search}show path labels {n} .\n"
                   f"show path {n} .\nquit\n")
        try:
            out2 = _maude_run(maude, script2, timeout)
            TRACE_DIR.mkdir(parents=True, exist_ok=True)
            tpath = TRACE_DIR / f"maude__{job['model']}__{job['lemma']}__B{job['B']}{'g' if job['scopes'] != 'mt' else ''}.txt"
            header = (f"# {job['model']} / {job['lemma']} ({job['kind']}) -- {rec['result']}\n"
                      f"# {bound}\n# query: {search}")
            tpath.write_text(header + out2)
            rec["trace"] = _rel(tpath)
            rec["rule_path"] = _extract_labels(out2)
        except subprocess.TimeoutExpired:
            rec["trace"] = None
    else:
        rec.update(result="error", detail=out[-2000:])
    return rec


def _rel(p: Path) -> str:
    try:
        return str(p.resolve().relative_to(HERE))
    except ValueError:
        return str(p.resolve())


def _extract_labels(out: str) -> List[str]:
    # `show path labels N` prints one rule label per line before `show path` output
    labels = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("state 0,"):
            break
        if re.fullmatch(r"[a-z][a-z0-9-]*", line):
            labels.append(line)
    return labels


def spthy_lemmas(path: Path) -> List[str]:
    return re.findall(r"^lemma\s+([A-Za-z0-9_]+)\s*:", path.read_text(), re.M)


def run_tamarin_job(tamarin: Optional[str], model: str, lemma: str, timeout: float) -> dict:
    path = TAMARIN_DIR / f"{model}.spthy"
    rec = dict(model=model, lemma=lemma, engine="tamarin", bound="unbounded")
    if model == "asu" and lemma in HYPOTHESES:
        rec["hypotheses"] = HYPOTHESES[lemma]
    if tamarin is None:
        rec.update(result="not_run", seconds=None,
                   note="tamarin-prover not installed in this environment (run formal/install.sh)")
        return rec
    TRACE_DIR.mkdir(parents=True, exist_ok=True)
    outfile = TRACE_DIR / f"tamarin__{model}__{lemma}.spthy"
    t0 = time.monotonic()
    env = dict(os.environ, LC_ALL="C.UTF-8")
    try:
        proc = subprocess.run([tamarin, f"--prove={lemma}", str(path), f"--output={outfile}"],
                              capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        rec.update(result="timeout", seconds=round(time.monotonic() - t0, 3))
        return rec
    rec["seconds"] = round(time.monotonic() - t0, 3)
    out = proc.stdout + proc.stderr
    if WF_FAIL.search(out):
        # Critique F10: never record a verdict for an ill-formed theory.
        i = out.find("wellformedness checks failed")
        rec.update(result="error", detail=("ill-formed theory: " + out[max(0, i - 200):i + 3000]))
        return rec
    m = re.search(rf"^\s*{re.escape(lemma)}\s+\((all-traces|exists-trace)\):\s+(verified|falsified|analysis incomplete)[^\n]*",
                  out, re.M)
    if not m:
        rec.update(result="error", detail=out[-2000:])
        return rec
    kind, verdict = m.group(1), m.group(2)
    rec["kind"] = "exists" if kind == "exists-trace" else "safety"
    rec["summary_line"] = m.group(0).strip()
    rec["result"] = "timeout" if verdict == "analysis incomplete" else verdict
    if rec["result"] == "falsified" or (kind == "exists-trace" and verdict == "verified"):
        rec["trace"] = _rel(outfile)
    else:
        rec["proof"] = _rel(outfile)
    return rec


def judge(rec: dict, table: Dict[str, Dict[str, str]]) -> None:
    exp = table.get(rec["model"], {}).get(rec["lemma"])
    rec["expected"] = exp
    if exp is None and rec["result"] not in ("not_run",):
        rec["matches_expected"] = False
        rec["note"] = (rec.get("note", "") + " lemma missing from the expected table").strip()
        return
    if rec["result"] in ("not_run", "timeout", "error"):
        rec["matches_expected"] = None
        return
    holds = rec["result"] in ("verified", "verified_bounded")
    rec["matches_expected"] = (holds and exp == "holds") or (not holds and exp == "fails")


def _clear_traces(prefix: str) -> None:
    if TRACE_DIR.is_dir():
        for f in TRACE_DIR.glob(prefix + "__*"):
            f.unlink()


def main(argv=None) -> int:
    global TRACE_DIR
    ap = argparse.ArgumentParser()
    ap.add_argument("--timeout", type=float, default=600.0, help="seconds per lemma")
    ap.add_argument("--only", choices=["maude", "tamarin"], default="tamarin",
                    help="engine (default tamarin; maude = legacy revision-1 encoding)")
    ap.add_argument("--quick", action="store_true", help="smaller Maude bounds (tests)")
    ap.add_argument("--model", action="append", default=None, help="restrict to model(s)")
    ap.add_argument("--out", default=str(RESULTS))
    ap.add_argument("--trace-dir", default=str(HERE / "traces"))
    args = ap.parse_args(argv)
    TRACE_DIR = Path(args.trace_dir)

    results = []
    env: Dict[str, object] = {}
    caveats: List[str] = []
    if args.only == "tamarin":
        tamarin = find_tamarin()
        if tamarin:
            ver = subprocess.run([tamarin, "--version"], capture_output=True, text=True,
                                 env=dict(os.environ, LC_ALL="C.UTF-8"))
            vout = ver.stdout + ver.stderr
            env["tamarin"] = [l.strip() for l in vout.splitlines() if "tamarin-prover 1." in l][:1]
            mm = re.search(r"returned unsupported version '([^']+)'", vout)
            if mm:
                caveats.append(f"Tamarin reports Maude {mm.group(1)} as unsupported (supported: 3.2.1+); "
                               "Ubuntu ships 3.2. Verdicts were obtained with it; re-run with Maude >= 3.2.1 "
                               "to remove this caveat.")
            maude = find_maude()
            env["maude"] = maude and subprocess.run([maude, "--version"], capture_output=True,
                                                    text=True).stdout.strip()
        else:
            env["tamarin"] = None
        _clear_traces("tamarin")
        for model in EXPECTED:
            if args.model and model not in args.model:
                continue
            lemmas = spthy_lemmas(TAMARIN_DIR / f"{model}.spthy")
            for lemma in sorted(set(EXPECTED[model]) - set(lemmas)):
                results.append(dict(model=model, lemma=lemma, engine="tamarin", result="error",
                                    seconds=None, expected=EXPECTED[model][lemma], matches_expected=False,
                                    detail="lemma listed in the expected table but absent from the model"))
            for lemma in lemmas:
                rec = run_tamarin_job(tamarin, model, lemma, args.timeout)
                judge(rec, EXPECTED)
                results.append(rec)
                print(f"[tamarin] {model:18s} {lemma:40s} {rec['result']}", flush=True)
    else:
        maude = find_maude()
        if maude is None:
            print("maude not found; install it (formal/install.sh)", file=sys.stderr)
            return 2
        env["maude"] = subprocess.run([maude, "--version"], capture_output=True,
                                      text=True).stdout.strip()
        caveats.append("LEGACY: Maude rows check the revision-1 (pre-D-005) rules, bounded; not proofs.")
        for job in maude_jobs(args.quick):
            if args.model and job["model"] not in args.model:
                continue
            rec = run_maude_job(maude, job, args.timeout)
            judge(rec, MAUDE_EXPECTED)
            results.append(rec)
            print(f"[maude]   {rec['model']:18s} {rec['lemma']:24s} B={job['B']} "
                  f"{'grants ' if job['scopes'] != 'mt' else ''}{rec['result']} "
                  f"({rec.get('seconds')}s, states={rec.get('states')})", flush=True)

    mismatches = [r for r in results if r.get("matches_expected") is False]
    errors = [r for r in results if r["result"] == "error"]
    doc = {
        "generated_by": "formal/run_all.py",
        "generated_at_unix": int(time.time()),
        "model_revision": "2 (DECISIONS D-005; docs/critique/formal.md F1-F12)" if args.only == "tamarin"
                          else "1 (legacy Maude encoding)",
        "tools": env,
        "caveats": caveats,
        "hypotheses": {
            "H1": "the human decides from the trusted card fields only (no DecidesOnExplanation)",
            "H2": "enrollment is closed (no EnrollmentOpen; D-005 item 2)",
            "H3": "honest rendering origin: the page driving the authenticator shows the card matching "
                  "the challenge (no CeremonyControl)",
        },
        "result_values": {
            "verified": "Tamarin proof (unbounded); for exists-trace lemmas: witness trace found",
            "falsified": "counterexample/attack trace found (see 'trace')",
            "verified_bounded": "Maude: no counterexample in the exhaustively searched bounded state space; NOT a proof",
            "timeout": "no verdict within the time limit",
            "not_run": "engine not available in this environment",
            "error": "engine error or ill-formed theory (see 'detail')",
        },
        "mismatches_vs_expected": len(mismatches),
        "errors": len(errors),
        "results": results,
    }
    Path(args.out).write_text(json.dumps(doc, indent=2) + "\n")
    print(f"wrote {args.out}: {len(results)} records, {len(mismatches)} mismatches vs expected, "
          f"{len(errors)} errors")
    return 1 if (mismatches or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
