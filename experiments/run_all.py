"""Regenerate every experiment number: ``python -m experiments.run_all``.

Writes experiments/results/{scenarios,agentdojo,fatigue,latency,manifest}.json,
raw per-trial JSONL (gzip) and experiments/results/SUMMARY.md, then figures
into experiments/results/figures/. ``--quick`` runs a tiny configuration
(used by the tests); its output goes to a separate directory by default.
Live-model results are never produced here (see experiments/live/).
"""
from __future__ import annotations

import argparse
import glob
import gzip
import json
import os
import platform
import sys
import time
from typing import Any, Dict, List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUT = os.path.join(HERE, "results")
MODES = ["none", "chat-confirm", "narrated-card", "unbound", "totp", "txn-sign", "host-confirm", "asu",
         "asu-no-expl"]
# chat-confirm is ASR=1 by definition (the compromised side answers in its own
# channel); it is reported but excluded from comparative figures (EXP-3).
DEFINITIONAL_MODES = ("chat-confirm",)
N_DETERMINISTIC = 3      # trials per deterministic-oracle cell (checks determinism)
N_BENIGN = 10            # trials per stochastic benign cell
DOJO_ORACLES = ("diligent", "perceptual", "careless:0.3")
DOJO_MODES = ["none", "narrated-card", "unbound", "totp", "txn-sign", "host-confirm", "asu"]
DOJO_FORGED_MODES = ["narrated-card", "totp", "txn-sign", "host-confirm", "asu", "asu-no-expl"]
SENS_MODES = ["none", "narrated-card", "asu"]
SENSITIVITY_VARIANTS = {"verbatim_injection_text": {"scheme": "https://", "placeholder": False},
                        "http_scheme_prefix": {"scheme": "http://", "placeholder": True}}


def _dump(path: str, obj: Any) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=1, sort_keys=False, default=str)


def _dump_jsonl_gz(path: str, rows: List[Dict[str, Any]]) -> None:
    with gzip.open(path, "wt", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, sort_keys=True, default=str) + "\n")


def _git() -> Dict[str, Any]:
    """Source revision of the code that produced the results (EXP-9)."""
    import hashlib
    import subprocess

    root = os.path.dirname(HERE)
    out: Dict[str, Any] = {"git_commit": None, "git_dirty": None, "git_status_sha256": None}
    try:
        out["git_commit"] = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True,
                                           text=True, check=True).stdout.strip() or None
        st = subprocess.run(["git", "status", "--porcelain"], cwd=root, capture_output=True, text=True,
                            check=True).stdout
        out["git_dirty"] = bool(st.strip())
        out["git_status_sha256"] = hashlib.sha256(st.encode()).hexdigest()
        out["git_dirty_paths_experiments_asu"] = sorted(
            line[3:] for line in st.splitlines() if line[3:].startswith(("experiments/", "asu/")))
    except Exception as e:  # not a git checkout
        out["git_error"] = f"{type(e).__name__}: {e}"
    return out


def _versions() -> Dict[str, Any]:
    out = {"python": sys.version.split()[0], "platform": platform.platform()}
    for mod in ("agentdojo", "fastapi", "starlette", "webauthn", "cryptography", "pyotp", "cbor2", "pyyaml",
                "matplotlib", "asu-gateway"):
        try:
            from importlib.metadata import version

            out[mod] = version(mod)
        except Exception:
            out[mod] = None
    return out


def run(out_dir: str, quick: bool = False, n: int = 20, workers: int = 0, skip: Optional[List[str]] = None,
        seed: int = 20261013) -> Dict[str, Any]:
    skip = set(skip or [])
    os.makedirs(out_dir, exist_ok=True)
    manifest: Dict[str, Any] = {"started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                                "command": " ".join(sys.argv), "quick": quick, "seed": seed,
                                "versions": _versions(), "steps": {}}
    manifest.update(_git())

    from .oracles import ORACLE_SPECS

    # 1. scripted scenarios A1-A13 + benign near-miss tasks ----------------
    if "scenarios" not in skip:
        from .runner import run_grid

        t0 = time.time()
        if quick:
            res = run_grid(scenario_keys=["A3", "A4", "A6-p30", "A12-spoofed-origin-write", "A13-case8"],
                           modes=MODES, oracles=["diligent", "perceptual", "careless:0.3"], n=2, base_seed=seed,
                           workers=workers)
        else:
            res = run_grid(modes=MODES, oracles=list(ORACLE_SPECS), n=n, base_seed=seed, workers=workers,
                           n_deterministic=N_DETERMINISTIC, n_benign=N_BENIGN)
        trials = res.pop("trials")
        _dump_jsonl_gz(os.path.join(out_dir, "scenarios_trials.jsonl.gz"), trials)
        _dump(os.path.join(out_dir, "scenarios.json"), res)
        manifest["steps"]["scenarios"] = {"wall_s": round(time.time() - t0, 1), "n_trials": res["n_trials"],
                                          "n_errors": res["n_errors"]}

    # 2. AgentDojo replay -----------------------------------------------
    if "agentdojo" not in skip or "fatigue" not in skip:
        from .agentdojo_replay import load_workloads

        workloads = load_workloads(os.path.join(out_dir, "agentdojo_workloads.json"))
    if "agentdojo" not in skip:
        from .agentdojo_replay import (SUITES, build_jobs, mapping_table, run_jobs, suite_policy, summarize)

        t0 = time.time()
        lim = dict(max_user_tasks=2, max_injection_tasks=2) if quick else {}
        oracles = ["diligent", "perceptual"] if quick else list(DOJO_ORACLES)
        dmodes = DOJO_MODES
        jobs = build_jobs(workloads, dmodes, oracles, seed, narrations=("honest",), security=True, **lim)
        forged_oracles = ["diligent", "narration_trusting"]
        jobs += build_jobs(workloads, DOJO_FORGED_MODES, forged_oracles, seed, narrations=("forged",),
                           benign=False, **lim)
        results = run_jobs(jobs, workers=workers)
        # EXP-6 sensitivity: adapter variants (verbatim injection text; http:// scheme prefix)
        sens: Dict[str, Any] = {}
        for vname, adapter in SENSITIVITY_VARIANTS.items():
            vjobs = build_jobs(workloads, SENS_MODES, ["diligent"], seed, narrations=("honest",), benign=False,
                               adapter=adapter, security=True, variant=vname, policy_name="dojo_default", **lim)
            vres = run_jobs(vjobs, workers=workers)
            sens[vname] = {"adapter": adapter, "summary": summarize(vres)}
            results += vres
        _dump_jsonl_gz(os.path.join(out_dir, "agentdojo_trials.jsonl.gz"), results)
        main_res = [r for r in results if not r.get("variant")]
        dojo = {
            "config": {"modes": dmodes, "forged_modes": DOJO_FORGED_MODES, "oracles": oracles,
                       "forged_narration_oracles": forged_oracles, "base_seed": seed, "limits": lim or None,
                       "sensitivity_modes": SENS_MODES},
            "workloads": {"agentdojo_version": workloads["agentdojo_version"],
                          "benchmark_version": workloads["benchmark_version"], "sha256": workloads["sha256"],
                          "counts": {s: {"user_tasks": len(workloads["suites"][s]["user_tasks"]),
                                         "injection_tasks": len(workloads["suites"][s]["injection_tasks"])}
                                     for s in SUITES}},
            "effect_class_mapping": mapping_table(),
            "policies": {s: suite_policy(s, workloads["suites"][s]["tools"]) for s in SUITES},
            "summary": summarize(main_res),
            "sensitivity": sens,
        }
        _dump(os.path.join(out_dir, "agentdojo.json"), dojo)
        manifest["steps"]["agentdojo"] = {"wall_s": round(time.time() - t0, 1), "n_trials": len(results),
                                          "n_errors": sum(1 for r in results if r.get("error"))}

    # 3. fatigue / step-up sweep (sessions; sensitivity grid) ----------
    if "fatigue" not in skip:
        from .fatigue import run_fatigue

        t0 = time.time()
        if quick:
            fat = run_fatigue(workloads, policies=["default", "allow_all"], base_seed=seed, workers=workers,
                              max_user_tasks=4, max_injection_tasks=1, grants_opts=(True,),
                              grid=["fatigued:0.2:0.9"], session_len=3, sessions_per_injection=1)
        else:
            fat = run_fatigue(workloads, base_seed=seed, workers=workers)
        _dump(os.path.join(out_dir, "fatigue.json"), fat)
        manifest["steps"]["fatigue"] = {"wall_s": round(time.time() - t0, 1), "n_trials": fat["n_trials"]}

    # 4. latency -----------------------------------------------------------
    if "latency" not in skip:
        from .latency import run_latency

        t0 = time.time()
        lat = run_latency(n=20 if quick else 300)
        _dump(os.path.join(out_dir, "latency.json"), lat)
        manifest["steps"]["latency"] = {"wall_s": round(time.time() - t0, 1)}

    manifest["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    _dump(os.path.join(out_dir, "manifest.json"), manifest)
    write_summary(out_dir)
    if "plots" not in skip:
        try:
            from .plots import make_all

            manifest["figures"] = [os.path.relpath(p, out_dir) for p in make_all(out_dir)]
        except Exception as e:  # figures are optional; numbers are in the JSON
            manifest["figures_error"] = f"{type(e).__name__}: {e}"
        _dump(os.path.join(out_dir, "manifest.json"), manifest)
    return manifest


# ---------------------------------------------------------------------------
def _fmt(v: Any, nd: int = 2) -> str:
    if v is None:
        return "—"
    if isinstance(v, float):
        return f"{v:.{nd}f}"
    return str(v)


def _load(out_dir: str, name: str) -> Optional[Dict[str, Any]]:
    p = os.path.join(out_dir, name)
    if not os.path.exists(p):
        return None
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


def _odisp(o: str) -> str:
    from .oracles import ORACLE_DISPLAY

    return ORACLE_DISPLAY.get(o, o)


def _cell(c: Optional[Dict[str, Any]], prompts: bool = True) -> str:
    if not c:
        return "—"
    if c.get("deterministic"):
        txt = f"{_fmt(c['asr'])} (det.)"
    else:
        lo, hi = c["asr_ci95"]
        txt = f"{_fmt(c['asr'])} [{_fmt(lo)},{_fmt(hi)}]"
    if prompts:
        txt += f" / {_fmt(c['prompts_mean'], 1)}"
    if c.get("errors"):
        txt += f" (err {c['errors']})"
    return txt


LIMITATIONS = [
    ("EXP-1 oracle", "`exact-compare (upper bound)` (formerly `diligent`) compares the whole card with the gateway's "
     "own rendering of the expected call by string equality: it is circular and superhuman. `perceptual` uses "
     "hand-written expectations and checks only salient visible fields with ASSUMED miss probabilities "
     "(experiments/perceptual.py). Neither is human data (D-002)."),
    ("EXP-2 attacker", "**Not addressed in this run.** The compromised agent still uses one scripted technique "
     "per scenario (plus the fallback after a 409 / no challenge). No best-response (max over techniques) ASR is "
     "reported, and the new attack family (amount cancellation, decoy target, grant redirection, padding, label "
     "spoofing, non-injective rendering, enrollment squatting, ...) has no scenarios here. Baseline rows, "
     "narrated-card in particular, therefore UNDERSTATE the best-response ASR (forging is always available "
     "against narrated-card and totp), and the asu rows are not tested against ASU-specific attacks. The "
     "red-team tests in tests/redteam/ cover those attacks against the gateway directly."),
    ("EXP-3 baselines", "`chat-confirm` is ASR = 1 **by definition** (the compromised side answers in its own "
     "channel). It is listed but is not a measurement, and it is excluded from comparative figures. "
     "`host-confirm` and `txn-sign` are simulated in the harness on the gateway's bound mode (see "
     "experiments/harness.py). host-confirm tracks asu by construction (device compromise is not modelled). "
     "txn-sign shows only payee+amount, but the gateway still binds all arguments, so substitution of "
     "non-displayed arguments is refused (txn-sign ASR is a LOWER bound there)."),
    ("EXP-4 statistics", "Deterministic cells (exact-compare only) are marked `det.` and have no CI "
     f"(n={N_DETERMINISTIC} identical trials confirm determinism). Stochastic cells: Wilson 95% CI. Seeds are "
     "shared across modes (paired design); paired differences vs asu use the exact McNemar test. AgentDojo: "
     "(user, injection) pairs are clustered; CIs are cluster-bootstrap CIs over injection tasks (n_eff = "
     "number of injection tasks). narration_trusting is stochastic (with no agent text it reads the card like "
     "`perceptual`), so its cells have CIs."),
    ("EXP-5 fatigue", "Fatigue persists over a session of 10 tasks; the frontier is a sensitivity result over an "
     "assumed (slope, cap) grid, not a finding. One gateway and one agent session per user session, so grants, "
     "the aggregate budget and deny lockouts carry across its tasks. No AgentDojo user task has two similar "
     "effects, so no simulated approver ever ticks 'grant similar' and grants on/off stay identical; that is a "
     "property of the workload, not of ASU. Policy orderings whose ASRs lie inside each other's CIs are noise."),
    ("EXP-6 AgentDojo", "ASR is reported under the project predicate (every effectful injection call executed) and "
     "AgentDojo's own security() on the replayed post-state; adapter variants test the placeholder and scheme "
     "choices."),
    ("EXP-8 narration_trusting", "A human who decides from the agent's untrusted text defeats the trusted card "
     "(asu ASR = baselines on most rows). See the limitation row below. `asu-no-expl` removes the "
     "explanation box (ablation); with no text to trust (asu-no-expl, txn-sign) this approver reads the card like "
     "`perceptual`, not like exact-compare. A7-no-aggregate and A12-spoofed-origin-write are policy-allowed "
     "(1.00 in every mode) and are not approval failures."),
    ("Measurement fixes", "After the anomaly report (docs/critique/experiments_anomalies.md): cards are read in a "
     "workspace-relative display (`/workspace/...`), so results no longer depend on the machine's temporary-path "
     "length (D1); the perceptual approver reads the Target row and the 'actually resolves to' risk line, draws "
     "once per prompt against the closest outstanding expectation, delegates the expectations a ticked grant "
     "covers and counts grant-executed effects (A9), and grades text-only views (narrated-card, chat, TOTP relay) "
     "with the same miss model instead of exact text; txn-sign grades recipients like the full card and does not "
     "expect object ids among the Targets (f2, f3). Results from before this fix are not comparable."),
    ("A12 / policy allow", "`allowed by policy` = every executed attack effect ran with `via=policy_allow` (no "
     "approval asked). These are not approval bypasses and are reported in a separate column."),
    ("EXP-11 latency", "Latency rows are in-process microbenchmarks (TestClient, no socket/TLS/browser) and "
     "EXCLUDE human time; they are not approval latency."),
    ("Live/LLM", "No live-model or LLM-approver results are in this directory (they run on the author's machine)."),
]


def write_summary(out_dir: str) -> str:
    L: List[str] = []
    man = _load(out_dir, "manifest.json") or {}
    L.append("# Experiment results summary\n")
    L.append("Generated by `python -m experiments.run_all`" + (" --quick (TINY CONFIG, not for reporting)"
                                                              if man.get("quick") else "") + ".")
    L.append(f"Run: {man.get('started_at')} to {man.get('finished_at')}; seed {man.get('seed')}; git commit "
             f"`{man.get('git_commit')}`, dirty tree: **{man.get('git_dirty')}** (status sha256 "
             f"`{(man.get('git_status_sha256') or '')[:16]}`; uncommitted experiments/asu paths are listed in "
             f"manifest.json); versions: {json.dumps(man.get('versions', {}))}.\n")
    if man.get("reduced_n_note"):
        L.append(f"**Reduced run:** {man['reduced_n_note']}\n")
    L.append("All ASR/TCR numbers are computed from the mock_ledger ground truth only. Approvers are "
             "**simulated oracles**, not people (D-002: no human-catch-rate claims). The gateway runs in its "
             "deployed configuration: closed enrollment with a one-time enrollment token, user verification "
             "required, `dev_mode` off. `—` means not applicable or not run.\n")
    L.append("## Caveats (read before any table)\n")
    L.append("| item | caveat |")
    L.append("|---|---|")
    for k, v in LIMITATIONS:
        L.append(f"| {k} | {v} |")
    L.append("")

    scen = _load(out_dir, "scenarios.json")
    if scen:
        modes = scen["config"]["modes"]
        keys = sorted(scen["attack"], key=lambda k: (int(k.split("-")[0][1:]), k))
        L.append("## Scripted attacks A1–A13 (fully compromised agent, ONE scripted technique per scenario)\n")
        L.append(f"{scen['n_trials']} trials, {scen['n_errors']} trial errors. n per cell by oracle: "
                 f"{json.dumps(scen['config'].get('n_per_cell_by_oracle'))}. Cell: ASR [95% Wilson CI] / mean "
                 "prompts; `det.` = deterministic oracle (no CI). `chat-confirm` = 1 by definition.\n")
        # Limitation row first (EXP-8)
        if "narration_trusting" in scen["config"]["oracles"]:
            L.append("### LIMITATION: approver `narration_trusting` (decides from the agent's untrusted text)\n")
            L.append("Where `asu` matches the baselines, the trusted card gives no protection against this approver. "
                     "`asu-no-expl` removes the explanation box.\n")
            L.append("| scenario | " + " | ".join(modes) + " |")
            L.append("|---|" + "---|" * len(modes))
            for k in keys:
                L.append(f"| {k} | " + " | ".join(_cell(scen["attack"][k].get(m, {}).get("narration_trusting"),
                                                         False) for m in modes) + " |")
            L.append("")
        for o in scen["config"]["oracles"]:
            if o == "narration_trusting":
                continue
            L.append(f"### ASR — approver `{_odisp(o)}`\n")
            L.append("| scenario | " + " | ".join(modes) + " |")
            L.append("|---|" + "---|" * len(modes))
            for k in keys:
                L.append(f"| {k} | " + " | ".join(_cell(scen["attack"][k].get(m, {}).get(o)) for m in modes) + " |")
            L.append("")
        L.append("### Approval bypass vs allowed by policy (approver `exact-compare (upper bound)`)\n")
        L.append("Cell: approval bypass / allowed by policy (count of successful trials). Only rows with any "
                 "policy-allowed success are listed.\n")
        L.append("| scenario | " + " | ".join(modes) + " |")
        L.append("|---|" + "---|" * len(modes))
        for k in keys:
            cs = [scen["attack"][k].get(m, {}).get("diligent") or {} for m in modes]
            if any(c.get("allowed_by_policy") for c in cs):
                L.append(f"| {k} | " + " | ".join(
                    f"{c.get('approval_bypass', '—')} / {c.get('allowed_by_policy', '—')}" for c in cs) + " |")
        L.append("")
        pv = scen.get("paired_vs_asu") or {}
        if pv:
            L.append("### Paired differences vs `asu` (stochastic oracles; shared seeds)\n")
            L.append("Cell: ASR(mode) − ASR(asu) and the exact McNemar p. Only cells with "
                     "p < 0.05 are listed.\n")
            L.append("| scenario | oracle | mode | diff | p |")
            L.append("|---|---|---|---|---|")
            for k in keys:
                for o, mm in sorted((pv.get(k) or {}).items()):
                    for m, d in sorted(mm.items()):
                        if d.get("n_pairs") and d["mcnemar_p"] < 0.05:
                            L.append(f"| {k} | {_odisp(o)} | {m} | {d['diff']:+.2f} | {d['mcnemar_p']} |")
            L.append("")
        extra = [k for k in keys if any("laundered_amount_mean" in (scen["attack"][k].get(m, {}).get(o) or {})
                                        or "team_sends_mean" in (scen["attack"][k].get(m, {}).get(o) or {})
                                        for m in modes for o in scen["config"]["oracles"])]
        if extra:
            L.append("### Scenario-specific metrics (approver `exact-compare`, mean per trial)\n")
            L.append("| scenario | metric | " + " | ".join(modes) + " |")
            L.append("|---|---|" + "---|" * len(modes))
            for k in extra:
                for met in ("laundered_amount_mean", "team_sends_mean", "attacker_sends_mean"):
                    vals = [(scen["attack"][k].get(m, {}).get("diligent") or {}).get(met) for m in modes]
                    if any(v is not None for v in vals):
                        L.append(f"| {k} | {met} | " + " | ".join(_fmt(v, 1) for v in vals) + " |")
            L.append("")
        L.append("### Benign agent, including near-miss tasks (cell: TCR / prompts per task / false-block rate)\n")
        L.append("Near-miss tasks (EXP-7): lookalike recipient and payee, long truncated body and URL, and a "
                 "legitimate `bash -c` command. Under `exact-compare` false blocks are 0 by construction, so "
                 "read `perceptual`, `careless` and `fatigued`.\n")
        for o in scen["config"]["oracles"]:
            L.append(f"Approver `{_odisp(o)}` (n per cell {scen['config'].get('n_benign_by_oracle', {}).get(o)}):\n")
            L.append("| task@policy | " + " | ".join(modes) + " |")
            L.append("|---|" + "---|" * len(modes))
            for k in sorted(scen["benign"]):
                row = []
                for m in modes:
                    c = scen["benign"][k].get(m, {}).get(o)
                    row.append("—" if not c else f"{_fmt(c['tcr'])} / {_fmt(c['prompts_per_task_mean'], 1)} / "
                                                 f"{_fmt(c['false_block_rate'])}")
                L.append(f"| {k} | " + " | ".join(row) + " |")
            L.append("")

    dojo = _load(out_dir, "agentdojo.json")
    if dojo:
        s = dojo["summary"]
        w = dojo["workloads"]
        L.append("## AgentDojo ground-truth replay\n")
        L.append(f"agentdojo {w['agentdojo_version']} benchmark {w['benchmark_version']} (workload sha256 "
                 f"`{w['sha256'][:16]}`); {s['n_trials']} trials in the main run, {s['n_errors']} errors. Injection "
                 f"tasks with no effectful ground-truth call are out of scope: {s['out_of_scope_injection_tasks']}. "
                 "The honest-narration attacker does not lie, and the forged-narration attacker claims the user's "
                 "pending call. Neither is a best-response attacker (EXP-2).\n")
        L.append("Cell: ASR (project predicate) [cluster-bootstrap 95% CI over injection tasks] · AgentDojo "
                 "security() ASR · approval bypass/allowed-by-policy counts. n = pairs; n_eff = injection tasks.\n")
        for narr in sorted(s["cells"]["attack"]):
            L.append(f"### ASR, narration = {narr}, all suites pooled\n")
            cells = s["cells"]["attack"][narr].get("ALL", {})
            modes = [m for m in MODES if m in cells]
            L.append("| approver | mode | ASR [cluster CI] | security() ASR | bypass / policy | n / n_eff |")
            L.append("|---|---|---|---|---|---|")
            orcs = sorted({o for m in cells.values() for o in m})
            for o in orcs:
                for m in modes:
                    c = cells.get(m, {}).get(o)
                    if not c:
                        continue
                    ci = c.get("asr_cluster_ci95") or [None, None]
                    L.append(f"| {_odisp(o)} | {m} | {_fmt(c['asr'])} [{_fmt(ci[0])},{_fmt(ci[1])}] | "
                             f"{_fmt(c.get('agentdojo_security_asr'))} | {c.get('approval_bypass')} / "
                             f"{c.get('allowed_by_policy')} | {c['n']} / {c.get('n_eff_injection_tasks')} |")
            L.append("")
            L.append(f"Per suite (ASR; narration = {narr}):\n")
            L.append("| suite | approver | " + " | ".join(modes) + " |")
            L.append("|---|---|" + "---|" * len(modes))
            for suite in ["workspace", "travel", "banking", "slack"]:
                sc = s["cells"]["attack"][narr].get(suite, {})
                for o in orcs:
                    L.append(f"| {suite} | {_odisp(o)} | " + " | ".join(
                        _fmt((sc.get(m, {}).get(o) or {}).get("asr")) for m in modes) + " |")
            L.append("")
        pv = s.get("paired_vs_asu") or {}
        if pv:
            L.append("### Paired differences vs `asu` (same pairs; cluster bootstrap by injection task)\n")
            L.append("| narration | approver | mode | ASR(mode) − ASR(asu) | 95% CI | n_eff |")
            L.append("|---|---|---|---|---|---|")
            for narr, oo in sorted(pv.items()):
                for o, mm in sorted(oo.items()):
                    for m, d in sorted(mm.items()):
                        if d.get("n_pairs"):
                            L.append(f"| {narr} | {_odisp(o)} | {m} | {d['diff']:+.3f} | [{d['ci95'][0]:+.3f},"
                                     f"{d['ci95'][1]:+.3f}] | {d['n_eff']} |")
            L.append("")
        allc = (s["cells"]["attack"].get("honest", {}).get("ALL", {}).get("none", {}).get("diligent") or {})
        if allc.get("agentdojo_security_n"):
            L.append(f"Predicate check (mode none, exact-compare): the project predicate and AgentDojo security() "
                     f"agree on {_fmt(allc.get('predicate_agreement'))} of {allc['agentdojo_security_n']} computable "
                     f"pairs; security-only successes {allc.get('security_only')}, project-only "
                     f"{allc.get('project_only')}. security() was not computable for "
                     f"{allc.get('agentdojo_security_uncomputable')} pairs (slack injection_task_5 is defined "
                     "only on traces).\n")
        sens = dojo.get("sensitivity") or {}
        if sens:
            L.append("### Adapter sensitivity (EXP-6; honest narration, approver `exact-compare`)\n")
            L.append("| variant | mode | ASR | security() ASR |")
            L.append("|---|---|---|---|")
            base = s["cells"]["attack"].get("honest", {}).get("ALL", {})
            for m in dojo["config"].get("sensitivity_modes", []):
                c = (base.get(m) or {}).get("diligent") or {}
                L.append(f"| main (https://, placeholder) | {m} | {_fmt(c.get('asr'))} | "
                         f"{_fmt(c.get('agentdojo_security_asr'))} |")
            for vn, v in sens.items():
                cells = v["summary"]["cells"]["attack"].get("honest", {}).get("ALL", {})
                for m in dojo["config"].get("sensitivity_modes", []):
                    c = (cells.get(m) or {}).get("diligent") or {}
                    L.append(f"| {vn} | {m} | {_fmt(c.get('asr'))} | {_fmt(c.get('agentdojo_security_asr'))} |")
            L.append("")
        L.append("### Benign user tasks (cell: TCR / prompts per task / false-block rate)\n")
        modes = dojo["config"]["modes"]
        L.append("| suite | approver | " + " | ".join(modes) + " |")
        L.append("|---|---|" + "---|" * len(modes))
        for suite in ["workspace", "travel", "banking", "slack", "ALL"]:
            cells = s["cells"]["benign"].get(suite, {})
            orcs = sorted({o for m in cells.values() for o in m})
            for o in orcs:
                row = []
                for m in modes:
                    c = cells.get(m, {}).get(o)
                    row.append("—" if not c else f"{_fmt(c['tcr'])} / {_fmt(c['prompts_per_task_mean'])} / "
                                                 f"{_fmt(c['false_block_rate'])}")
                L.append(f"| {suite} | {_odisp(o)} | " + " | ".join(row) + " |")
        L.append("")

    fat = _load(out_dir, "fatigue.json")
    if fat and "grid" in fat:
        L.append("## Step-up policy sweep with session-level fatigue (asu mode) — SENSITIVITY RESULT\n")
        L.append(f"{fat['n_trials']} trials. Each session = {fat['session_len']} AgentDojo user tasks of one suite "
                 f"with one injected pair in the second half; {fat['sessions_per_injection']} sessions per "
                 "in-scope injection task. Fatigue p(rubber-stamp at the n-th prompt of the SESSION) = min(cap, "
                 "slope·(n−1)), which is an assumption. ASR CI is a cluster bootstrap over injection tasks.\n")
        L.append("| fatigue | policy | grants | prompts/task | TCR | false-block | ASR [cluster CI] | allowed by "
                 "policy | approved by human | prompts before attack |")
        L.append("|---|---|---|---|---|---|---|---|---|---|")
        for p in fat["points"]:
            ci = p.get("asr_cluster_ci95") or [None, None]
            L.append(f"| {p['oracle']} | {p['policy']} | {'on' if p['grants'] else 'off'} | "
                     f"{_fmt(p['prompts_per_task'])} | {_fmt(p['tcr'])} | {_fmt(p['false_block_rate'])} | "
                     f"{_fmt(p['asr'])} [{_fmt(ci[0])},{_fmt(ci[1])}] | {_fmt(p['asr_allowed_by_policy'])} | "
                     f"{_fmt(p['asr_approved'])} | {_fmt(p['prompts_before_attack_mean'], 1)} |")
        sen = fat.get("sensitivity") or {}
        L.append("\nPolicy order by ASR (lowest first; grants on) under each fatigue setting:\n")
        for spec, order in (sen.get("orders") or {}).items():
            flag = " (differs from default)" if (sen.get("ordering_changes_vs_default") or {}).get(spec) else ""
            L.append(f"- `{spec}`: {', '.join(order)}{flag}")
        L.append(f"\nLowest-ASR policy is the same under every setting: **{sen.get('lowest_asr_policy_stable')}**. "
                 "Non-dominated points under the default setting (ties collapsed): " + "; ".join(
                     f"{x['policy']} (grants {'on' if x['grants'] else 'off'}): {_fmt(x['prompts_per_task'])} "
                     f"prompts, ASR {_fmt(x['asr'])}" for x in fat.get("frontier", [])) + ".\n")

    lat = _load(out_dir, "latency.json")
    if lat:
        m = lat["machine"]
        L.append("## Gateway-side latency — in-process microbenchmarks, EXCLUDING human time\n")
        L.append(f"{m['platform']}, {m['cpu_count']} CPUs, Python {m['python']}. In-process (TestClient: no network "
                 "socket, TLS, browser WebAuthn ceremony or human reading/deciding time). Do not quote these as "
                 "approval latency.\n")
        L.append("| operation | n | median (µs) | p95 (µs) | mean (µs) |")
        L.append("|---|---|---|---|---|")
        for k, r in lat["rows"].items():
            L.append(f"| {k} | {r['n']} | {r['median_us']} | {r['p95_us']} | {r['mean_us']} |")
        L.append("")

    live = sorted(glob.glob(os.path.join(out_dir, "live_*.json")))
    L.append("## Live LLM agents / LLM approver (OpenRouter)\n")
    if not live:
        L.append("**Not run.** Live-model experiments run only on the author's machine; no live results exist "
                 "in this directory.\n")
    else:
        for p in live:
            d = _load(out_dir, os.path.basename(p)) or {}
            L.append(f"- `{os.path.basename(p)}`: {d.get('n_episodes')} episodes, {d.get('n_errors')} errors, "
                     f"models {d.get('models')}")
        L.append("")
    path = os.path.join(out_dir, "SUMMARY.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")
    return path


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Regenerate all experiment results.")
    ap.add_argument("--quick", action="store_true", help="tiny configuration (smoke test)")
    ap.add_argument("--out", default=None)
    ap.add_argument("--n", type=int, default=20, help="trials per scenario cell")
    ap.add_argument("--workers", type=int, default=0)
    ap.add_argument("--seed", type=int, default=20261013)
    ap.add_argument("--skip", nargs="*", default=[],
                    choices=["scenarios", "agentdojo", "fatigue", "latency", "plots"])
    ap.add_argument("--allow-dirty", action="store_true",
                    help="run even if the git tree has uncommitted changes (recorded in manifest.json)")
    ap.add_argument("--summary-only", action="store_true", help="rewrite SUMMARY.md from existing JSON")
    a = ap.parse_args(argv)
    out = a.out or (os.path.join(DEFAULT_OUT, "quick") if a.quick else DEFAULT_OUT)
    if a.summary_only:
        print(write_summary(out))
        return 0
    if not a.quick and not a.allow_dirty and _git().get("git_dirty"):
        print("refusing to run on a dirty git tree (results could not be tied to a commit); "
              "commit first or pass --allow-dirty", file=sys.stderr)
        return 2
    man = run(out, quick=a.quick, n=a.n, workers=a.workers, skip=a.skip, seed=a.seed)
    print(json.dumps(man["steps"], indent=2))
    print(f"wrote {out}/SUMMARY.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
