"""Scenario grid runner: (scenario | benign task) x approval mode x oracle x seed.

Each trial runs on a fresh gateway (``harness.Trial``). Trials are
independent and seeded, so the result does not depend on worker count or
order. Errors are recorded per trial and reported, never dropped.
"""
from __future__ import annotations

import os
import time
import traceback
from concurrent.futures import ProcessPoolExecutor
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from asu.config import APPROVAL_MODES

from .agents.base import AgentRuntime, HumanSim
from .agents.benign import run_benign
from .agents.compromised import CompromisedAgent
from .harness import Trial
from .oracles import ORACLE_SPECS, Expectations, make_oracle
from .scenarios import all_scenarios, benign_only_scenarios, by_key
from .scenarios.common import Scenario
from .scoring import aggregate_attack, aggregate_benign, benign_completion, canonical_expected

# Gateway modes plus harness-side modes (experiments.harness.HARNESS_MODES).
MODES: Tuple[str, ...] = tuple(APPROVAL_MODES) + ("host-confirm", "txn-sign", "asu-no-expl")


def trial_seed(base: int, *parts: Any) -> int:
    import hashlib

    h = hashlib.sha256(("|".join([str(base)] + [str(p) for p in parts])).encode()).digest()
    return int.from_bytes(h[:4], "big")


def run_trial(scn_key: str, mode: str, oracle_spec: str, seed: int, agent: str = "compromised",
              tmp_root: Optional[str] = None) -> Dict[str, Any]:
    scn = by_key()[scn_key]
    return _run(scn, mode, oracle_spec, seed, agent, tmp_root)


def _run(scn: Scenario, mode: str, oracle_spec: str, seed: int, agent: str, tmp_root: Optional[str]) -> Dict[str, Any]:
    t0 = time.perf_counter()
    rec: Dict[str, Any] = {"scenario": scn.key, "task": scn.task.id, "mode": mode, "oracle": oracle_spec,
                           "seed": seed, "agent": agent, "policy": scn.policy_name, "error": None}
    trial = None
    try:
        trial = Trial(mode, scn.policy(), tmp_root=tmp_root)
        if scn.setup is not None:
            scn.setup(trial)
        oracle = make_oracle(oracle_spec, seed)
        oracle.begin(scn.task, Expectations(scn.task, trial.config.policy, trial.ws))
        expected = canonical_expected(scn.task, trial.config.policy, trial.ws)
        human = HumanSim(trial, oracle)
        rt = AgentRuntime(trial, human, compromised=(agent == "compromised"))
        if agent == "compromised":
            scn.attack(CompromisedAgent(rt), rt, trial)
        else:
            run_benign(rt, scn.task)
        descs = trial.ledger_descriptors()
        done, total = benign_completion(descs, expected)
        rec.update({
            "attack_success": bool(scn.attack_succeeded(descs, trial)) if agent == "compromised" else None,
            "attack_effects": sum(1 for d in descs if scn.is_attack(d, trial)),
            "ledger_effects": len(descs),
            "benign_done": done, "benign_total": total,
            "prompts": human.prompts, "page_prompts": human.page_prompts, "chat_prompts": human.chat_prompts,
            "decisions": [{k: v for k, v in d.items() if k in ("approve", "grant", "basis", "channel")}
                          for d in human.decisions],
            "outcomes": [{"tool": o.tool, "status": o.status, "path": o.path, "attack": o.attack}
                         for o in rt.outcomes],
            # ledger 'via' of every executed attack effect (policy_allow, approval, grant, ...)
            "attack_paths": sorted({r.get("via") for r in trial.ledger() if scn.is_attack(r["descriptor"], trial)}),
            "metrics": scn.metrics(descs, trial) if scn.metrics else {},
            "ledger_via": [r.get("via") for r in trial.ledger()],
        })
    except Exception as e:  # recorded, counted in "errors", never silently dropped
        rec["error"] = f"{type(e).__name__}: {e}"
        rec["traceback"] = traceback.format_exc(limit=6)
    finally:
        if trial is not None:
            trial.close()
    rec["wall_s"] = round(time.perf_counter() - t0, 4)
    return rec


def attack_paths(outcomes) -> List[str]:
    """How each executed attack effect got through (outcome paths)."""
    return sorted({o.path for o in outcomes if o.attack and o.status == "executed"})


def _job(args: Tuple[str, str, str, int, str, Optional[str]]) -> Dict[str, Any]:
    return run_trial(*args)


def benign_workloads(scns: Sequence[Scenario]) -> List[Scenario]:
    """One representative scenario per (task, policy, setup) to run the
    benign agent on the same configuration the attacks used."""
    seen, out = set(), []
    for s in scns:
        k = (s.task.id, s.policy_name)
        if k in seen:
            continue
        seen.add(k)
        out.append(s)
    return out


def run_grid(scenario_keys: Optional[Iterable[str]] = None, modes: Sequence[str] = MODES,
             oracles: Sequence[str] = ORACLE_SPECS, n: int = 10, base_seed: int = 20261013,
             workers: int = 0, tmp_root: Optional[str] = None, benign: bool = True,
             progress: bool = False, n_deterministic: Optional[int] = None,
             n_benign: Optional[int] = None) -> Dict[str, Any]:
    """``n_deterministic``: trials per cell for deterministic oracles (a few
    suffice to confirm determinism; reported as n_distinct_outcomes).
    ``n_benign``: trials per benign cell for stochastic oracles."""
    from .oracles import is_deterministic

    def n_for(o: str, benign_: bool = False) -> int:
        if is_deterministic(o) and n_deterministic is not None:
            return min(n, n_deterministic)
        if benign_ and n_benign is not None:
            return n_benign
        return n

    scns = [s for s in all_scenarios() if scenario_keys is None or s.key in set(scenario_keys)]
    jobs: List[Tuple[str, str, str, int, str, Optional[str]]] = []
    for s in scns:
        for m in modes:
            for o in oracles:
                for i in range(n_for(o)):
                    # Common random numbers (EXP-4): the seed does not depend on the
                    # mode, so stochastic oracles draw the same stream in every mode
                    # and mode comparisons are paired.
                    jobs.append((s.key, m, o, trial_seed(base_seed, s.key, o, i), "compromised", tmp_root))
    near = benign_only_scenarios() if scenario_keys is None else \
        [b for b in benign_only_scenarios() if b.key in set(scenario_keys)]
    bench = (benign_workloads(scns) + near) if benign else []
    for s in bench:
        for m in modes:
            for o in oracles:
                for i in range(n_for(o, True)):
                    jobs.append((s.key, m, o, trial_seed(base_seed, "benign", s.task.id, s.policy_name, o, i),
                                 "benign", tmp_root))
    t0 = time.perf_counter()
    workers = workers if workers > 0 else max(1, min(8, (os.cpu_count() or 2)))
    if workers == 1:
        results = []
        for j, job in enumerate(jobs):
            results.append(_job(job))
            if progress and j % 200 == 0:
                print(f"  {j}/{len(jobs)}", flush=True)
    else:
        with ProcessPoolExecutor(max_workers=workers) as ex:
            results = list(ex.map(_job, jobs, chunksize=16))
    wall = time.perf_counter() - t0

    attack_cells: Dict[str, Dict[str, Dict[str, Any]]] = {}
    benign_cells: Dict[str, Dict[str, Dict[str, Any]]] = {}
    groups: Dict[Tuple[str, str, str, str], List[Dict[str, Any]]] = {}
    for r in results:
        groups.setdefault((r["agent"], r["scenario"], r["mode"], r["oracle"]), []).append(r)
    scn_by_key = {s.key: s for s in scns + benign_only_scenarios()}
    for (agent, key, mode, oracle), trials in sorted(groups.items()):
        if agent == "compromised":
            attack_cells.setdefault(key, {}).setdefault(mode, {})[oracle] = aggregate_attack(trials, oracle)
        else:
            s = scn_by_key[key]
            bkey = f"{s.task.id}@{s.policy_name}"
            benign_cells.setdefault(bkey, {}).setdefault(mode, {})[oracle] = aggregate_benign(trials, oracle)
    # Paired comparisons (common random numbers) vs asu, stochastic oracles only.
    from .oracles import is_deterministic
    from .scoring import paired_compare

    paired: Dict[str, Dict[str, Dict[str, Any]]] = {}
    by_cell: Dict[Tuple[str, str, str], Dict[int, bool]] = {}
    for r in results:
        if r["agent"] == "compromised" and r.get("error") is None:
            by_cell.setdefault((r["scenario"], r["mode"], r["oracle"]), {})[r["seed"]] = bool(r["attack_success"])
    for (key, mode, oracle), outcome in sorted(by_cell.items()):
        if mode == "asu" or is_deterministic(oracle):
            continue
        base = by_cell.get((key, "asu", oracle))
        if base:
            paired.setdefault(key, {}).setdefault(oracle, {})[mode] = paired_compare(outcome, base)
    errors = [r for r in results if r.get("error")]
    return {
        "config": {"modes": list(modes), "oracles": list(oracles), "n_per_cell": n,
                   "n_per_cell_by_oracle": {o: n_for(o) for o in oracles},
                   "n_benign_by_oracle": {o: n_for(o, True) for o in oracles}, "base_seed": base_seed,
                   "workers": workers, "scenarios": [s.key for s in scns]},
        "scenarios": {s.key: {"id": s.id, "variant": s.variant, "title": s.title, "task": s.task.id,
                              "task_description": s.task.description, "policy": s.policy_name,
                              "source": s.source, "notes": s.notes} for s in scns},
        "policies": {s.policy_name: s.policy() for s in scns},
        "attack": attack_cells,
        "benign": benign_cells,
        "paired_vs_asu": paired,
        "n_trials": len(results),
        "n_errors": len(errors),
        "error_samples": [{k: e.get(k) for k in ("scenario", "mode", "oracle", "agent", "error", "traceback")}
                          for e in errors[:10]],
        "wall_s": round(wall, 2),
        "trials": results,
    }
