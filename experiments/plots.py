"""Figures from experiments/results/*.json (matplotlib, static PNG + PDF).

Default output directory is experiments/results/figures/ (paper/ is frozen,
docs/DECISIONS.md D-001; the author copies figures into the paper).
Every figure is drawn only from the JSON files; nothing is recomputed here.
"""
from __future__ import annotations

import argparse
import json
import os
from typing import Any, Dict, List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(HERE, "results")

# Reference categorical order (dataviz skill palette, light mode), fixed order.
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]
INK = "#0b0b0b"
INK2 = "#52514e"
GRID = "#e4e3df"
SURFACE = "#fcfcfb"
# chat-confirm is ASR = 1 by definition and is excluded from comparative figures (EXP-3).
MODES = ["none", "narrated-card", "unbound", "totp", "txn-sign", "host-confirm", "asu", "asu-no-expl"]
ORACLE_DISPLAY = {"diligent": "exact-compare (upper bound)", "perceptual": "perceptual"}


def _load(name: str, results_dir: str) -> Optional[Dict[str, Any]]:
    p = os.path.join(results_dir, name)
    if not os.path.exists(p):
        return None
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


def _style(plt) -> None:
    plt.rcParams.update({
        "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
        "axes.edgecolor": GRID, "axes.labelcolor": INK2, "xtick.color": INK2, "ytick.color": INK2,
        "text.color": INK, "axes.grid": False, "font.size": 9, "axes.spines.top": False,
        "axes.spines.right": False,
    })


def _save(fig, out_dir: str, name: str) -> List[str]:
    os.makedirs(out_dir, exist_ok=True)
    paths = []
    for ext in ("png", "pdf"):
        p = os.path.join(out_dir, f"{name}.{ext}")
        fig.savefig(p, dpi=200, bbox_inches="tight")
        paths.append(p)
    return paths


def asr_heatmap(scen: Dict[str, Any], oracle: str, out_dir: str) -> List[str]:
    import matplotlib.pyplot as plt
    from matplotlib.colors import LinearSegmentedColormap

    keys = sorted(scen["attack"], key=lambda k: (int(k.split("-")[0][1:]), k))
    modes = [m for m in MODES if m in scen["config"]["modes"]]
    data = [[(scen["attack"][k].get(m, {}).get(oracle) or {}).get("asr") for m in modes] for k in keys]
    n = (scen["config"].get("n_per_cell_by_oracle") or {}).get(oracle, scen["config"]["n_per_cell"])
    det = oracle.split(":")[0] in ("diligent",)
    cmap = LinearSegmentedColormap.from_list("seq_blue", ["#f3f7fd", "#2a78d6", "#0d2f5c"])
    fig, ax = plt.subplots(figsize=(6.4, 0.26 * len(keys) + 1.3))
    vals = [[(v if v is not None else float("nan")) for v in row] for row in data]
    ax.imshow(vals, cmap=cmap, vmin=0, vmax=1, aspect="auto")
    for i, row in enumerate(data):
        for j, v in enumerate(row):
            txt = "n/a" if v is None else f"{v:.2f}"
            ax.text(j, i, txt, ha="center", va="center", fontsize=7,
                    color=("#ffffff" if (v or 0) > 0.55 else INK))
    ax.set_xticks(range(len(modes)), modes, rotation=30, ha="right")
    ax.set_yticks(range(len(keys)), keys)
    ax.set_title(f"ASR by approval mode, oracle: {ORACLE_DISPLAY.get(oracle, oracle)} "
                 f"({'deterministic' if det else f'n={n} per cell'}; one scripted technique per scenario)",
                 fontsize=8, loc="left")
    for s in ax.spines.values():
        s.set_visible(False)
    paths = _save(fig, out_dir, f"scenario_asr_{oracle.replace(':', '_').replace('.', 'p')}")
    plt.close(fig)
    return paths


def dojo_bars(dojo: Dict[str, Any], out_dir: str) -> List[str]:
    import matplotlib.pyplot as plt

    cells = dojo["summary"]["cells"]["attack"].get("honest", {}).get("ALL", {})
    oracles = dojo["config"]["oracles"]
    modes = [m for m in MODES if m in cells]
    fig, ax = plt.subplots(figsize=(6.8, 2.8))
    width = 0.8 / max(1, len(oracles))
    for oi, o in enumerate(oracles):
        ys = [(cells[m].get(o) or {}).get("asr") or 0.0 for m in modes]
        xs = [i - 0.4 + width * (oi + 0.5) for i in range(len(modes))]
        ax.bar(xs, ys, width=width - 0.02, color=SERIES[oi], label=ORACLE_DISPLAY.get(o, o), edgecolor=SURFACE,
               linewidth=1)
        for x, m in zip(xs, modes):
            ci = (cells[m].get(o) or {}).get("asr_cluster_ci95")
            if ci and ci[0] is not None:
                ax.plot([x, x], ci, color=INK, linewidth=0.8)
    ax.set_xticks(range(len(modes)), modes)
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("ASR (injection goal reached)")
    ax.yaxis.grid(True, color=GRID, linewidth=0.6)
    ax.set_axisbelow(True)
    n = (cells.get("asu", {}).get(oracles[0]) or {}).get("n")
    neff = (cells.get("asu", {}).get(oracles[0]) or {}).get("n_eff_injection_tasks")
    ax.set_title(f"AgentDojo v1 replay, honest narration, pooled (n={n} pairs, n_eff={neff} injection tasks; "
                 "whiskers: cluster bootstrap 95% CI)", fontsize=8, loc="left")
    ax.legend(frameon=False, fontsize=7, ncol=len(oracles), loc="upper center", bbox_to_anchor=(0.5, -0.14))
    ax.tick_params(axis="x", labelsize=8)
    paths = _save(fig, out_dir, "agentdojo_asr_by_mode")
    plt.close(fig)
    return paths


def fatigue_frontier(fat: Dict[str, Any], out_dir: str) -> List[str]:
    """One panel per fatigue setting (sensitivity), grants on."""
    import matplotlib.pyplot as plt

    specs = fat.get("grid") or [fat["oracle"]]
    cols = min(3, len(specs))
    rows = (len(specs) + cols - 1) // cols
    fig, axes = plt.subplots(rows, cols, figsize=(3.0 * cols, 2.6 * rows), squeeze=False, sharex=True, sharey=True)
    policies = list(fat.get("policies") or [])
    for idx, spec in enumerate(specs):
        ax = axes[idx // cols][idx % cols]
        pts = [p for p in fat["points"] if p["oracle"] == spec and p["grants"] and p["asr"] is not None]
        for p in pts:
            ci = p.get("asr_cluster_ci95") or [None, None]
            ci_ = policies.index(p["policy"]) if p["policy"] in policies else 0
            ax.errorbar([p["prompts_per_task"]], [p["asr"]],
                        yerr=[[p["asr"] - (ci[0] if ci[0] is not None else p["asr"])],
                              [(ci[1] if ci[1] is not None else p["asr"]) - p["asr"]]],
                        fmt="o", color=SERIES[ci_ % len(SERIES)], markersize=4, linewidth=0.8,
                        label=p["policy"] if idx == 0 else None)
        ax.set_title(spec, fontsize=8, loc="left")
        ax.set_ylim(-0.02, 1.02)
        ax.yaxis.grid(True, color=GRID, linewidth=0.6)
        ax.set_axisbelow(True)
    for j in range(len(specs), rows * cols):
        axes[j // cols][j % cols].axis("off")
    fig.supxlabel("prompts per benign task (session)", fontsize=8)
    fig.supylabel("ASR (asu mode)", fontsize=8)
    fig.legend(frameon=False, fontsize=6, loc="lower center", ncol=3, bbox_to_anchor=(0.5, -0.06))
    fig.suptitle("Step-up policy sweep, session-level fatigue: sensitivity to assumed (slope, cap)", fontsize=9,
                 x=0.01, ha="left")
    paths = _save(fig, out_dir, "fatigue_frontier")
    plt.close(fig)
    return paths


def latency_bars(lat: Dict[str, Any], out_dir: str) -> List[str]:
    import matplotlib.pyplot as plt

    rows = lat["rows"]
    names = list(rows)
    med = [rows[k]["median_us"] / 1000 for k in names]
    p95 = [rows[k]["p95_us"] / 1000 for k in names]
    fig, ax = plt.subplots(figsize=(6.4, 0.32 * len(names) + 1.0))
    y = list(range(len(names)))
    ax.barh(y, med, color=SERIES[0], height=0.6, label="median")
    ax.scatter(p95, y, color=INK, marker="|", s=120, label="p95", zorder=3)
    ax.set_yticks(y, names)
    ax.invert_yaxis()
    ax.set_xlabel("milliseconds")
    ax.xaxis.grid(True, color=GRID, linewidth=0.6)
    ax.set_axisbelow(True)
    ax.legend(frameon=False, fontsize=7, loc="lower right")
    m = lat["machine"]
    ax.set_title(f"Gateway-side in-process microbenchmarks, excluding human time (n={lat['n']}; {m['machine']}, "
                 f"{m['cpu_count']} CPU)", fontsize=8, loc="left")
    paths = _save(fig, out_dir, "latency")
    plt.close(fig)
    return paths


def make_all(results_dir: str = RESULTS, out_dir: Optional[str] = None) -> List[str]:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    _style(plt)
    out_dir = out_dir or os.path.join(results_dir, "figures")
    made: List[str] = []
    scen = _load("scenarios.json", results_dir)
    if scen:
        for o in scen["config"]["oracles"]:
            made += asr_heatmap(scen, o, out_dir)
    dojo = _load("agentdojo.json", results_dir)
    if dojo:
        made += dojo_bars(dojo, out_dir)
    fat = _load("fatigue.json", results_dir)
    if fat:
        made += fatigue_frontier(fat, out_dir)
    lat = _load("latency.json", results_dir)
    if lat:
        made += latency_bars(lat, out_dir)
    return made


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default=RESULTS)
    ap.add_argument("--out", default=None)
    a = ap.parse_args(argv)
    for p in make_all(a.results, a.out):
        print(p)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
