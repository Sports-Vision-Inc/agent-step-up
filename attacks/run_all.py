#!/usr/bin/env python3
"""Run the approval-binding attack family against every target and write the matrix.

Outputs:
  attacks/results/matrix.json   (rows + metadata)
  attacks/results/matrix.md     (human-readable grid + per-cell notes)
  attacks/results/evidence/*    (per-probe evidence logs)

Usage:
  python attacks/run_all.py            # all targets
  python attacks/run_all.py ap2 agt    # selected targets
"""
from __future__ import annotations
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attacks.targets import TARGETS, ATTACKS, REPO_ROOT  # noqa: E402
import copy  # noqa: E402
from attacks.common import RESULTS, tree_state  # noqa: E402
from attacks.probes import (  # noqa: E402
    ap2_probe, agt_probe, mcp_probe, openclaw_probe, frameworks_probe, asu_probe)

PROBES = {
    "ap2": ap2_probe.run,
    "agt": agt_probe.run,
    "mcp": mcp_probe.run,
    "openclaw": openclaw_probe.run,
    "frameworks": frameworks_probe.run,
    "asu": asu_probe.run,
}

# Order targets are displayed in the matrix.
TARGET_ORDER = ["ap2", "agt", "mcp", "openclaw", "frameworks", "asu"]
ATTACK_ORDER = [f"AB{i}" for i in range(1, 13)]

_SYM = {"vulnerable": "VULN", "not_vulnerable": "ok", "partial": "PART", "n/a": "-"}


def run(selected=None):
    os.makedirs(RESULTS, exist_ok=True)
    st = tree_state(REPO_ROOT)  # before the probes write their evidence
    rows = []
    for name in TARGET_ORDER:
        if selected and name not in selected:
            continue
        try:
            rows.extend(PROBES[name]())
        except Exception as e:  # a probe failure is recorded, never fatal
            import traceback
            tb = traceback.format_exc()
            from attacks.common import write_evidence, row
            ev = write_evidence(f"{name}_error.log", tb)
            for ab in ATTACK_ORDER:
                rows.append(row(name, ab, applicable=True, executed=False, outcome="n/a",
                                note=f"probe crashed: {e}", evidence=ev))
    targets = {k: copy.deepcopy(TARGETS[k]) for k in (selected or TARGET_ORDER) if k in TARGETS}
    if "asu" in targets:
        # The ASU column is measured against this exact tree.
        targets["asu"]["commit"] = st["stamp"]
        targets["asu"]["ref"] = "git rev-parse HEAD" + (" + uncommitted changes (dirty tree)" if st["dirty"] else "")
    meta = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "asu_commit": st["stamp"],
        "tree": {"head": st["commit"], "dirty": st["dirty"], "asu_dirty": st["asu_dirty"],
                 "dirty_paths": st["dirty_paths"]},
        "targets": targets,
        "attacks": ATTACKS,
        "note": "Approval-binding attack family (D-004). All runs are local, defensive, "
                "with mock resources and neutral placeholder data. See docs/notes/attacks.md.",
    }
    out = {"meta": meta, "rows": rows}
    with open(os.path.join(RESULTS, "matrix.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, sort_keys=True)
    _write_md(out)
    _print_summary(rows)
    return out


def _cell(rows_by):
    def get(t, ab):
        r = rows_by.get((t, ab))
        return r
    return get


def _write_md(out):
    rows = out["rows"]
    meta = out["meta"]
    by = {(r["target"], r["attack_id"]): r for r in rows}
    present = [t for t in TARGET_ORDER if any(r["target"] == t for r in rows)]
    lines = []
    lines.append("# Approval-binding attack matrix\n")
    tree = meta.get("tree") or {}
    lines.append(f"_Generated {meta['generated_at']}. ASU commit tested: "
                 f"`{meta.get('asu_commit')}`"
                 + (f" (working tree dirty; asu/ itself {'dirty' if tree.get('asu_dirty') else 'clean'})"
                    if tree.get("dirty") else "") + "._\n")
    lines.append("All attacks were run locally and defensively against the documented, intended "
                 "usage of each target, with mock resources and neutral placeholder data. No real "
                 "service, credential, or person was contacted.\n")
    lines.append("Outcomes: `VULN` vulnerable · `ok` not vulnerable · `PART` partial / "
                 "argument-level / integrator-dependent · `-` n/a (no such feature).\n")

    # Grid
    header = "| Attack | " + " | ".join(present) + " |"
    sep = "|---|" + "|".join(["---"] * len(present)) + "|"
    lines.append(header)
    lines.append(sep)
    for ab in ATTACK_ORDER:
        cells = []
        for t in present:
            r = by.get((t, ab))
            if not r:
                cells.append("")
                continue
            sym = _SYM[r["outcome"]]
            if r["outcome"] != "n/a" and not r["executed"]:
                sym += "*"  # not executed (static / derived)
            cells.append(sym)
        lines.append(f"| **{ab}** {ATTACKS[ab]} | " + " | ".join(cells) + " |")
    lines.append("\n`*` = not executed (static analysis, or derived from the AUDIT matrix). Every cell without `*` was executed in this run; the ASU cells map to named pytest node ids (see each cell's repro line).\n")

    # Targets provenance
    lines.append("## Targets\n")
    for t in present:
        info = meta["targets"].get(t, TARGETS[t])
        lines.append(f"- **{t}** — {info['name']}. `{info['repo']}` "
                     f"({info.get('ref')}, commit `{info.get('commit')}`), {info['license']}. "
                     f"{info['scope']}")
    lines.append("")

    # Per-cell detail
    lines.append("## Per-cell findings\n")
    for t in present:
        lines.append(f"### {t} — {TARGETS[t]['name']}\n")
        for ab in ATTACK_ORDER:
            r = by.get((t, ab))
            if not r:
                continue
            flags = []
            if r["applicable"]:
                flags.append("applicable")
            else:
                flags.append("n/a")
            flags.append("executed" if r["executed"] else "not-executed")
            sev = f", sev={r['severity']}" if r["severity"] != "none" else ""
            lines.append(f"- **{ab} {ATTACKS[ab]}** — `{r['outcome']}`{sev} "
                         f"({', '.join(flags)}). {r['note']}"
                         + (f"\n  - evidence: `{r['evidence']}`" if r["evidence"] else "")
                         + (f"\n  - repro: `{r['repro']}`" if r["repro"] else ""))
        lines.append("")

    with open(os.path.join(RESULTS, "matrix.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def _print_summary(rows):
    from collections import Counter
    c = Counter(r["outcome"] for r in rows)
    print(f"attacks matrix: {len(rows)} cells -> "
          f"{c['vulnerable']} vulnerable, {c['partial']} partial, "
          f"{c['not_vulnerable']} not-vulnerable, {c['n/a']} n/a")
    for r in rows:
        if r["outcome"] == "vulnerable":
            print(f"  VULN {r['target']}/{r['attack_id']} (sev={r['severity']})")


if __name__ == "__main__":
    run(set(sys.argv[1:]) or None)
