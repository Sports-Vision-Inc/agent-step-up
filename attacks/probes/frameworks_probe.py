"""AB-family mapping for in-process agent frameworks.

We do NOT re-probe these runtimes: AUDIT already measures their SPEC-3 properties
(P1..P7) in audit/results/matrix.json (owned by AUDIT; we only read it). This
probe maps the relevant AB attacks onto AUDIT's findings so the attack matrix is
complete without duplicating work. Each row cites the AUDIT evidence it derives
from.
"""
from __future__ import annotations
import json
import os

from attacks.common import row, write_evidence, VULN, NOT_VULN, PARTIAL, NA
from attacks.targets import REPO_ROOT

T = "frameworks"
_AUDIT_MATRIX = os.path.join(REPO_ROOT, "audit", "results", "matrix.json")

# AB attack -> (AUDIT test key it corresponds to, human note)
_MAP = {
    "AB10": ("T2_P2_effect_binding",
             "Post-approval substitution == P2 effect-binding. AUDIT reproduced Loopjacking-class "
             "substitution (FAIL) in langgraph and agno; PASS in openai-agents/google-adk/"
             "pydantic-ai. crewai/autogen/mcp have no effect-bound approval (their primitive is "
             "feedback/input)."),
    "AB1":  ("T4_P4_trusted_rendering",
             "Amount ambiguity requires a trusted renderer to disambiguate; AUDIT finds no framework "
             "renderer (PART) except where noted, so a human sees agent-structured values."),
}


def _load_audit():
    if not os.path.isfile(_AUDIT_MATRIX):
        return None
    try:
        return json.load(open(_AUDIT_MATRIX, encoding="utf-8"))
    except Exception:
        return None


def run():
    rows = []
    audit = _load_audit()
    if audit is None:
        rows.append(row(T, "AB10", applicable=True, executed=False, outcome=NA,
                        note="audit/results/matrix.json not present; run `python audit/run_all.py` first."))
        return rows

    # Index AUDIT rows by (runtime, test).
    idx = {}
    for r in audit:
        idx.setdefault(r["test"], []).append(r)

    ev = write_evidence("frameworks_from_audit.log",
                        "Derived from audit/results/matrix.json. Counts per AUDIT test:\n" +
                        "\n".join(f"{k}: " + ", ".join(f"{x['runtime']}={x['outcome']}" for x in v)
                                  for k, v in sorted(idx.items())))

    # AB10 post-approval substitution across frameworks, from P2 results.
    p2 = idx.get("T2_P2_effect_binding", [])
    fails = [x["runtime"] for x in p2 if x["outcome"] == "fail"]
    passes = [x["runtime"] for x in p2 if x["outcome"] == "pass"]
    rows.append(row(T, "AB10", applicable=True, executed=False,
                    outcome=VULN if fails else NOT_VULN,
                    severity="high" if fails else "none",
                    note=f"Per AUDIT P2 (effect-binding): substitution SUCCEEDS against {fails or 'none'}; "
                         f"blocked for {passes}. These are AUDIT's executed probes "
                         f"(we read, not re-run). " + _MAP['AB10'][1],
                    evidence=ev))

    # AB independence (P1) is the paper's motivating observation for in-process SDKs.
    p1 = idx.get("T1_P1_agent_independence", [])
    p1_fail = [x["runtime"] for x in p1 if x["outcome"] == "fail"]
    rows.append(row(T, "AB9", applicable=True, executed=False, outcome=VULN if p1_fail else NOT_VULN,
                    severity="high" if p1_fail else "none",
                    note=f"Ceremony control / P1: AUDIT finds the approval callback is in-process and "
                         f"agent-reachable (FAIL) for {p1_fail}. The agent controls the ceremony surface "
                         f"itself, which is the strongest form of ceremony control. OpenClaw PART.",
                    evidence=ev))

    # AB5/AB6 rendering, from P4.
    p4 = idx.get("T4_P4_trusted_rendering", [])
    p4_fail = [x["runtime"] for x in p4 if x["outcome"] == "fail"]
    p4_part = [x["runtime"] for x in p4 if x["outcome"] in ("part", "partial")]
    rows.append(row(T, "AB6", applicable=True, executed=False,
                    outcome=VULN if p4_fail else PARTIAL,
                    severity="medium",
                    note=f"Trusted rendering / P4: FAIL (human reacts to model text) for {p4_fail}; "
                         f"PART (structured args but no renderer/untrusted-text box) for {p4_part}. "
                         "Non-injective display / label spoofing is possible wherever there is no "
                         "trusted renderer.",
                    evidence=ev))
    rows.append(row(T, "AB5", applicable=True, executed=False,
                    outcome=VULN if p4_fail else PARTIAL, severity="medium",
                    note="Same P4 basis: no framework-owned label surface, so agent-chosen names/text "
                         "reach the human unmediated where P4 is FAIL/PART.", evidence=ev))

    # AB1 amount ambiguity depends on a trusted renderer, which these runtimes lack.
    rows.append(row(T, "AB1", applicable=True, executed=False, outcome=PARTIAL, severity="low",
                    note=_MAP["AB1"][1] + " No framework sums or re-types amounts, but with no trusted "
                         "renderer a human cannot reliably disambiguate agent-structured amount text.",
                    evidence=ev))

    # P5 non-repudiation fails everywhere -> relevant to AB8 (no signed challenge to be ambiguous about).
    rows.append(row(T, "AB8", applicable=False, executed=False, outcome=NA,
                    note="No runtime produces a signed approval challenge (AUDIT P5 FAIL everywhere), so "
                         "there is no concatenated challenge to be non-injective. The gap is the absence "
                         "of binding, not its encoding."))

    for ab, why in [
        ("AB2", "No recipient/target-typed approval descriptor in these runtimes (see AUDIT P4)."),
        ("AB3", "No ASU-style delegated grant across these runtimes (AUDIT P6 out of scope; OpenClaw "
                "allow-always is covered under the openclaw target)."),
        ("AB4", "Padding/blank-glyph requires a renderer; absent here (covered by P4 / AB6)."),
        ("AB7", "No passkey enrollment surface in these runtimes."),
        ("AB11", "AUDIT P7 (flood) FAILs for SDKs; captured there, no per-run flood primitive to map "
                 "cleanly to one AB cell beyond P1."),
        ("AB12", "No aggregate monetary limit in these runtimes."),
    ]:
        rows.append(row(T, ab, applicable=False, executed=False, outcome=NA, note=why))
    # Derived, not executed by this suite: AUDIT executed the probes; we only map
    # their results. The grid marks these cells with '*'.
    for r in rows:
        if r["outcome"] != NA and not r["note"].startswith("DERIVED"):
            r["note"] = "DERIVED from audit/results/matrix.json (AUDIT executed; not re-run here). " + r["note"]
    return rows
