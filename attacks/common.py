"""Shared helpers for attack probes: row construction + evidence logging."""
from __future__ import annotations
import json
import os
import subprocess
import time

ATTACKS_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(ATTACKS_DIR, "results")
EVIDENCE = os.path.join(RESULTS, "evidence")

# Canonical outcome vocabulary.
VULN = "vulnerable"
NOT_VULN = "not_vulnerable"
PARTIAL = "partial"
NA = "n/a"
OUTCOMES = {VULN, NOT_VULN, PARTIAL, NA}

SEV = {"critical", "high", "medium", "low", "info", "none"}


def git_commit(repo_root: str) -> str | None:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repo_root,
            capture_output=True, text=True, timeout=10)
        if out.returncode == 0:
            return out.stdout.strip()
    except Exception:
        pass
    return None


def tree_state(repo_root: str) -> dict:
    """Commit + dirtiness of the working tree, for stamping results.

    ``stamp`` is ``git rev-parse HEAD``, with ``-dirty`` appended if
    ``git status --porcelain`` reports any change (tracked or untracked).
    ``asu_dirty`` records whether any of those changes is under asu/ (the code
    the ASU column measures).
    """
    head = git_commit(repo_root) or "unknown"
    paths = []
    try:
        out = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=repo_root,
                             capture_output=True, text=True, timeout=30)
        if out.returncode == 0:
            paths = [ln[3:] for ln in out.stdout.splitlines() if ln.strip()]
    except Exception:
        pass
    dirty = bool(paths)
    return {
        "commit": head,
        "dirty": dirty,
        "stamp": head + ("-dirty" if dirty else ""),
        "asu_dirty": any(p.startswith("asu/") for p in paths),
        "dirty_paths": sorted(paths),
    }


def write_evidence(name: str, text: str) -> str:
    os.makedirs(EVIDENCE, exist_ok=True)
    path = os.path.join(EVIDENCE, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    # Return a repo-relative path for the matrix.
    return os.path.relpath(path, os.path.dirname(ATTACKS_DIR))


def row(target, attack_id, *, applicable, executed, outcome, severity="none",
        evidence="", repro="", note=""):
    assert outcome in OUTCOMES, outcome
    assert severity in SEV, severity
    return {
        "target": target,
        "attack_id": attack_id,
        "applicable": bool(applicable),
        "executed": bool(executed),
        "outcome": outcome,
        "severity": severity,
        "evidence": evidence,
        "repro": repro,
        "note": note,
        "ts": time.time(),
    }
