"""Risk policy: allow | deny | challenge (SPEC sections 4 step 5 and 9)."""
from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

from .descriptor import amount_of, iter_paths, iter_urls, recipients

# Reasons that a delegated grant may NOT turn into an allow: a grant was
# signed for "similar" effects within caps, never for unattended (autonomous)
# actions or for crossing the anti-threshold-splitting aggregate.
NON_GRANTABLE_PREFIXES = ("autonomous_origin", "aggregate_", "unknown_tool")

RISK_WEIGHTS = {
    "tool_default_challenge": 20,
    "destructive_class": 40,
    "autonomous_origin": 30,
    "amount_over": 30,
    "first_time_recipient": 25,
    "outside_workspace": 30,
    "aggregate_effects": 30,
    "aggregate_amount": 40,
    "unknown_tool": 50,
    "no_arg_schema": 20,
}


@dataclass
class Decision:
    outcome: str  # allow | deny | challenge
    reasons: List[str] = field(default_factory=list)
    risk: int = 0
    effect_class: Optional[str] = None

    @property
    def grantable(self) -> bool:
        return self.outcome == "challenge" and not any(r.startswith(NON_GRANTABLE_PREFIXES) for r in self.reasons)

    def to_dict(self) -> Dict[str, Any]:
        return {"outcome": self.outcome, "reasons": list(self.reasons), "risk": self.risk,
                "grantable": self.grantable, "effect_class": self.effect_class}


def glob_to_regex(glob: str) -> "re.Pattern[str]":
    """``**`` matches across ``/``; ``*`` and ``?`` do not. ``/x/**`` also
    matches ``/x`` itself; a leading ``**/`` matches any (possibly empty)
    directory prefix."""
    i, out = 0, ["^"]
    while i < len(glob):
        if glob.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif glob.startswith("/**", i) and i + 3 == len(glob):
            out.append("(?:/.*)?")
            i += 3
        elif glob.startswith("**", i):
            out.append(".*")
            i += 2
        elif glob[i] == "*":
            out.append("[^/]*")
            i += 1
        elif glob[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(glob[i]))
            i += 1
    out.append("$")
    return re.compile("".join(out))


def path_matches(path: str, glob: str) -> bool:
    """Deny globs match case-insensitively (case-insensitive file systems such
    as macOS/Windows defaults: ``~/.SSH`` is ``~/.ssh``)."""
    rx = glob_to_regex(glob)
    return bool(rx.match(path) or re.compile(rx.pattern, re.IGNORECASE).match(path))


def host_matches(host: str, pattern: str) -> bool:
    host = host.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        pattern = pattern[2:]
    return host == pattern or host.endswith("." + pattern)


def _in_workspace(p: str, root: str) -> bool:
    root = root.rstrip("/") or "/"
    return p == root or p.startswith(root + "/") or root == "/"


def tool_class(policy: Dict[str, Any], tool: str) -> str:
    spec = policy.get("tools", {}).get(tool)
    return spec["class"] if spec else "admin"


def decide(desc: Dict[str, Any], policy: Dict[str, Any], store: Any = None, user_id: Optional[str] = None,
           now: Optional[int] = None, workspace_root: Optional[str] = None) -> Decision:
    now = int(now if now is not None else time.time())
    tool = desc["tool"]
    cls = desc["effect_class"]
    spec = policy.get("tools", {}).get(tool)
    reasons: List[str] = []

    # -- hard denies ---------------------------------------------------------
    if spec is None:
        if policy.get("unknown_tool", "deny") == "deny":
            return Decision("deny", ["unknown_tool"], 100, cls)
        reasons.append("unknown_tool")
    elif spec.get("default", "challenge") == "deny":
        return Decision("deny", ["tool_denied_by_policy"], 100, cls)
    untyped = spec is not None and "args" not in spec
    if untyped and cls != "read" and policy.get("untyped_tools", "challenge") == "deny":
        return Decision("deny", ["no_arg_schema"], 100, cls)

    deny = policy.get("deny", {}) or {}
    for p in iter_paths(desc):
        for g in deny.get("path_globs", []) or []:
            for candidate in (p["path"], p["resolved_path"]):
                if path_matches(candidate, g):
                    return Decision("deny", [f"path_denied:{g}:{candidate}"], 100, cls)
    hosts = [urlsplit(u).hostname or "" for u in iter_urls(desc)]
    for h in hosts:
        for pat in deny.get("hosts", []) or []:
            if host_matches(h.strip("[]"), pat):
                return Decision("deny", [f"host_denied:{pat}:{h}"], 100, cls)

    # -- default / step-up ---------------------------------------------------
    if spec is not None and spec.get("default", "challenge") == "challenge":
        reasons.append("tool_default_challenge")
    if untyped and cls != "read" and policy.get("untyped_tools", "challenge") == "challenge":
        # D-005 item 4: argument meanings of a tool without a declared schema
        # are guessed from names; never run such an effect silently.
        reasons.append("no_arg_schema")

    su = policy.get("step_up", {}) or {}
    if cls in (su.get("destructive_classes") or []):
        reasons.append(f"destructive_class:{cls}")
    if su.get("autonomous_origin") and desc.get("origin") != "user_turn":
        reasons.append("autonomous_origin")
    amount, currency = amount_of(desc)
    thr = su.get("amount_over")
    if thr is not None and amount is not None and abs(amount) > Decimal(str(thr)):
        reasons.append(f"amount_over:{thr}")
    if su.get("first_time_recipient") and cls in ("send", "pay"):
        seed = set(su.get("known_recipients") or [])
        for r in recipients(desc):
            known = r in seed or (store is not None and user_id is not None and store.is_known_recipient(user_id, r))
            if not known:
                reasons.append(f"first_time_recipient:{r}")
    if su.get("outside_workspace", True) and workspace_root and cls != "read":
        root = os.path.realpath(workspace_root)
        for p in iter_paths(desc):
            if not _in_workspace(p["resolved_path"], root) or not _in_workspace(p["path"], root):
                reasons.append(f"outside_workspace:{p['resolved_path']}")
                break
    agg = su.get("aggregate") or {}
    if agg and cls != "read" and store is not None and user_id is not None:
        window = int(agg.get("window_s", 600))
        recent = [e for e in store.recent_effects(user_id, now - window) if e["effect_class"] != "read"]
        max_effects = agg.get("max_effects")
        if max_effects is not None and len(recent) + 1 > int(max_effects):
            reasons.append(f"aggregate_effects:{len(recent) + 1}>{max_effects}/{window}s")
        max_amount = agg.get("max_amount")
        if max_amount is not None and amount is not None:
            total = sum((Decimal(e["amount"]) for e in recent
                         if e.get("amount") is not None and (e.get("currency") or None) == (currency or None)),
                        Decimal(0))
            if total + abs(amount) > Decimal(str(max_amount)):
                reasons.append(f"aggregate_amount:{total + abs(amount)}>{max_amount}/{window}s")

    risk = sum(RISK_WEIGHTS.get(r.split(":", 1)[0], 10) for r in reasons)
    outcome = "challenge" if reasons else "allow"
    return Decision(outcome, reasons, min(risk, 100), cls)
