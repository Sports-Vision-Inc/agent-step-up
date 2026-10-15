"""Scoped delegated grants ("allow similar for 1h, max N") — property P6.

D-005 items 1 and 5. The grant is BUILT BY THE GATEWAY from the approved
descriptor when the approval is created (``grant_request``); the agent cannot
choose any of its constraints. If the user ticks "grant similar", the
WebAuthn challenge v2 covers ``g = SHA-256(JCS(grant))`` and
``Store.mark_approved`` only accepts a grant byte-identical (same JCS digest)
to that request.

A grant binds EVERY argument of the approved call to its approved value
(``bound_args``), except the arguments it explicitly lists in ``free_args``,
each with a bound:

* the single ``amount`` argument: any value with |amount| <= ``max_amount``
  (the approved amount), same currency, and a running total <= ``max_total_amount``;
* ``text`` arguments (subject, body, memo, ...): any string up to ``max_len``.

Recipients, accounts, paths, urls, argv, flags, ints, enums and structured
values are never free. A later call matches only if it has exactly the same
argument names and types. Matching reads every constraint from the signed
grant itself; use counting and amount accounting are atomic in the store.
"""
from __future__ import annotations

import json
import time
from decimal import Decimal
from typing import Any, Dict, Optional, Tuple

from . import jcs
from .descriptor import _AMOUNT_RE, amount_of, types_of

GRANT_TYPE = "asu.grant"
GRANT_VERSION = 2
NON_GRANTABLE_CLASSES = ("exec", "admin")
FREE_TYPES = ("amount", "text")


def build_grant_request(desc: Dict[str, Any], policy: Dict[str, Any], decision: Any,
                        now: Optional[int] = None) -> Optional[Dict[str, Any]]:
    """Constraints the user may delegate, built only from the descriptor and
    the policy; None if no grant may be offered."""
    gp = policy.get("grants", {}) or {}
    max_uses = int(gp.get("max_uses", 0))
    ttl = int(gp.get("max_ttl_s", 0))
    if max_uses <= 0 or ttl <= 0 or not decision.grantable:
        return None
    if desc["effect_class"] in NON_GRANTABLE_CLASSES:
        return None
    now = int(now if now is not None else time.time())
    types = types_of(desc)
    amount, currency = amount_of(desc)
    max_text = int(gp.get("max_text_len", 4000))
    bound: Dict[str, Any] = {}
    free: Dict[str, Any] = {}
    for k in sorted(desc.get("args", {})):
        t = types.get(k, "json")
        v = desc["args"][k]
        if t == "amount" and isinstance(v, str) and amount is not None:
            free[k] = {"type": "amount", "max": str(abs(amount))}
        elif t == "text" and isinstance(v, str):
            free[k] = {"type": "text", "max_len": max(max_text, len(v))}
        else:
            bound[k] = v
    max_total = None
    if amount is not None:
        cap = gp.get("max_total_amount")
        max_total = str(Decimal(str(cap))) if cap is not None else str(abs(amount) * max_uses)
    return {
        "v": GRANT_VERSION,
        "type": GRANT_TYPE,
        "principal": desc["principal"],
        "session_id": desc["session_id"],
        "agent_id": desc["agent_id"],
        "tool": desc["tool"],
        "effect_class": desc["effect_class"],
        "origin": desc["origin"],
        "arg_types": {k: types.get(k, "json") for k in sorted(desc.get("args", {}))},
        "bound_args": bound,
        "free_args": free,
        "target": desc.get("target"),
        "max_amount": str(abs(amount)) if amount is not None else None,
        "currency": currency,
        "max_total_amount": max_total,
        "max_uses": max_uses,
        "issued_at": now,
        "not_after": now + ttl,
    }


def _same(a: Any, b: Any) -> bool:
    try:
        return jcs.canonicalize(a) == jcs.canonicalize(b)
    except Exception:
        return False


def grant_matches(grant: Dict[str, Any], desc: Dict[str, Any], now: Optional[int] = None) -> Tuple[bool, str]:
    now = int(now if now is not None else time.time())
    if grant.get("type") != GRANT_TYPE or grant.get("v") != GRANT_VERSION:
        return False, "bad_grant"
    for k in ("principal", "session_id", "agent_id", "tool", "effect_class", "origin"):
        if grant.get(k) != desc.get(k):
            return False, f"grant_{k}_mismatch"
    if now >= int(grant.get("not_after", 0)):
        return False, "grant_expired"
    args = desc.get("args", {}) or {}
    bound = grant.get("bound_args") or {}
    free = grant.get("free_args") or {}
    if not isinstance(bound, dict) or not isinstance(free, dict) or set(bound) & set(free):
        return False, "bad_grant"
    # exactly the same argument names and types as the approved call
    if set(args) != set(bound) | set(free):
        return False, "grant_args_mismatch"
    if not _same(types_of(desc), grant.get("arg_types")):
        return False, "grant_arg_types_mismatch"
    for k, v in bound.items():
        if not _same(args[k], v):
            return False, f"grant_bound_arg_mismatch:{k}"
    for k, rule in free.items():
        v = args[k]
        kind = rule.get("type") if isinstance(rule, dict) else None
        if kind == "amount":
            if not (isinstance(v, str) and _AMOUNT_RE.match(v)):
                return False, "grant_amount_invalid"
            if abs(Decimal(v)) > Decimal(str(rule.get("max"))):
                return False, "grant_amount_over"
        elif kind == "text":
            if not isinstance(v, str) or len(v) > int(rule.get("max_len", 0)):
                return False, "grant_text_over"
        else:
            return False, "bad_grant"
    amount, currency = amount_of(desc)
    if grant.get("max_amount") is None:
        if amount is not None:
            return False, "grant_has_no_amount"
    else:
        if amount is None or currency != grant.get("currency"):
            return False, "grant_currency_mismatch"
        if abs(amount) > Decimal(grant["max_amount"]):
            return False, "grant_amount_over"
    return True, "ok"


def try_use_grant(store: Any, desc: Dict[str, Any], now: Optional[int] = None) -> Optional[str]:
    """Atomically consume one use of a matching grant; returns grant id."""
    now = int(now if now is not None else time.time())
    amount, _ = amount_of(desc)
    with store.tx() as c:
        rows = c.execute(
            "SELECT id, grant_json, uses, max_uses, amount_used, not_after FROM grants WHERE session_id=? AND tool=?"
            " AND revoked=0 AND not_after>? AND uses<max_uses ORDER BY created_at",
            (desc["session_id"], desc["tool"], now)).fetchall()
        for r in rows:
            g = json.loads(r["grant_json"])
            ok, _why = grant_matches(g, desc, now)
            if not ok:
                continue
            # caps come from the signed grant; the row's max_uses/not_after are
            # copies and must not exceed it
            if r["uses"] >= min(int(g["max_uses"]), int(r["max_uses"])):
                continue
            new_total = Decimal(r["amount_used"]) + (abs(amount) if amount is not None else Decimal(0))
            if g.get("max_total_amount") is not None and new_total > Decimal(g["max_total_amount"]):
                continue
            cur = c.execute("UPDATE grants SET uses=uses+1, amount_used=? WHERE id=? AND uses=? AND uses<max_uses",
                            (str(new_total), r["id"], r["uses"]))
            if cur.rowcount == 1:
                store.log("grant_used", {"grant_id": r["id"], "uses": r["uses"] + 1, "amount_used": str(new_total)})
                return r["id"]
    return None
