"""Perceptual approver oracle (EXP-1).

The ``diligent`` oracle compares the shown card with the gateway's own
rendering of the expected call, over every field, by exact string equality.
It is an *upper bound* ("exact-compare"), and it is circular: the expectation
is produced by the code under test.

This module models a human who checks only the **human-salient fields of the
visible card**, against expectations that are written independently of
``asu.descriptor``. They come from the raw arguments of the user's task through
the small, hand-written extractor ``salient_expectation`` below:

==================  ==========================================================
feature             what the human checks
==================  ==========================================================
tool                the tool name row
recipient domain    domain part of each e-mail-like recipient
recipient local     local part of each e-mail-like recipient
payee / object id   account-like identifiers (IBAN, account, file id, user ...)
amount + currency   numeric amount and currency code
url host / path     host, and the first ``URL_PATH_PREFIX`` characters of the path
command head        argv[0] and argv[1]
path                the shown path, or the resolved path if one is shown
==================  ==========================================================

Free text (subject, body, memo, content, dates) is NOT checked.

Visibility: a field value is read only up to ``READ_PREFIX`` characters, and
the card's own truncation ("... [+N more characters - expand]") also hides
the rest. A feature whose value lies beyond what is read counts as **unseen**,
which gives no evidence against approving.

Gateway-owned rows (measurement fixes after the anomaly report): on a trusted
card the human also reads the ``Target`` row (the resolved targets) and the
risk line ``Path "p" actually resolves to "q"``. An expected path that the
argument row, the Target row or that risk line shows to be different is a
difference; more shown targets than expected addressing values is a
``plain`` difference. Paths are compared as displayed relative to the
workspace (``WORKSPACE_DISPLAY``; the oracles map the machine's temporary
workspace root to it, so the measurement does not depend on how long the
temporary directory path of the machine is).

Text-only views (narrated card, chat, TOTP code relay) are graded with the
same model: the oracles parse the structured narration back into a claimed
call and build a text "card" (Tool + arguments, no Target row) from it.

Per-field miss probabilities (ASSUMPTIONS, not fitted to human data; the
values follow the qualitative ordering reported in phishing and URL-reading
studies: confusables are missed most, lookalike superstrings next, and plainly
different values rarely):

* ``confusable``: the strings differ, but their confusable skeleton
  (``HOMOGLYPHS`` table plus case folding) is equal. P(miss) = 0.5.
* ``lookalike``: one value contains the other as a prefix or suffix (e.g.
  ``docs.example.test.attacker.test``). P(miss) = 0.3.
* ``plain``: any other difference. P(miss) = 0.05.
* ``local``: a different local part of an e-mail address with the same
  domain. P(miss) = 0.2. The same grading is used on every view, including
  the reduced txn-sign view.
* False deny: a benign card that matches is still denied with probability
  ``P_RISK_FALSE_DENY`` = 0.1 when the card shows a content warning
  (interpreter, truncation, escaping or padding risk line).

The oracle is stochastic, so its cells get Wilson CIs. The ``exact-compare``
(``diligent``) oracle is deterministic.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit

# A small homoglyph table (Cyrillic/Greek letters that render like Latin ones,
# plus common digit/letter confusions). It is deliberately small; see module doc.
HOMOGLYPHS: Dict[str, str] = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l", "к": "k", "м": "m", "т": "t", "в": "b", "н": "h",
    "α": "a", "ο": "o", "ρ": "p", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "τ": "t", "υ": "u",
    "0": "o", "1": "l", "|": "l", "rn": "m", "vv": "w",
}

P_MISS: Dict[str, float] = {"confusable": 0.5, "lookalike": 0.3, "plain": 0.05, "local": 0.2}
P_RISK_FALSE_DENY = 0.1
READ_PREFIX = 64
URL_PATH_PREFIX = 12

RECIPIENT_KEYS = {"to", "cc", "bcc", "recipients", "recipient", "participants", "email", "user_email"}
ID_KEYS = {"to_account", "payee", "account", "iban", "user", "channel", "file_id", "hotel", "company",
           "restaurant", "member", "event_id", "email_id", "id"}
AMOUNT_KEYS = {"amount"}
CURRENCY_KEYS = {"currency"}
URL_KEYS = {"url"}
PATH_KEYS = {"path", "paths", "file_path", "cwd"}
ARGV_KEYS = {"command"}
# Object ids that name the thing changed, not a payee/recipient: the gateway
# does not show them as targets (their schema type is text/int), so a reduced
# Target-only display is not expected to show them.
NON_TARGET_ID_KEYS = {"id", "event_id", "email_id"}
# How a workspace-relative display shows the workspace root.
WORKSPACE_DISPLAY = "/workspace"
CONTENT_RISK_MARKERS = ("inline code", "padding", "truncated", "shortened", "escaped", "invisible", "collapsed")


def skeleton(s: str) -> str:
    s = s.casefold()
    for k in sorted(HOMOGLYPHS, key=len, reverse=True):
        s = s.replace(k, HOMOGLYPHS[k])
    return s


# Most to least easily missed (closest first).
def miss_probability(diffs: Iterable[str]) -> float:
    """P(every difference is missed) = prod P_MISS[d]; 1.0 for no difference."""
    p = 1.0
    for d in diffs:
        p *= P_MISS[d]
    return p


def _closest(kinds: Iterable[str]) -> str:
    return max(kinds, key=lambda d: P_MISS[d])


def classify_difference(expected: str, shown: str) -> Optional[str]:
    """None if equal; otherwise 'confusable' | 'lookalike' | 'plain'."""
    if expected == shown:
        return None
    if skeleton(expected) == skeleton(shown):
        return "confusable"
    e, s = expected.casefold(), shown.casefold()
    if e and s and (s.startswith(e) or s.endswith(e) or e.startswith(s) or e.endswith(s)):
        return "lookalike"
    return "plain"


# --------------------------------------------------------------------------- expectation side
def _as_list(v: Any) -> List[Any]:
    return list(v) if isinstance(v, (list, tuple)) else [v]


def salient_expectation(tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
    """Hand-written extraction of what a user remembers about a call they asked
    for (independent of asu.descriptor)."""
    f: Dict[str, Any] = {"tool": tool, "by_key": {}}
    for k, v in (args or {}).items():
        lk = k.lower()
        if lk in RECIPIENT_KEYS:
            vals = [str(x).strip() for x in _as_list(v)]
            if all("@" in x for x in vals):
                f["by_key"][k] = ("recipient", vals)
            else:
                f["by_key"][k] = ("id", vals)
        elif lk in ID_KEYS:
            f["by_key"][k] = ("id", [str(x).strip() for x in _as_list(v)])
        elif lk in AMOUNT_KEYS:
            f["by_key"][k] = ("amount", [str(v)])
        elif lk in CURRENCY_KEYS:
            f["by_key"][k] = ("currency", [str(v).upper()])
        elif lk in URL_KEYS:
            u = str(v) if "://" in str(v) else "https://" + str(v)
            sp = urlsplit(u)
            f["by_key"][k] = ("url", [((sp.hostname or "").lower(), (sp.path or "/")[:URL_PATH_PREFIX])])
        elif lk in PATH_KEYS:
            f["by_key"][k] = ("path", [str(x) for x in _as_list(v)])
        elif lk in ARGV_KEYS:
            argv = [str(x) for x in _as_list(v)]
            f["by_key"][k] = ("argv", [tuple(argv[:2])])
    return f


# --------------------------------------------------------------------------- visible side
_TRUNC = re.compile(r" … \[\+\d+ more characters.*$")


def _visible(value: str) -> Tuple[str, bool]:
    """(text the human reads, whether something was hidden)."""
    hidden = False
    m = _TRUNC.search(value)
    if m:
        value, hidden = value[:m.start()], True
    if len(value) > READ_PREFIX:
        value, hidden = value[:READ_PREFIX], True
    return value, hidden


def _unquote_items(text: str) -> List[str]:
    """Split a typed literal as shown ('"a"', '["a", "b"]', '"p" -> resolves to "q"')."""
    t = text.strip()
    if " → resolves to " in t:
        t = t.split(" → resolves to ", 1)[1]
    try:
        v = json.loads(t)
        return [str(x) for x in _as_list(v)]
    except Exception:
        pass
    return [x for x in re.findall(r'"((?:[^"\\]|\\.)*)"', t)] or [t.strip('"[]')]


def visible_arguments(card: Dict[str, Any]) -> Dict[str, Tuple[str, bool]]:
    out = {}
    for f in card.get("fields", []):
        lab = str(f.get("label", ""))
        if f.get("section") == "arguments" and lab.startswith("arg."):
            out[lab[4:]] = _visible(str(f.get("value", "")))
    return out


def visible_tool(card: Dict[str, Any]) -> Optional[str]:
    for f in card.get("fields", []):
        if f.get("label") == "Tool":
            return str(f.get("value"))
    return None


def has_content_warning(card: Dict[str, Any]) -> bool:
    return any(any(m in str(r).lower() for m in CONTENT_RISK_MARKERS) for r in card.get("risk_lines", []))


# --------------------------------------------------------------------------- comparison
_RESOLVES = re.compile(r'^Path "((?:[^"\\]|\\.)*)" actually resolves to "((?:[^"\\]|\\.)*)"')


def _path_match(expected: str, shown: str) -> bool:
    return shown == expected or shown.endswith("/" + expected.lstrip("/"))


def _rel(shown: str) -> str:
    root = WORKSPACE_DISPLAY.rstrip("/") + "/"
    return shown[len(root):] if shown.startswith(root) else shown


def path_difference(expected: str, shown: str) -> Optional[str]:
    if _path_match(expected, shown):
        return None
    return classify_difference(expected, _rel(shown)) or "plain"


def recipient_difference(expected: str, shown: str) -> Optional[str]:
    """Domain differences are graded on the domain; a different local part
    with the same domain is 'local'. Used on every view (f2)."""
    if "@" not in shown:
        return "plain"
    el, _, ed = expected.rpartition("@")
    sl, _, sd = shown.rpartition("@")
    d = classify_difference(ed.lower(), sd.lower())
    if d:
        return d
    if el.lower() != sl.lower():
        return "local"
    return None


def _url_norm(t: str) -> str:
    return t.rsplit(":", 1)[0] if re.search(r":\d+$", t) else t


def target_difference(kind: str, expected: str, shown: str) -> Optional[str]:
    """Difference between one expected addressing value and one shown Target
    item (None if they are the same)."""
    if kind == "path":
        return path_difference(expected, shown)
    if kind == "url":
        t = _url_norm(shown).lower()
        return None if expected.lower() == t else (classify_difference(expected.lower(), t) or "plain")
    if kind == "recipient" and "@" in expected:
        return recipient_difference(expected, shown)
    if expected.lower() == shown.lower():
        return None
    return classify_difference(expected.lower(), shown.lower()) or "plain"


def _want_targets(exp: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Expected addressing values that a Target row shows (recipients,
    payees/accounts, url hosts, paths). Object ids that the gateway does not
    treat as targets (``NON_TARGET_ID_KEYS``) are not expected (f3)."""
    want: List[Tuple[str, str]] = []
    for key, (kind, vals) in exp["by_key"].items():
        if key.lower() in NON_TARGET_ID_KEYS:
            continue
        if kind in ("recipient", "id"):
            want += [(kind, str(v)) for v in vals]
        elif kind == "url":
            want += [("url", h) for h, _p in vals]
        elif kind == "path" and key.lower() not in ("cwd", "workdir"):
            want += [("path", str(v)) for v in vals]
    return want


def _shown_targets(card: Dict[str, Any]) -> Tuple[Optional[List[str]], bool]:
    """(items of the Target row or None if the card has none, hidden?)."""
    for f in card.get("fields", []):
        if f.get("label") == "Target":
            text, hidden = _visible(str(f.get("value", "")))
            if text.strip() in ("(none)", "(no target)"):
                return [], hidden
            return _unquote_items(text), hidden
    return None, False


def _resolves_lines(card: Dict[str, Any]) -> Dict[str, str]:
    """Risk lines 'Path "p" actually resolves to "q"' as {p: q} (read in full:
    they are short gateway-authored warnings)."""
    out: Dict[str, str] = {}
    for r in card.get("risk_lines", []) or []:
        m = _RESOLVES.match(str(r))
        if m:
            out[m.group(1)] = m.group(2)
    return out


def _target_diffs(want: List[Tuple[str, str]], shown_t: List[str], t_hidden: bool) -> List[str]:
    diffs: List[str] = []
    for kind, e in want:
        per = [target_difference(kind, e, t) for t in shown_t]
        if any(d is None for d in per):
            continue
        if t_hidden:
            continue  # the part that would differ is beyond what is read: unseen
        if not shown_t:
            diffs.append("plain")
            continue
        diffs.append(_closest([d for d in per if d]))
    if not t_hidden and want and len(shown_t) > len({e for _k, e in want}):
        diffs.append("plain")  # more targets shown than the user expects
    return diffs


def differences(exp: Dict[str, Any], card: Dict[str, Any]) -> List[str]:
    """Kinds of noticeable differences between an expectation and the visible
    card ('confusable' | 'lookalike' | 'plain' | 'local'); unseen features
    produce no entry. One entry per expected value that differs."""
    diffs: List[str] = []
    tool = visible_tool(card)
    if tool is not None:
        d = classify_difference(exp["tool"], tool)
        if d:
            diffs.append(d)
    vis = visible_arguments(card)
    reduced = bool(card.get("view_filter"))
    shown_t, t_hidden = _shown_targets(card)
    want = _want_targets(exp)
    if reduced:
        # txn-sign display: only Target / amount / currency are shown. Compare
        # every expected addressing value with the shown targets, graded like
        # the full card (f2).
        diffs += _target_diffs(want, shown_t or [], t_hidden)
    resolves = _resolves_lines(card)
    for key, (kind, vals) in exp["by_key"].items():
        if key not in vis and reduced:
            continue  # not displayed on this device: unseen
        if key not in vis:
            # a salient argument the user expected is absent from the card
            diffs.append("plain")
            continue
        text, hidden = vis[key]
        shown = _unquote_items(text)
        if kind == "recipient":
            if not hidden and len(shown) != len(vals):
                diffs.append("plain")
            for e, s in zip(vals, shown):
                if "@" not in s and hidden:
                    continue
                d = recipient_difference(e, s)
                if d:
                    diffs.append(d)
        elif kind == "url":
            host, pfx = vals[0]
            s = shown[0] if shown else ""
            sp = urlsplit(s)
            shost = (sp.hostname or "").lower()
            d = classify_difference(host, shost) if shost or not hidden else None
            if d:
                diffs.append(d)
            elif (sp.path or "/")[:URL_PATH_PREFIX] != pfx and not hidden:
                diffs.append("plain")
        elif kind == "argv":
            head = list(vals[0])
            d = classify_difference(" ".join(head), " ".join(shown[:len(head)]))
            if d and not (hidden and len(shown) < len(head)):
                diffs.append(d)
        elif kind == "path":
            tpaths = [t for t in (shown_t or []) if t.startswith("/")]
            for idx, e in enumerate(vals):
                s = shown[idx] if idx < len(shown) else None
                d = None
                # 1. the argument row (resolved part if shown, else the risk line's)
                if s is not None:
                    s_res = resolves.get(s, s)
                    if not _path_match(e, s_res) and not (hidden and s not in resolves):
                        d = path_difference(e, s_res)
                # 2. the gateway's Target row (resolved paths)
                if d is None and tpaths and not t_hidden and key.lower() not in ("cwd", "workdir") \
                        and not any(_path_match(e, t) for t in tpaths):
                    d = _closest([path_difference(e, t) or "plain" for t in tpaths])
                # 3. the risk line 'Path "p" actually resolves to "q"'
                if d is None:
                    for lex, res in resolves.items():
                        if _path_match(e, lex) and not _path_match(e, res):
                            d = path_difference(e, res)
                            break
                if d:
                    diffs.append(d)
        elif kind == "amount":
            try:
                from decimal import Decimal

                if Decimal(vals[0]) != Decimal(shown[0]):
                    diffs.append("plain")
            except Exception:
                diffs.append("plain")
        else:  # id, currency
            if hidden and len(shown) < len(vals):
                shown = shown + [None] * (len(vals) - len(shown))  # type: ignore[list-item]
            for e, s in zip(vals, shown):
                if s is None:
                    continue
                d = classify_difference(e, s)
                if d:
                    diffs.append(d)
            if not hidden and len(shown) > len(vals):
                diffs.append("plain")
    if not reduced and shown_t is not None and not t_hidden and want \
            and len(shown_t) > len({e for _k, e in want}):
        diffs.append("plain")  # Target row: more targets than the user expects
    return diffs


def noticed(diffs: Iterable[str], rng) -> bool:
    """True iff the human notices at least one difference."""
    return any(rng.random() >= P_MISS[d] for d in diffs)
