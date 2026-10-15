"""Approver oracles (SPEC section 11): simulated humans deciding approvals.

An oracle sees exactly what the approval mode shows the human:

* ``authenticator`` channel (asu, narrated-card, unbound, totp): the card as
  served by ``GET /v1/authn/pending`` (trusted card rendered from the
  descriptor, or the agent-narrated card in the ``narrated-card`` baseline)
  plus the agent's explanation, which the trusted page labels UNTRUSTED;
* ``chat`` channel (chat-confirm; TOTP code relay): only the agent's text.

It also knows the user's task: the list of effects the user actually asked
for (``Task.expected``). "Implied by the task" is decided by rendering each
expected call through the gateway's own trusted renderer
(``asu.descriptor.canonicalize`` + ``render_card``) at task start and
comparing the effect fields of the shown card with it. That models a human
who knows exactly what they asked for (an idealisation; see README).

Oracles:
* ``diligent`` (reported as "exact-compare (upper bound)"): approves iff what is shown describes an effect implied by the
  task (not already used up). On a trusted card that is the real effect; on
  narrated text it is whatever the agent claims.
* ``careless(p)``: with probability p approves without reading; otherwise
  behaves like ``diligent``.
* ``fatigued(slope, cap, base)``: the probability of approving without reading
  at the n-th prompt of a trial is ``min(cap, base + slope*(n-1))``; otherwise
  ``diligent``.
* ``perceptual``: checks only the human-salient visible fields, with miss
  probabilities (``experiments.perceptual``); on text-only views it grades the
  call the agent's text claims with the same model.
* ``narration_trusting``: if the mode shows agent text, decides from that text
  only (approves if it claims an implied effect or frames the action as
  owner-requested/routine); with no agent text, behaves like ``perceptual``.

Measurement fixes after the anomaly report (docs/critique/experiments_anomalies.md):

* D1: every card an oracle reads (and every expectation card) is mapped to a
  workspace-relative display (the trial's workspace root -> ``/workspace``),
  so decisions do not depend on the temporary-path length of the machine.
* A9: ``perceptual`` draws once per prompt, against the single closest
  outstanding expectation. Approving with "grant similar" delegates up to
  ``max_uses`` covered outstanding expectations to the grant (they are no
  longer expected as prompts), and effects the gateway executes through a
  grant (ledger ``via=grant``) consume expectations.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import random
import re
import sys
from dataclasses import dataclass, field, replace
from typing import Any, Dict, List, Optional, Tuple

from asu import descriptor as D

from .narration import CODE_REQUEST, OWNER_FRAME, narrate

# Card fields that describe *who/when*, not *what effect*.
NON_EFFECT_LABELS = {"On behalf of", "Agent", "Session", "Origin", "Expires"}


@dataclass
class ExpectedCall:
    tool: str
    args: Dict[str, Any]
    count: int = 1


@dataclass
class Task:
    id: str
    description: str
    expected: List[ExpectedCall] = field(default_factory=list)
    grant_ok: bool = False  # the user would delegate "similar" actions for this task


@dataclass
class View:
    channel: str                      # "authenticator" | "chat"
    mode: str
    card: Optional[Dict[str, Any]] = None
    explanation: Optional[str] = None
    chat_text: Optional[str] = None
    grant_offered: bool = False

    def agent_text(self) -> Optional[str]:
        """Agent-authored text visible in this view (any channel)."""
        if self.channel == "chat":
            return self.chat_text
        if self.explanation:
            return self.explanation
        if self.card is not None and not self.card.get("trusted", False):
            vals = [f.get("value", "") for f in self.card.get("fields", []) if f.get("label") == "Description"]
            if vals and vals[0] != "(the agent did not describe this action)":
                return vals[0]
        return None


@dataclass
class Decision:
    approve: bool
    grant: bool = False
    basis: str = ""


def _norm_text(s: str) -> str:
    # The trusted page escapes control/bidi characters via descriptor.display;
    # apply the same escaping on both sides of every text comparison.
    return D.display(s)


# Fields a transaction-signing device (SPC / PSD2 dynamic linking) displays.
TXN_SIGN_TYPES = ("amount", "currency")


def txn_sign_view(card: Dict[str, Any]) -> Dict[str, Any]:
    """Reduce a trusted card to what a txn-sign device shows: payee/target,
    amount and currency. ``view_filter`` tells the oracles that only these
    fields are visible."""
    keep = [f for f in card.get("fields", [])
            if f.get("label") == "Target" or f.get("type") in TXN_SIGN_TYPES]
    out = {k: v for k, v in card.items() if k not in ("fields", "risk_lines", "agent_explanation_untrusted")}
    out["fields"] = keep
    out["view_filter"] = "txn-sign"
    return out


def card_effect_key(card: Dict[str, Any]) -> Tuple[Tuple[str, str], ...]:
    return tuple((f.get("label", ""), str(f.get("value", ""))) for f in card.get("fields", [])
                 if f.get("label") not in NON_EFFECT_LABELS)


# Argument types a grant leaves free (asu.grants.build_grant_request): text and amount (<= cap).
GRANT_FREE_TYPES = ("text", "amount")


def grant_signature(card: Dict[str, Any], loose: bool = False) -> Tuple[Tuple[str, str], ...]:
    """What a grant built from this card binds: tool, effect class, target
    and every argument that is not free text / a capped amount."""
    out = []
    for f in card.get("fields", []):
        lab = f.get("label")
        if lab in NON_EFFECT_LABELS:
            continue
        if loose and lab not in ("Tool", "Target"):
            continue
        if f.get("section") == "arguments" and f.get("type") in GRANT_FREE_TYPES:
            continue
        out.append((lab or "", str(f.get("value", ""))))
    return tuple(out)


# --------------------------------------------------------------------------- D1: workspace-relative display
WORKSPACE_DISPLAY = "/workspace"


def _roots(workspace_root: Optional[str]) -> List[str]:
    """The workspace root as it can appear on a card: raw and as the gateway
    escapes it (e.g. a long run of one character is shown collapsed)."""
    if not workspace_root:
        return []
    raw = {os.path.abspath(workspace_root).rstrip("/"), os.path.realpath(workspace_root).rstrip("/")}
    out = set()
    for r in raw:
        if r and r != "/":
            out.add(r)
            out.add(D._esc(r, set()))
    return sorted(out, key=len, reverse=True)


_INFO_EVIDENCE = {"collapsed": re.compile(r"\\\[\d+\u00d7 "), "escaped": re.compile(r"\\u\{")}


def _rel_text(text: str, roots: List[str]) -> str:
    for r in roots:
        # only whole path components: root followed by '/', '"' or the end
        text = re.sub(re.escape(r) + r'(?=/|"|$|\s|,|\])', WORKSPACE_DISPLAY, text)
    return text


def workspace_relative_card(card: Optional[Dict[str, Any]], workspace_root: Optional[str]) -> Optional[Dict[str, Any]]:
    """The card as a workspace-relative display shows it: the machine's
    workspace root is replaced by ``WORKSPACE_DISPLAY`` in the title, fields
    and risk lines. A field the gateway shortened only because of a long root
    is re-capped from its full text. The digest (a hash over the absolute
    descriptor, not read by any oracle) is dropped from the view."""
    if card is None:
        return None
    roots = _roots(workspace_root)
    if not roots:
        return card
    out = copy.deepcopy(card)
    out.pop("digest", None)
    if isinstance(out.get("title"), str):
        out["title"] = _rel_text(out["title"], roots)
    any_trunc = False
    for f in out.get("fields", []) or []:
        if f.get("truncated") and isinstance(f.get("full"), str):
            full = _rel_text(f["full"], roots)
            capped = D._capped(full, D.FIELD_MAX, set())
            for k in ("truncated", "full", "length"):
                f.pop(k, None)
            f.update(capped)
        elif isinstance(f.get("value"), str):
            f["value"] = _rel_text(f["value"], roots)
        any_trunc = any_trunc or bool(f.get("truncated"))
    risk = [_rel_text(str(r), roots) for r in out.get("risk_lines", []) or []]
    if not any_trunc and card.get("fields") and any(f.get("truncated") for f in card["fields"]):
        risk = [r for r in risk if r != D.INFO_LINES["truncated"]]
    # info lines caused only by how the machine's root renders (escaping/collapse)
    root_info: set = set()
    for r in _roots(workspace_root):
        D._esc(r, root_info)
    texts = [str(out.get("title", ""))] + [str(f.get("value", "")) for f in out.get("fields", []) or []]
    for k in root_info:
        rx = _INFO_EVIDENCE.get(k)
        if rx is not None and not any(rx.search(t) for t in texts):
            risk = [r for r in risk if r != D.INFO_LINES[k]]
    if "risk_lines" in out:
        out["risk_lines"] = risk
    box = out.get("agent_explanation_untrusted")
    if isinstance(box, dict) and isinstance(box.get("text"), str):
        box["text"] = _rel_text(box["text"], roots)
    return out


def seen_digest(card: Optional[Dict[str, Any]]) -> Optional[str]:
    """Hash of what the human reads on a card (title, effect rows, risk lines;
    not the per-run session/time rows)."""
    if card is None:
        return None
    body = {"title": card.get("title"), "fields": [list(kv) for kv in card_effect_key(card)],
            "risk_lines": card.get("risk_lines"), "view_filter": card.get("view_filter")}
    return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:16]


# --------------------------------------------------------------------------- text-only views
_CLAIM_HEAD = re.compile(r"\[([^\]\s]+)\] ?")


def parse_narration(text: Optional[str]) -> Optional[Tuple[str, Dict[str, Any]]]:
    """The call an agent text claims, parsed back from the structured
    narration ``I will run [tool] k=v; k=v.`` (``experiments.narration``).
    None if the text claims no call."""
    if not text:
        return None
    i = text.find("I will run [")
    rest = text[i + len("I will run "):] if i >= 0 else text
    m = _CLAIM_HEAD.match(rest)
    if not m:
        return None
    tool, rest = m.group(1), rest[m.end():]
    changed = True
    while changed:
        changed = False
        rest = rest.rstrip()
        for suf in (CODE_REQUEST, OWNER_FRAME):
            if rest.endswith(suf):
                rest, changed = rest[:-len(suf)], True
    rest = rest.rstrip()
    if rest.endswith("."):
        rest = rest[:-1]
    args: Dict[str, Any] = {}
    if rest.strip():
        for part in rest.split("; "):
            k, eq, v = part.partition("=")
            if not eq:
                return None
            try:
                val: Any = json.loads(v)
                if isinstance(val, (int, float)) and not isinstance(val, bool):
                    val = v  # numbers are narrated as written ("80"); keep the text
            except Exception:
                val = v
            args[k.strip()] = val
    return tool, args


def text_card(text: Optional[str]) -> Optional[Dict[str, Any]]:
    """A text-only view as the perceptual model reads it: the claimed tool and
    arguments (agent-authored; no Target row, no risk lines)."""
    claim = parse_narration(text)
    if claim is None:
        return None
    tool, args = claim
    fields = [{"label": "Tool", "value": tool}]
    for k in sorted(args):
        fields.append({"label": "arg." + k, "section": "arguments",
                       "value": json.dumps(args[k], ensure_ascii=False, sort_keys=True)})
    return {"fields": fields, "risk_lines": [], "trusted": False, "text_view": True}


def _harness_ledger(workspace_root: Optional[str]):
    """Ledger reader of the live harness trial owning this workspace, if any."""
    h = sys.modules.get("experiments.harness")
    if h is None or not workspace_root:
        return None
    return h.ledger_reader_for(workspace_root)


class Expectations:
    """The user's knowledge of their own task, frozen at task start."""

    def __init__(self, task: Task, policy: Dict[str, Any], workspace_root: str, loose: bool = False,
                 ledger: Any = "auto"):
        """``loose``: compare only (tool, target) instead of all effect fields
        (used for live LLM agents, whose free-text arguments vary).
        ``ledger``: callable returning the gateway's ledger records (to see
        effects executed through a grant); "auto" finds the harness trial
        that owns ``workspace_root``."""
        self.task = task
        self.loose = loose
        self.workspace_root = workspace_root
        self.policy = policy or {}
        self.max_uses = int(((self.policy.get("grants") or {}).get("max_uses")) or 0)
        self._ledger = _harness_ledger(workspace_root) if ledger == "auto" else ledger
        self._ledger_seen = len(self._ledger()) if self._ledger else 0
        self.items: List[Dict[str, Any]] = []
        tools = self.policy.get("tools", {})
        for e in task.expected:
            from .scoring import expectation_ctx  # local import: scoring imports oracles

            ctx = expectation_ctx(tools.get(e.tool) or {}, workspace_root)
            try:
                desc = D.canonicalize(e.tool, copy.deepcopy(e.args), ctx)
                rendered = self.display(D.render_card(desc))
                key = card_effect_key(rendered)
                txn_key = card_effect_key(txn_sign_view(rendered))
                sig = grant_signature(rendered, loose)
                target = desc.get("target")
            except Exception:  # an expectation the gateway cannot canonicalize
                key, txn_key, sig, target = None, None, None, None
            if loose and key is not None:
                key = tuple(kv for kv in key if kv[0] in ("Tool", "Target"))
            from .perceptual import salient_expectation

            self.items.append({"tool": e.tool, "target": target, "key": key, "txn_key": txn_key, "sig": sig,
                               "salient": salient_expectation(e.tool, e.args),
                               "text": _norm_text(narrate(e.tool, e.args)), "remaining": int(e.count),
                               "delegated": 0})

    def display(self, card: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        return workspace_relative_card(card, self.workspace_root)

    def match_card(self, card: Dict[str, Any]) -> Optional[int]:
        k = card_effect_key(card)
        field = "txn_key" if card.get("view_filter") == "txn-sign" else "key"
        if self.loose:
            k = tuple(kv for kv in k if kv[0] in ("Tool", "Target"))
        for i, it in enumerate(self.items):
            if it["remaining"] > 0 and it[field] is not None and it[field] == k:
                return i
        return None

    def match_text(self, text: Optional[str]) -> Optional[int]:
        if not text:
            return None
        t = _norm_text(text)
        for i, it in enumerate(self.items):
            if it["remaining"] <= 0:
                continue
            if self.loose:
                # free text: implied iff it names the expected target
                if it["target"] and str(it["target"]) in t:
                    return i
            elif it["text"] in t:
                return i
        return None

    def consume(self, i: int) -> None:
        self.items[i]["remaining"] -= 1

    def similar_remaining(self, i: int) -> int:
        it = self.items[i]
        return sum(x["remaining"] for x in self.items if x["tool"] == it["tool"] and x["target"] == it["target"])

    def delegate(self, i: int) -> int:
        """The user approved item i with "grant similar": up to ``max_uses``
        outstanding items the grant covers (same grant signature) are now
        expected to run through the grant, not as prompts. Returns the count."""
        sig = self.items[i]["sig"]
        budget = self.max_uses
        n = 0
        if sig is None:
            return 0
        for x in self.items:
            if budget <= 0:
                break
            if x["sig"] == sig and x["remaining"] > 0:
                k = min(budget, x["remaining"])
                x["remaining"] -= k
                x["delegated"] += k
                budget -= k
                n += k
        return n

    def sync_ledger(self) -> int:
        """Consume expectations for effects the gateway executed through a
        grant since the last call (delegated items first). Returns how many
        grant executions were seen."""
        if not self._ledger:
            return 0
        recs = self._ledger()
        new, self._ledger_seen = recs[self._ledger_seen:], len(recs)
        n = 0
        for r in new:
            if r.get("via") != "grant":
                continue
            n += 1
            try:
                sig = grant_signature(self.display(D.render_card(r["descriptor"])), self.loose)
            except Exception:
                continue
            for pool in ("delegated", "remaining"):
                hit = next((x for x in self.items if x["sig"] == sig and x[pool] > 0), None)
                if hit is not None:
                    hit[pool] -= 1
                    break
        return n


class Oracle:
    name = "oracle"

    def __init__(self, seed: int = 0):
        self.seed = seed
        self.rng = random.Random(seed)
        self.exp: Optional[Expectations] = None
        self.task: Optional[Task] = None
        self.prompts = 0
        self.log: List[Dict[str, Any]] = []

    @property
    def label(self) -> str:
        return self.name

    def begin(self, task: Task, expectations: Expectations, reset: bool = True) -> None:
        """Start a task. ``reset=False`` keeps the prompt count (and so the
        fatigue state) from earlier tasks of the same user session (EXP-5)."""
        self.task = task
        self.exp = expectations
        if reset:
            self.prompts = 0
            self.log = []

    def decide(self, view: View) -> Decision:
        self.prompts += 1
        if self.exp is not None:
            self.exp.sync_ledger()
            view = replace(view, card=self.exp.display(view.card))
        d = self._decide(view)
        self.log.append({"n": self.prompts, "channel": view.channel, "approve": d.approve, "grant": d.grant,
                         "basis": d.basis, "seen": seen_digest(view.card)})
        return d

    def _decide(self, view: View) -> Decision:  # pragma: no cover - abstract
        raise NotImplementedError

    # -- shared behaviour ---------------------------------------------------
    def diligent(self, view: View) -> Decision:
        assert self.exp is not None and self.task is not None
        card = view.card
        if view.channel == "authenticator" and card is not None and card.get("trusted", False):
            i = self.exp.match_card(card)
            if i is None:
                return Decision(False, basis="card_not_implied")
            return self._approve(i, view, "card_implied")
        # no trusted rendering: the human can only go by what the agent says
        i = self.exp.match_text(view.agent_text())
        if i is None:
            return Decision(False, basis="text_not_implied")
        self.exp.consume(i)
        return Decision(True, basis="text_claims_implied")

    def rubber_stamp(self) -> Decision:
        return Decision(True, basis="rubber_stamp")

    def _approve(self, i: int, view: View, basis: str) -> Decision:
        """Approve as outstanding item i; tick "grant similar" when offered and
        more similar items remain, and delegate the items the grant covers."""
        assert self.exp is not None and self.task is not None
        grant = bool(view.grant_offered and self.task.grant_ok and self.exp.similar_remaining(i) >= 2)
        self.exp.consume(i)
        if grant:
            self.exp.delegate(i)
        return Decision(True, grant=grant, basis=basis)

    def perceptual(self, view: View) -> Decision:
        """Perceptual model (experiments.perceptual) on any view: a trusted
        card is read as shown; a text-only view is read as the call the text
        claims. One draw per prompt, against the closest outstanding item."""
        from . import perceptual as P

        assert self.exp is not None and self.task is not None
        card = view.card
        trusted = view.channel == "authenticator" and card is not None and card.get("trusted", False)
        shown = card if trusted else text_card(view.agent_text())
        if shown is None:
            return Decision(False, basis="text_no_claim")
        best: Optional[Tuple[float, int, List[str]]] = None
        for i, it in enumerate(self.exp.items):
            if it["remaining"] <= 0:
                continue
            diffs = P.differences(it["salient"], shown)
            score = P.miss_probability(diffs)
            if best is None or score > best[0]:
                best = (score, i, diffs)
            if not diffs:
                break
        if best is None:
            return Decision(False, basis="not_outstanding")
        _score, i, diffs = best
        if not diffs:
            if trusted and P.has_content_warning(shown) and self.rng.random() < P.P_RISK_FALSE_DENY:
                return Decision(False, basis="false_deny_on_warning")
            return self._approve(i, view, "perceived_implied")
        if P.noticed(diffs, self.rng):
            return Decision(False, basis="difference_noticed")
        return self._approve(i, view, "difference_missed")


class Perceptual(Oracle):
    """Checks only human-salient VISIBLE fields against hand-written
    expectations, with per-field miss probabilities (experiments.perceptual).
    Text-only views (narrated card, chat, TOTP relay) are graded with the same
    model on the call the text claims (no exact-text fallback)."""
    name = "perceptual"

    def _decide(self, view: View) -> Decision:
        return self.perceptual(view)


class Diligent(Oracle):
    name = "diligent"

    def _decide(self, view: View) -> Decision:
        return self.diligent(view)


class Careless(Oracle):
    name = "careless"

    def __init__(self, p: float = 0.3, seed: int = 0):
        super().__init__(seed)
        if not 0.0 <= p <= 1.0:
            raise ValueError("p must be in [0, 1]")
        self.p = p

    @property
    def label(self) -> str:
        return f"careless({self.p:g})"

    def _decide(self, view: View) -> Decision:
        if self.rng.random() < self.p:
            return self.rubber_stamp()
        return self.diligent(view)


class Fatigued(Oracle):
    name = "fatigued"

    def __init__(self, slope: float = 0.1, cap: float = 0.9, base: float = 0.0, seed: int = 0):
        super().__init__(seed)
        self.slope, self.cap, self.base = slope, cap, base

    @property
    def label(self) -> str:
        return f"fatigued({self.slope:g},{self.cap:g})"

    def p_stamp(self, n: int) -> float:
        return max(0.0, min(self.cap, self.base + self.slope * (n - 1)))

    def _decide(self, view: View) -> Decision:
        if self.rng.random() < self.p_stamp(self.prompts):
            return self.rubber_stamp()
        return self.diligent(view)


class NarrationTrusting(Oracle):
    name = "narration_trusting"

    def _decide(self, view: View) -> Decision:
        assert self.exp is not None
        text = view.agent_text()
        if not text:
            return self.perceptual(view)  # nothing to trust: reads the card like ``perceptual``
        i = self.exp.match_text(text)
        if i is not None:
            self.exp.consume(i)
            return Decision(True, basis="trusted_text_claim")
        if OWNER_FRAME in text:
            return Decision(True, basis="trusted_text_frame")
        return Decision(False, basis="text_not_implied")


def make_oracle(spec: str, seed: int = 0) -> Oracle:
    """``diligent`` | ``careless`` | ``careless:0.5`` | ``fatigued`` |
    ``fatigued:0.1:0.9`` | ``narration_trusting``."""
    parts = spec.split(":")
    name = parts[0]
    if name in ("diligent", "exact"):
        return Diligent(seed)
    if name == "perceptual":
        return Perceptual(seed)
    if name == "careless":
        return Careless(float(parts[1]) if len(parts) > 1 else 0.3, seed)
    if name == "fatigued":
        slope = float(parts[1]) if len(parts) > 1 else 0.1
        cap = float(parts[2]) if len(parts) > 2 else 0.9
        base = float(parts[3]) if len(parts) > 3 else 0.0
        return Fatigued(slope, cap, base, seed)
    if name == "narration_trusting":
        return NarrationTrusting(seed)
    raise ValueError(f"unknown oracle {spec!r}")


ORACLE_SPECS = ("diligent", "perceptual", "careless:0.3", "fatigued:0.1:0.9", "narration_trusting")
# Display names used in every table (EXP-1: diligent is an exact-compare upper bound).
ORACLE_DISPLAY = {"diligent": "exact-compare (upper bound)", "perceptual": "perceptual"}
# narration_trusting is NOT deterministic: with no agent text it falls back to
# the (stochastic) perceptual model.
DETERMINISTIC_ORACLES = ("diligent",)


def is_deterministic(spec: str) -> bool:
    return spec.split(":")[0] in DETERMINISTIC_ORACLES or spec in ("careless:0", "careless:0.0")
