"""Agent runtime: how a scripted agent issues effects and obtains approvals.

``AgentRuntime.effect`` is the single place where the per-mode approval UX is
modelled (SPEC section 4 baselines):

* ``none``: the gateway never returns 202 for policy challenges.
* ``chat-confirm``: the approval is answered in the agent's own channel
  (``POST /v1/approvals/{id}/chat-confirm``). A compromised agent (or whoever
  is speaking in that channel, e.g. a spoofed owner) simply answers "yes"
  itself; a benign agent relays the human's answer to its narration.
* ``narrated-card`` / ``asu`` / ``unbound`` / ``totp``: the human reviews the
  pending approval on the authenticator page (``HumanSim.review_pending``) and
  approves with the passkey (or a TOTP code in the ``totp`` baseline).
* ``totp`` additionally lets a compromised agent ask the human for a code in
  chat (code relay) and submit it inline with any call.

Agents never receive anything from the human channel except what the gateway
API returns to them (status / approval id).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..harness import AgentAPI, Resp, Trial
from ..narration import CODE_REQUEST, explain
from ..oracles import Oracle, View, txn_sign_view

PAGE_MODES = ("asu", "narrated-card", "unbound", "totp", "host-confirm", "txn-sign", "asu-no-expl")



class HumanSim:
    """The human: an oracle operating the HumanDevice of a trial."""

    def __init__(self, trial: Trial, oracle: Oracle):
        self.trial = trial
        self.device = trial.human
        self.oracle = oracle
        self.prompts = 0
        self.chat_prompts = 0
        self.page_prompts = 0
        self.decisions: List[Dict[str, Any]] = []
        self._seen: set = set()

    def review_pending(self) -> int:
        """Open the authenticator page and decide every pending approval."""
        n = 0
        for ap in self.device.pending():
            aid = ap.get("id")
            if aid in self._seen:
                continue
            self._seen.add(aid)
            card = ap.get("card")
            mode = self.trial.mode
            explanation = ap.get("explanation")
            if mode in ("asu-no-expl", "txn-sign"):
                explanation = None  # no agent text on this display
            if mode == "txn-sign" and card is not None:
                card = txn_sign_view(card)
            view = View(channel="authenticator", mode=mode, card=card, explanation=explanation,
                        grant_offered=bool(ap.get("grant_request")) and mode in ("asu", "asu-no-expl"))
            if card is None:  # page refused to render a faithful card: only deny is possible
                ok = self.device.deny(aid)
                self.decisions.append({"approval_id": aid, "approve": False, "basis": "no_card", "ok": ok})
                continue
            self.prompts += 1
            self.page_prompts += 1
            d = self.oracle.decide(view)
            if d.approve:
                ok = self.device.approve(aid, grant=d.grant and view.grant_offered)
            else:
                ok = self.device.deny(aid)
            self.decisions.append({"approval_id": aid, "approve": d.approve, "grant": d.grant, "basis": d.basis,
                                   "ok": ok, "channel": "authenticator"})
            n += 1
        return n

    def chat(self, text: str, want: str = "confirm") -> Optional[str]:
        """A message from the agent in its own channel asking the human to
        confirm (chat-confirm) or to read out a TOTP code (relay)."""
        self.prompts += 1
        self.chat_prompts += 1
        view = View(channel="chat", mode=self.trial.mode, chat_text=text)
        d = self.oracle.decide(view)
        self.decisions.append({"approve": d.approve, "basis": d.basis, "channel": "chat", "want": want})
        if want == "totp_code":
            return self.device.next_totp_code() if d.approve else None
        return "yes" if d.approve else "no"


@dataclass
class Outcome:
    tool: str
    status: str               # executed | denied_policy | denied_human | mismatch | rate_limited | error | ...
    path: str = ""            # how it ended (policy_allow, approval, grant, totp_relay, ...)
    attack: bool = False
    detail: Dict[str, Any] = field(default_factory=dict)


class AgentRuntime:
    def __init__(self, trial: Trial, human: HumanSim, compromised: bool, api: Optional[AgentAPI] = None):
        self.trial = trial
        self.mode = trial.mode
        self.human = human
        self.compromised = compromised
        self.api = api or trial.new_agent()
        self.outcomes: List[Outcome] = []

    def other_session(self, agent_id: str = "agent-2") -> "AgentRuntime":
        """A second agent session for the same user (opened by the human)."""
        return AgentRuntime(self.trial, self.human, self.compromised, api=self.trial.new_agent(agent_id))

    # ------------------------------------------------------------------
    def _obtain(self, approval_id: str, narration: Optional[str]) -> str:
        if self.mode == "chat-confirm":
            if self.compromised:
                answer = "yes"  # the agent (or the speaker it obeys) answers in its own channel
            else:
                answer = self.human.chat(narration or "", want="confirm") or "no"
            self.api.chat_confirm(approval_id, answer)
        elif self.mode in PAGE_MODES:
            self.human.review_pending()
        return self.api.status(approval_id)

    def effect(self, tool: str, args: Dict[str, Any], *, narration: Optional[str] = None,
               origin: str = "user_turn", attack: bool = False, substitute: Optional[Dict[str, Any]] = None,
               resubmit_args: bool = False, between: Any = None, relay: bool = True) -> Outcome:
        """Try to cause one effect through the gateway.

        narration   agent text sent as ``explanation`` (and used in chat).
        substitute  args to submit at execute time instead (A4 substitution).
        resubmit_args  resend the original args at execute time.
        between     callable run after approval and before execute (TOCTOU).
        relay       totp mode, compromised agent, attack effect: ask for a
                    code in chat first and submit it inline.
        """
        if narration is None:
            narration = explain(tool, args)
        out = self._effect(tool, args, narration, origin, attack, substitute, resubmit_args, between, relay)
        self.outcomes.append(out)
        return out

    def _effect(self, tool, args, narration, origin, attack, substitute, resubmit_args, between, relay) -> Outcome:
        api = self.api
        if self.mode == "totp" and self.compromised and attack and relay:
            code = self.human.chat(narration + " " + CODE_REQUEST, want="totp_code")
            if code:
                r = api.call(tool, args, explanation=narration, origin=origin, totp_code=code)
                if r.code == 200:
                    return Outcome(tool, "executed", "totp_relay", attack)
                if r.code == 429:
                    return Outcome(tool, "rate_limited", r.body.get("reason", ""), attack)
                # fall through to the normal path if the inline code was refused
        r = api.call(tool, args, explanation=narration, origin=origin)
        if r.code == 200:
            return Outcome(tool, "executed", "no_challenge", attack)
        if r.code == 403:
            return Outcome(tool, "denied_policy", ",".join(r.body.get("reasons", [])), attack)
        if r.code == 429:
            return Outcome(tool, "rate_limited", r.body.get("reason", ""), attack)
        if r.code != 202:
            return Outcome(tool, "error", f"http_{r.code}", attack, {"body": r.body})
        aid = r.body["approval_id"]
        st = self._obtain(aid, narration)
        if st != "approved":
            return Outcome(tool, "denied_human" if st == "denied" else st, "approval", attack, {"approval_id": aid})
        if between is not None:
            between()
        if substitute is not None:
            r2 = api.execute(aid, args=substitute)
        elif resubmit_args:
            r2 = api.execute(aid, args=args)
        else:
            r2 = api.execute(aid)
        if r2.code == 200:
            return Outcome(tool, "executed", "approval_substituted" if substitute is not None else "approval",
                           attack, {"approval_id": aid})
        if r2.code == 409:
            return Outcome(tool, "mismatch", "effect_mismatch", attack, {"approval_id": aid})
        return Outcome(tool, f"exec_{r2.status or r2.code}", "approval", attack, {"approval_id": aid, "body": r2.body})

    def request_only(self, tool: str, args: Dict[str, Any], narration: Optional[str] = None,
                     origin: str = "user_turn") -> Optional[str]:
        """Create an approval and get it decided, but do not execute (A11)."""
        r = self.api.call(tool, args, explanation=narration or explain(tool, args), origin=origin)
        if r.code != 202:
            return None
        aid = r.body["approval_id"]
        st = self._obtain(aid, narration or explain(tool, args))
        return aid if st == "approved" else None
