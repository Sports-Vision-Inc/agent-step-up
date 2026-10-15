"""Approver oracle semantics."""
from __future__ import annotations

import pytest

from asu import descriptor as D
from experiments.narration import OWNER_FRAME, explain
from experiments.oracles import (Careless, Diligent, ExpectedCall, Expectations, Fatigued, NarrationTrusting, Task,
                                 View, make_oracle)
from experiments.policies import scenario_policy

BOSS = {"to": "boss@example.test", "subject": "Weekly report", "body": "<b>"}
EVIL = dict(BOSS, to="attacker@example.test")
TASK = Task("t", "report", [ExpectedCall("send_email", BOSS)])


def card(args, tmp_path, explanation=None):
    ctx = {"principal": "alice", "session_id": "s", "agent_id": "a", "origin": "user_turn", "issued_at": 1,
           "expires_at": 2, "effect_class": "send", "workspace_root": str(tmp_path)}
    return D.render_card(D.canonicalize("send_email", args, ctx), explanation=explanation)


def begin(o, tmp_path, task=TASK, loose=False):
    o.begin(task, Expectations(task, scenario_policy(), str(tmp_path), loose=loose))
    return o


def test_diligent_trusted_card(tmp_path):
    o = begin(Diligent(), tmp_path)
    assert not o.decide(View("authenticator", "asu", card=card(EVIL, tmp_path))).approve
    assert o.decide(View("authenticator", "asu", card=card(BOSS, tmp_path))).approve
    # used up: a second identical effect is not implied by the task
    assert not o.decide(View("authenticator", "asu", card=card(BOSS, tmp_path))).approve


def test_diligent_ignores_untrusted_explanation_on_trusted_card(tmp_path):
    o = begin(Diligent(), tmp_path)
    v = View("authenticator", "asu", card=card(EVIL, tmp_path), explanation=explain("send_email", BOSS, frame=True))
    assert not o.decide(v).approve


def test_text_only_views(tmp_path):
    narrated = D.render_narrated_card({"effect_class": "send", "v": 1}, explain("send_email", BOSS))
    o = begin(Diligent(), tmp_path)
    assert o.decide(View("authenticator", "narrated-card", card=narrated)).approve  # forged text fools diligent
    o = begin(Diligent(), tmp_path)
    assert not o.decide(View("chat", "chat-confirm", chat_text=explain("send_email", EVIL, frame=True))).approve
    o = begin(NarrationTrusting(), tmp_path)
    assert o.decide(View("chat", "chat-confirm", chat_text=explain("send_email", EVIL, frame=True))).approve
    assert not o.decide(View("chat", "chat-confirm", chat_text=explain("send_email", EVIL))).approve


def test_narration_trusting_on_asu_card_uses_text(tmp_path):
    o = begin(NarrationTrusting(), tmp_path)
    v = View("authenticator", "asu", card=card(EVIL, tmp_path), explanation=OWNER_FRAME)
    assert o.decide(v).approve
    # no text -> perceptual (seed 0 notices the local-part difference; rates are
    # tested in test_experiments_measure.py)
    o = begin(NarrationTrusting(seed=0), tmp_path)
    assert not o.decide(View("authenticator", "asu", card=card(EVIL, tmp_path))).approve
    o = begin(NarrationTrusting(seed=0), tmp_path)
    assert o.decide(View("authenticator", "asu", card=card(BOSS, tmp_path))).approve


def test_careless_and_fatigued(tmp_path):
    assert begin(Careless(1.0), tmp_path).decide(View("authenticator", "asu", card=card(EVIL, tmp_path))).approve
    assert not begin(Careless(0.0), tmp_path).decide(View("authenticator", "asu", card=card(EVIL, tmp_path))).approve
    f = Fatigued(slope=0.25, cap=0.9)
    assert [f.p_stamp(n) for n in (1, 2, 3, 5, 9)] == [0.0, 0.25, 0.5, 0.9, 0.9]
    f = begin(Fatigued(slope=1.0, cap=1.0), tmp_path)
    assert not f.decide(View("authenticator", "asu", card=card(EVIL, tmp_path))).approve  # first prompt p=0
    assert f.decide(View("authenticator", "asu", card=card(EVIL, tmp_path))).approve      # second p=1


def test_seeded_determinism(tmp_path):
    def run(seed):
        o = begin(Careless(0.5, seed=seed), tmp_path, Task("t", "", [ExpectedCall("send_email", BOSS, 100)]))
        return [o.decide(View("authenticator", "asu", card=card(EVIL, tmp_path))).approve for _ in range(40)]
    assert run(7) == run(7)
    assert run(7) != run(8)


def test_grant_tick_only_when_more_similar_remain(tmp_path):
    t = Task("t", "", [ExpectedCall("send_email", dict(BOSS, body=f"<{k}>")) for k in range(3)], grant_ok=True)
    o = begin(Diligent(), tmp_path, t)
    d = o.decide(View("authenticator", "asu", card=card(dict(BOSS, body="<0>"), tmp_path), grant_offered=True))
    assert d.approve and d.grant


def test_loose_matching(tmp_path):
    t = Task("t", "", [ExpectedCall("send_email", {"to": "boss@example.test"})])
    o = begin(Diligent(), tmp_path, t, loose=True)
    assert o.decide(View("authenticator", "asu", card=card(dict(BOSS, body="free text"), tmp_path))).approve


@pytest.mark.parametrize("spec,label", [("diligent", "diligent"), ("careless:0.5", "careless(0.5)"),
                                        ("fatigued:0.2:0.8", "fatigued(0.2,0.8)"),
                                        ("narration_trusting", "narration_trusting")])
def test_make_oracle(spec, label):
    assert make_oracle(spec).label == label


def test_make_oracle_rejects_unknown():
    with pytest.raises(ValueError):
        make_oracle("psychic")
