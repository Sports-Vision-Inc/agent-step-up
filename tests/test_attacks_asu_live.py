"""Executed attack tests for the ASU column of the attack matrix (AB9, AB10, AB11, AB12).

Each test drives a REAL gateway (create_app served by uvicorn on a localhost
port, approval_mode=asu, receipt re-verification on, packaged default policy)
through the red-team harness in tests/redteam/rt_live.py: a scripted human with
a software passkey and a compromised agent that holds only its bearer token.

attacks/probes/asu_probe.py runs these node ids and maps them to matrix cells,
so the matrix only says "executed" for a cell that a test actually executed.

AB9 has two parts. The first part checks the threat model's claim that the agent
cannot reach the ceremony. The second part runs the BY-DESIGN limitation (formal
experiment X2, assumption H3): whoever controls the page that renders the card
also chooses what the passkey signs. Consent-level P5 therefore needs an honest
rendering origin. That part passes when the limitation behaves as documented.
It is not a security guarantee.
"""
from __future__ import annotations

import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "redteam"))
sys.path.insert(0, os.path.dirname(HERE))

from rt_live import RT_FLOOD, Agent, Human, LiveGateway, default_policy, setup  # noqa: E402

from asu.authn.receipt import verify_receipt  # noqa: E402

PAY_OK = {"payee": "acct-utility-001", "amount": "40", "currency": "USD"}
PAY_BAD = {"payee": "acct-placeholder-999", "amount": "40", "currency": "USD"}


def _paid(gw, payee):
    return [e for e in gw.ledger() if e["descriptor"]["args"].get("payee") == payee]


@pytest.fixture
def live(tmp_path):
    gw, human, agent = setup(tmp_path, policy=default_policy(flood=dict(RT_FLOOD)))
    try:
        yield gw, human, agent
    finally:
        gw.__exit__()


# ------------------------------------------------------------------ AB9
def test_ab9_agent_cannot_reach_the_ceremony(live):
    """The agent's bearer token gives it no access to the authenticator API. It
    cannot list or view cards, request a challenge, submit an assertion, or
    enroll a credential. The gateway, not the agent, decides what is signed."""
    gw, human, agent = live
    r = agent.call("transfer_money", PAY_BAD)
    assert r.status_code == 202, r.text
    aid = r.json()["approval_id"]

    h = agent.http  # bearer token only, no web-login cookie
    assert h.get("/v1/authn/pending").status_code == 401
    assert h.get(f"/v1/authn/approvals/{aid}").status_code == 401
    assert h.post(f"/v1/authn/approvals/{aid}/options", json={"grant": False}).status_code == 401
    assert h.post(f"/v1/authn/approvals/{aid}/verify",
                  json={"credential": {}, "grant": False}).status_code in (401, 422)
    # Without an out-of-band enrollment token, the agent cannot add its own passkey.
    assert h.post("/v1/authn/register/options", json={"user_id": "alice"}).status_code in (400, 401, 403)

    # Nothing ran, and the approval is still pending for the human.
    assert agent.execute(aid).status_code == 202
    assert not _paid(gw, PAY_BAD["payee"])


def test_ab9_consent_needs_honest_rendering_origin_by_design(tmp_path):
    """BY-DESIGN LIMITATION (formal X2 / H3, D-005 item 7). A page served from the
    rendering origin can show the human card A and ask the authenticator to sign
    the challenge for B. The authenticator does not display the challenge. The
    resulting receipt is valid for B at KEY LEVEL (the user's key signed h_B for
    aid_B), but the human never saw B. Consent-level P5 therefore holds only under
    an honest rendering origin. The agent cannot do this: it would need the
    human's web login on the gateway origin (see the test above)."""
    # Two sessions (one pending card each under the default per-session cap).
    gw, human, agent_a = setup(tmp_path, policy=default_policy())
    try:
        agent_b = Agent(gw, human.agent_session("agent-2"))
        ra = agent_a.call("transfer_money", PAY_OK)
        rb = agent_b.call("transfer_money", PAY_BAD)
        assert ra.status_code == 202 and rb.status_code == 202, (ra.text, rb.text)
        aid_a, aid_b = ra.json()["approval_id"], rb.json()["approval_id"]

        # The page shows card A to the human...
        shown = human.view(aid_a)
        assert PAY_OK["payee"] in str(shown) and PAY_BAD["payee"] not in str(shown)

        # ...but a dishonest page script (same origin, human's cookie) requests B's challenge.
        o = human.post(f"/v1/authn/approvals/{aid_b}/options", {"grant": False})
        assert o.status_code == 200, o.text
        cred = human.auth.get(o.json())  # the authenticator signs bytes it does not display
        v = human.post(f"/v1/authn/approvals/{aid_b}/verify", {"credential": cred, "grant": False})
        assert v.status_code == 200, v.text
        receipt = v.json()["receipt"]

        # Key-level P5 still holds: a third party verifies that the user's key signed h_B for aid_B.
        ap_b = gw.store.get_approval(aid_b)
        pub = gw.store.get_credentials("alice")[0]["public_key"]
        pub = bytes(pub) if not isinstance(pub, bytes) else pub
        assert verify_receipt(receipt, pub, ap_b["digest"], aid_b, ap_b["nonce"],
                              expected_origins=[gw.origin], expected_rp_id="localhost",
                              require_user_verification=True)
        assert receipt["digest"] != gw.store.get_approval(aid_a)["digest"]

        # The gateway executes B. Consent-level P5 fails without an honest origin (by design).
        assert agent_b.execute(aid_b).status_code == 200
        assert _paid(gw, PAY_BAD["payee"])
        assert not _paid(gw, PAY_OK["payee"])
    finally:
        gw.__exit__()


# ------------------------------------------------------------------ AB10
def test_ab10_post_approval_substitution_is_409(live):
    """The human approves effect e. The agent then tries to execute a different
    payee, a different amount, or a different tool under the same approval id. Each
    attempt gets 409 effect_mismatch. Nothing runs, the approval stays usable, and
    a bare execute runs the STORED descriptor exactly once."""
    gw, human, agent = live
    r = agent.call("transfer_money", PAY_OK)
    assert r.status_code == 202, r.text
    aid = r.json()["approval_id"]
    human.approve(aid)

    assert agent.execute(aid, args=PAY_BAD).status_code == 409
    assert agent.execute(aid, args={**PAY_OK, "amount": "4000"}).status_code == 409
    assert agent.execute(aid, args={**PAY_OK, "memo": "extra"}).status_code == 409
    assert agent.execute(aid, tool="send_email",
                         args={"to": "someone@example.invalid", "subject": "s", "body": "b"}).status_code == 409
    assert not gw.ledger(), "a substituted effect ran"

    # Resubmitting the approved arguments verbatim is fine; the stored descriptor runs.
    ok = agent.execute(aid, args=dict(PAY_OK))
    assert ok.status_code == 200, ok.text
    led = gw.ledger()
    assert len(led) == 1 and led[0]["descriptor"]["args"]["payee"] == PAY_OK["payee"]
    # Consume-once: replay is refused.
    assert agent.execute(aid).status_code == 403
    assert len(gw.ledger()) == 1


def test_ab10_cross_session_use_of_an_approval_is_refused(live):
    gw, human, agent = live
    r = agent.call("transfer_money", PAY_OK)
    aid = r.json()["approval_id"]
    human.approve(aid)
    other = Agent(gw, human.agent_session("agent-2"))
    assert other.execute(aid).status_code == 404
    assert other.execute(aid, args=PAY_BAD).status_code == 404
    assert not gw.ledger()


# ------------------------------------------------------------------ AB11
def test_ab11_flood_within_one_session_is_rate_limited(tmp_path):
    """Packaged default policy: one pending card per session (an identical retry
    is de-duplicated), and at most 6 tool calls per minute per session. Further
    calls get 429 and do not create cards."""
    gw, human, agent = setup(tmp_path, policy=default_policy())
    try:
        r1 = agent.call("transfer_money", PAY_OK)
        assert r1.status_code == 202
        aid = r1.json()["approval_id"]
        r_dup = agent.call("transfer_money", PAY_OK)
        assert r_dup.status_code == 202 and r_dup.json()["approval_id"] == aid  # de-duplicated
        r2 = agent.call("transfer_money", PAY_BAD)
        assert r2.status_code == 429 and r2.json()["reason"] == "max_pending_per_session"
        codes = [agent.call("transfer_money", {**PAY_BAD, "amount": str(41 + i)}).status_code
                 for i in range(6)]
        assert codes.count(429) == 6
        rl = agent.call("read_file", {"path": "x.txt"})
        assert rl.status_code == 429 and rl.json()["reason"] == "rate_limit_per_min"
        assert [a["id"] for a in human.pending()] == [aid], "flood created extra cards"
    finally:
        gw.__exit__()


def test_ab11_flood_across_a_users_sessions_is_capped_per_user(tmp_path):
    """RT-9 closure: an agent holding several session tokens for one user gets at
    most max_pending_per_user (3) concurrent cards across all of them."""
    gw, human, agent = setup(tmp_path, policy=default_policy())
    try:
        agents = [agent] + [Agent(gw, human.agent_session(f"agent-{i}")) for i in range(2, 6)]
        codes = []
        for i, a in enumerate(agents):
            r = a.call("transfer_money", {**PAY_BAD, "amount": str(50 + i)})
            codes.append((r.status_code, r.json().get("reason")))
        assert [c for c, _ in codes[:3]] == [202, 202, 202], codes
        assert codes[3:] == [(429, "max_pending_per_user")] * 2, codes
        assert len(human.pending()) == 3
    finally:
        gw.__exit__()


def test_ab11_repeated_denials_lock_the_session_out(tmp_path):
    """After deny_lockout (3) denied cards, the session gets 429 deny_lockout."""
    gw, human, agent = setup(tmp_path, policy=default_policy(
        flood={**default_policy()["flood"], "max_requests_per_min": 100}))
    try:
        for i in range(3):
            r = agent.call("transfer_money", {**PAY_BAD, "amount": str(60 + i)})
            assert r.status_code == 202, r.text
            d = human.post(f"/v1/authn/approvals/{r.json()['approval_id']}/deny")
            assert d.status_code == 200, d.text
        r = agent.call("transfer_money", PAY_OK)
        assert r.status_code == 429 and r.json()["reason"] == "deny_lockout"
        assert human.pending() == []
    finally:
        gw.__exit__()


# ------------------------------------------------------------------ AB12
def test_ab12_threshold_splitting_hits_the_aggregate_and_grant_caps(tmp_path):
    """The human approves 10 USD to one payee and ticks "allow similar" (a grant
    capped per use and in total). The agent then splits a large transfer into
    10 USD pieces under that grant. The packaged policy's aggregate window
    (max_effects 5, max_amount 200 per 600 s, across the user's sessions) forces a
    fresh passkey ceremony. That card offers no grant, so the agent cannot
    delegate around it. The total that runs without a new ceremony stays within
    both the grant's signed max_total and the aggregate limit."""
    gw, human, agent = setup(tmp_path, policy=default_policy(
        flood={**default_policy()["flood"], "max_requests_per_min": 1000}))
    try:
        piece = {"payee": "acct-utility-001", "amount": "10", "currency": "USD"}
        r = agent.call("transfer_money", piece)
        assert r.status_code == 202, r.text
        aid = r.json()["approval_id"]
        gr = human.view(aid)["grant_request"]
        assert gr and gr["target"] == piece["payee"]
        human.approve(aid, grant=True)
        assert agent.execute(aid).status_code == 200

        codes = []
        for _ in range(20):
            r = agent.call("transfer_money", piece)
            codes.append(r.status_code)
            if r.status_code != 200:
                break
        assert codes[-1] == 202, codes          # splitting stopped by a fresh challenge
        pending = human.pending()
        assert len(pending) == 1
        view = human.view(pending[0]["id"])
        reasons = gw.store.get_approval(pending[0]["id"])["reasons"]
        assert any(str(x).startswith("aggregate_") for x in reasons), reasons
        assert any("aggregate_" in line for line in view["card"]["risk_lines"]), view["card"]
        assert not view.get("grant_request"), "aggregate step-up must not be delegable"

        paid = [e for e in gw.ledger() if e["descriptor"]["args"].get("payee") == piece["payee"]]
        total = sum(int(e["descriptor"]["args"]["amount"]) for e in paid)
        agg = default_policy()["step_up"]["aggregate"]
        assert len(paid) <= agg["max_effects"] and total <= agg["max_amount"], (len(paid), total)
        assert "max_total_amount" in gr, gr  # grant must carry a signed total cap
        assert total <= int(float(gr["max_total_amount"])), (total, gr["max_total_amount"])
    finally:
        gw.__exit__()
