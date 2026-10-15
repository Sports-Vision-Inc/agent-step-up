"""A6 approval flooding, A7 threshold splitting via aggregates, A9 grant stretching,
and the baseline approval modes of SPEC section 4."""
from __future__ import annotations

import copy
import json
import time

import pytest

from test_gateway_fixtures import TEST_POLICY, Env, env  # noqa: F401

EMAIL = {"to": "bob@example.com", "subject": "hi", "body": "hello"}


def pol(**over):
    p = copy.deepcopy(TEST_POLICY)
    for k, v in over.items():
        p[k] = {**p.get(k, {}), **v} if isinstance(v, dict) else v
    return p


def pay(env, amount="50", payee="bob", currency="usd", **kw):
    return env.call("transfer_money", {"payee": payee, "amount": amount, "currency": currency}, **kw)


# ---------------------------------------------------------------- A6 flood
def test_one_pending_per_session(tmp_path):
    e = Env(tmp_path, policy=pol(flood={"max_pending_per_session": 1}))
    c1, o1 = e.call("send_email", EMAIL)
    assert c1 == 202
    c2, o2 = e.call("send_email", {**EMAIL, "to": "carol@example.com"})
    assert c2 == 429 and o2 == {"status": "rate_limited", "reason": "max_pending_per_session"}
    assert len(e.store.list_pending("alice")) == 1
    e.store.mark_denied(o1["approval_id"])
    assert e.call("send_email", {**EMAIL, "to": "carol@example.com"})[0] == 202


def test_identical_pending_is_deduplicated(tmp_path):
    e = Env(tmp_path, policy=pol(flood={"max_pending_per_session": 1}))
    ids = {e.call("send_email", dict(EMAIL))[1]["approval_id"] for _ in range(10)}
    assert len(ids) == 1
    assert len(e.store.list_pending("alice")) == 1


def test_per_minute_rate_limit(tmp_path):
    e = Env(tmp_path, policy=pol(flood={"max_requests_per_min": 3}))
    codes = [e.call("read_file", {"path": "a"})[0] for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]
    # a different session has its own budget
    _, s2 = e.new_session()
    assert e.call("read_file", {"path": "a"}, session=s2)[0] == 200


def test_deny_lockout(tmp_path):
    e = Env(tmp_path, policy=pol(flood={"deny_lockout": 2, "max_pending_per_session": 1}))
    for i in range(2):
        c, o = e.call("send_email", {**EMAIL, "subject": str(i)})
        assert c == 202
        assert e.store.mark_denied(o["approval_id"])
    c, o = e.call("read_file", {"path": "a"})
    assert c == 429 and o["reason"] == "deny_lockout"
    c, o = e.call("send_email", {**EMAIL, "subject": "again"})
    assert c == 429


def test_flood_simulation_bounded_prompts(tmp_path):
    """A compromised agent spamming 200 distinct challenged calls produces at
    most max_pending prompts at a time; after the human denies `deny_lockout`
    of them the session is locked out."""
    e = Env(tmp_path, policy=pol(flood={"max_pending_per_session": 1, "max_requests_per_min": 1000,
                                         "deny_lockout": 3}))
    prompts = set()
    for i in range(200):
        c, o = e.call("send_email", {**EMAIL, "subject": f"spam {i}"})
        if c == 202:
            prompts.add(o["approval_id"])
            e.store.mark_denied(o["approval_id"])
    assert len(prompts) == 3
    assert e.ledger() == []


# ---------------------------------------------------- A7 threshold splitting
def test_split_payments_hit_aggregate_amount(tmp_path):
    """Each 45 USD payment is under amount_over=100 but the window total
    crosses max_amount=200; the gateway asks again even with a grant."""
    p = pol(step_up={"first_time_recipient": False, "destructive_classes": [],
                     "aggregate": {"window_s": 600, "max_effects": 100, "max_amount": 200}})
    e = Env(tmp_path, policy=p)
    codes = [pay(e, "45")[0] for _ in range(5)]
    assert codes[:4] == [200, 200, 200, 200]
    assert codes[4] == 202  # 225 > 200
    ap = e.store.list_pending("alice")[0]
    assert any(r.startswith("aggregate_amount") for r in ap["reasons"])
    assert ap["grant_request"] is None  # aggregate breaches are not delegable


def test_split_effects_hit_aggregate_count(tmp_path):
    p = pol(step_up={"aggregate": {"window_s": 600, "max_effects": 3, "max_amount": 10 ** 6}})
    e = Env(tmp_path, policy=p)
    codes = [e.call("write_file", {"path": f"f{i}.txt", "content": "x"})[0] for i in range(4)]
    assert codes == [200, 200, 200, 202]


def test_aggregate_spans_sessions_of_same_user(tmp_path):
    p = pol(step_up={"first_time_recipient": False, "destructive_classes": [],
                     "aggregate": {"window_s": 600, "max_effects": 100, "max_amount": 100}})
    e = Env(tmp_path, policy=p)
    assert pay(e, "60")[0] == 200
    _, s2 = e.new_session("alice", "agent-2")
    assert pay(e, "60", session=s2)[0] == 202


def test_aggregate_window_expires(tmp_path):
    p = pol(step_up={"first_time_recipient": False, "destructive_classes": [],
                     "aggregate": {"window_s": 600, "max_effects": 100, "max_amount": 100}})
    e = Env(tmp_path, policy=p)
    assert pay(e, "60")[0] == 200
    with e.store.tx() as c:
        c.execute("UPDATE effects SET executed_at=executed_at-601")
    assert pay(e, "60")[0] == 200


def test_negative_amount_counts_by_magnitude(tmp_path):
    p = pol(step_up={"first_time_recipient": False, "destructive_classes": []})
    e = Env(tmp_path, policy=p)
    assert pay(e, "-150")[0] == 202  # |amount| > amount_over


# -------------------------------------------------------- A9 grant stretching
def grant_env(tmp_path, **grants):
    p = pol(grants={"max_ttl_s": 3600, "max_uses": 3, **grants},
            step_up={"aggregate": {"window_s": 600, "max_effects": 1000, "max_amount": 10 ** 6}})
    return Env(tmp_path, policy=p)


def approve_with_grant(e, amount="50", payee="bob"):
    c, o = pay(e, amount, payee)
    assert c == 202
    aid = o["approval_id"]
    ap = e.store.get_approval(aid)
    assert ap["grant_request"] is not None
    assert e.fake_approve(aid, grant=True)
    assert e.execute(aid)[0] == 200
    return ap


def test_grant_allows_similar_within_caps(tmp_path):
    e = grant_env(tmp_path)
    approve_with_grant(e)
    for _ in range(3):
        c, o = pay(e, "50")
        assert c == 200 and e.store.get_effect(o["receipt_id"])["via"] == "grant"
    assert pay(e, "50")[0] == 202  # max_uses=3 exhausted


@pytest.mark.parametrize("change", [
    {"payee": "mallory"},          # different target
    {"amount": "50.01"},           # over signed per-use max
    {"currency": "eur"},           # different currency
])
def test_grant_does_not_stretch(tmp_path, change):
    e = grant_env(tmp_path)
    approve_with_grant(e)
    args = {"payee": "bob", "amount": "50", "currency": "usd", **change}
    assert e.call("transfer_money", args)[0] == 202


def test_grant_not_usable_from_other_session_or_tool(tmp_path):
    e = grant_env(tmp_path)
    approve_with_grant(e)
    _, s2 = e.new_session("alice", "agent-1")
    assert pay(e, "50", session=s2)[0] == 202


def test_grant_not_usable_for_autonomous_origin(tmp_path):
    e = grant_env(tmp_path)
    approve_with_grant(e)
    assert pay(e, "50", origin="autonomous")[0] == 202


def test_grant_expiry(tmp_path):
    e = grant_env(tmp_path)
    approve_with_grant(e)
    with e.store.tx() as c:
        c.execute("UPDATE grants SET not_after=?", (int(time.time()) - 1,))
    assert pay(e, "50")[0] == 202


def test_grant_total_amount_cap(tmp_path):
    e = grant_env(tmp_path, max_uses=10, max_total_amount=120)
    approve_with_grant(e)
    assert pay(e, "50")[0] == 200
    assert pay(e, "50")[0] == 200
    assert pay(e, "50")[0] == 202  # 150 > signed max_total_amount 120


def test_tampered_grant_rejected_at_approval(tmp_path):
    e = grant_env(tmp_path)
    c, o = pay(e)
    ap = e.store.get_approval(o["approval_id"])
    stretched = dict(ap["grant_request"], max_uses=1000)
    receipt = {"digest": ap["digest"], "approval_id": ap["id"], "nonce": ap["nonce"]}
    assert not e.store.mark_approved(ap["id"], receipt, stretched)
    assert e.store.get_approval(ap["id"])["status"] == "pending"
    other_target = dict(ap["grant_request"], target="mallory")
    assert not e.store.mark_approved(ap["id"], receipt, other_target)


def test_db_row_stretching_bounded_by_signed_grant(tmp_path):
    e = grant_env(tmp_path)
    approve_with_grant(e)
    with e.store.tx() as c:  # someone edits the copied columns, not the signed JSON
        c.execute("UPDATE grants SET max_uses=1000, not_after=not_after+100000")
    codes = [pay(e, "50")[0] for _ in range(5)]
    assert codes == [200, 200, 200, 202, 202]


def test_no_grant_offered_for_exec_or_autonomous(tmp_path):
    e = grant_env(tmp_path)
    c, o = e.call("run_shell", {"command": ["ls"]})
    assert c == 202 and e.store.get_approval(o["approval_id"])["grant_request"] is None
    c, o = e.call("send_email", EMAIL, origin="autonomous")
    assert c == 202 and e.store.get_approval(o["approval_id"])["grant_request"] is None


def test_grant_without_ticking_is_not_created(tmp_path):
    e = grant_env(tmp_path)
    c, o = pay(e)
    e.fake_approve(o["approval_id"], grant=False)
    e.execute(o["approval_id"])
    assert pay(e)[0] == 202


# ----------------------------------------------------------- baseline modes
def test_mode_none_runs_challenged_effects(tmp_path):
    e = Env(tmp_path, mode="none")
    c, o = e.call("send_email", EMAIL)
    assert c == 200 and e.store.get_effect(o["receipt_id"])["via"] == "mode_none"
    assert e.call("read_file", {"path": "/etc/passwd"})[0] == 403  # hard denies still apply


def test_mode_chat_confirm_agent_can_self_approve(tmp_path):
    e = Env(tmp_path, mode="chat-confirm")
    c, o = e.call("send_email", {**EMAIL, "to": "mallory@evil.example"})
    aid = o["approval_id"]
    assert e.gw.chat_confirm(e.session, aid, "yes")[0] == 200  # the agent answers itself (P1 fails)
    assert e.execute(aid)[0] == 200
    assert len(e.ledger()) == 1


def test_chat_confirm_endpoint_disabled_in_asu_mode(env):
    c, o = env.call("send_email", EMAIL)
    assert env.gw.chat_confirm(env.session, o["approval_id"], "yes")[0] == 404
    assert env.store.get_approval(o["approval_id"])["status"] == "pending"


def test_mode_narrated_card_shows_agent_text(tmp_path):
    e = Env(tmp_path, mode="narrated-card")
    c, o = e.call("send_email", {**EMAIL, "to": "mallory@evil.example"}, explanation="Reply to Bob's question")
    card = e.store.get_approval(o["approval_id"])["card"]
    assert card["title"] == "Reply to Bob's question"
    assert "mallory" not in json.dumps(card["fields"])  # P4 fails: real recipient not shown
    assert card["trusted"] is False
    e.fake_approve(o["approval_id"])
    assert e.execute(o["approval_id"], args={**EMAIL, "to": "x@y.z"})[0] == 409  # but still bound to h


def test_mode_unbound_allows_substitution_and_session_wide_reuse(tmp_path):
    e = Env(tmp_path, mode="unbound")
    c, o = e.call("send_email", EMAIL)
    aid = o["approval_id"]
    e.fake_approve(aid)
    c, out = e.execute(aid, args={**EMAIL, "to": "mallory@evil.example"})
    assert c == 200  # P2 fails: substituted effect runs
    assert e.ledger()[0]["descriptor"]["target"] == "mallory@evil.example"
    c, out = e.call("send_email", {**EMAIL, "to": "eve@evil.example"})
    assert c == 200 and e.store.get_effect(out["receipt_id"])["via"] == "unbound_session"
    assert e.call("read_file", {"path": "/etc/passwd"})[0] == 403


def test_mode_totp_code_is_relayable_and_unbound(tmp_path):
    import pyotp

    e = Env(tmp_path, mode="totp")
    secret = pyotp.random_base32()
    e.store.set_totp_secret("alice", secret)
    c, o = e.call("send_email", EMAIL)
    assert c == 202
    code = pyotp.TOTP(secret).now()
    # a code phished for one action authorizes a different one (P2 fails)
    c, out = e.call("send_email", {**EMAIL, "to": "mallory@evil.example"}, totp_code=code)
    assert c == 200
    c, out = e.call("send_email", {**EMAIL, "to": "eve@evil.example"}, totp_code=code)
    assert c == 403 and out["reasons"] == ["totp_invalid"]  # same step cannot be reused
    assert e.call("send_email", {**EMAIL, "to": "z@evil.example"}, totp_code="000000x")[0] == 403


def test_mode_totp_approval_then_substitution(tmp_path):
    e = Env(tmp_path, mode="totp")
    c, o = e.call("send_email", EMAIL)
    e.store.mark_approved(o["approval_id"], {"type": "totp"})
    c, out = e.execute(o["approval_id"], args={**EMAIL, "to": "mallory@evil.example"})
    assert c == 200
    assert e.ledger()[0]["descriptor"]["target"] == "mallory@evil.example"


def test_invalid_mode_rejected(tmp_path):
    with pytest.raises(ValueError):
        Env(tmp_path, mode="yolo")
