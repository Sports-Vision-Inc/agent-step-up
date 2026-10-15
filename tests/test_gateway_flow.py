"""Approval state machine and execute path: A4 substitution, A5 replay,
A11 cross-session reuse, A12 autonomous origin, receipt re-verification."""
from __future__ import annotations

import os
import threading

import pytest

from asu import descriptor as D
from test_gateway_fixtures import Env, env, register_soft_authenticator  # noqa: F401

EMAIL = {"to": "bob@example.com", "subject": "hi", "body": "hello"}


def challenge(env, tool="send_email", args=None, **kw):
    code, out = env.call(tool, dict(args or EMAIL), **kw)
    assert code == 202, out
    assert set(out) == {"status", "approval_id"}  # agent learns nothing else
    assert out["status"] == "approval_required"
    return out["approval_id"]


# ------------------------------------------------------------- state machine
def test_allow_executes_immediately(env):
    code, out = env.call("read_file", {"path": "notes.txt"})
    assert code == 200 and out["status"] == "executed"
    assert env.store.get_effect(out["receipt_id"])["via"] == "policy_allow"
    assert len(env.ledger()) == 1


def test_deny_returns_reasons_and_no_effect(env):
    code, out = env.call("read_file", {"path": "/etc/shadow"})
    assert code == 403 and out["status"] == "denied" and out["reasons"]
    code, out = env.call("forbidden_tool", {})
    assert code == 403
    code, out = env.call("no_such_tool", {})
    assert code == 403 and out["reasons"] == ["unknown_tool"]
    assert env.ledger() == []


def test_pending_approved_consumed(env):
    aid = challenge(env)
    assert env.store.get_approval(aid)["status"] == "pending"
    assert env.gw.approval_status(env.session, aid) == (200, {"status": "pending"})
    code, out = env.execute(aid)
    assert code == 202 and out == {"status": "approval_required", "approval_id": aid}
    assert env.fake_approve(aid)
    assert not env.fake_approve(aid)  # approved -> approved is not a transition
    assert env.gw.approval_status(env.session, aid) == (200, {"status": "approved"})
    code, out = env.execute(aid)
    assert code == 200 and out["status"] == "executed"
    assert env.store.get_approval(aid)["status"] == "consumed"
    led = env.ledger()
    assert len(led) == 1 and led[0]["approval_id"] == aid and led[0]["via"] == "approval"


def test_denied_cannot_be_approved_or_executed(env):
    aid = challenge(env)
    assert env.store.mark_denied(aid)
    assert not env.store.mark_denied(aid)
    assert not env.fake_approve(aid)
    code, out = env.execute(aid)
    assert code == 403 and out["reasons"] == ["approval_denied"]
    assert not env.store.consume(aid)


def test_consume_requires_approved(env):
    aid = challenge(env)
    assert not env.store.consume(aid)  # pending -> consumed is not allowed


def test_expired_approval(env):
    aid = challenge(env)
    with env.store.tx() as c:
        c.execute("UPDATE approvals SET expires_at=0 WHERE id=?", (aid,))
    assert env.store.get_approval(aid)["status"] == "expired"
    assert not env.fake_approve(aid)
    assert env.store.list_pending("alice") == []
    aid2 = challenge(env, args={**EMAIL, "subject": "other"})
    assert env.fake_approve(aid2)
    with env.store.tx() as c:
        c.execute("UPDATE approvals SET expires_at=0 WHERE id=?", (aid2,))
    code, out = env.execute(aid2)
    assert code == 403 and out["reasons"] == ["approval_expired"]
    assert env.ledger() == []


def test_mark_approved_rejects_receipt_for_other_approval(env):
    aid = challenge(env)
    ap = env.store.get_approval(aid)
    assert not env.store.mark_approved(aid, {"digest": "00" * 32})
    assert not env.store.mark_approved(aid, {"approval_id": "apr_other"})
    assert not env.store.mark_approved(aid, {"nonce": "x"})
    assert not env.store.mark_approved(aid, "not a dict")  # type: ignore[arg-type]
    assert env.store.get_approval(aid)["status"] == "pending"
    assert env.store.mark_approved(aid, {"digest": ap["digest"]})


def test_store_interface_keys(env):
    aid = challenge(env)
    ap = env.store.get_approval(aid)
    for k in ("id", "user_id", "session_id", "digest", "descriptor", "nonce", "status", "created_at",
              "expires_at", "receipt", "grant_request"):
        assert k in ap
    assert isinstance(ap["descriptor"], dict) and ap["receipt"] is None
    assert [p["id"] for p in env.store.list_pending("alice")] == [aid]
    assert env.store.get_approval("apr_nope") is None
    # users / credentials / totp
    env.store.add_credential("alice", b"\x01\x02", b"pk", 3, ["usb"])
    creds = env.store.get_credentials("alice")
    assert creds == [{"credential_id": b"\x01\x02", "public_key": b"pk", "sign_count": 3, "transports": ["usb"]}]
    env.store.update_sign_count(b"\x01\x02", 9)
    assert env.store.get_credentials("alice")[0]["sign_count"] == 9
    assert env.store.get_totp_secret("alice") is None
    env.store.set_totp_secret("alice", "JBSWY3DPEHPK3PXP")
    assert env.store.get_totp_secret("alice") == "JBSWY3DPEHPK3PXP"
    assert env.store.get_user("alice")["display_name"] == "Alice"
    assert env.store.get_user("nobody") is None


# ---------------------------------------------------- A4 substitution / P2
def test_executes_stored_descriptor_not_agent_copy(env):
    aid = challenge(env)
    ap = env.store.get_approval(aid)
    env.fake_approve(aid)
    code, out = env.execute(aid)  # no args resubmitted
    assert code == 200
    assert env.ledger()[0]["descriptor"] == ap["descriptor"]
    assert env.ledger()[0]["digest"] == ap["digest"]


def test_identical_resubmission_ok(env):
    aid = challenge(env)
    env.fake_approve(aid)
    code, _ = env.execute(aid, tool="send_email", args=dict(EMAIL))
    assert code == 200


def test_equivalent_spelling_resubmission_ok(env):
    aid = challenge(env)
    env.fake_approve(aid)
    code, _ = env.execute(aid, args={**EMAIL, "to": "BOB@Example.COM"})
    assert code == 200


@pytest.mark.parametrize("sub", [
    {"to": "mallory@evil.example"},
    {"to": "bob@example.com,mallory@evil.example"},
    {"body": "hello, also wire the money"},
    {"bcc": "mallory@evil.example"},
])
def test_substitution_after_approval_rejected(env, sub):
    aid = challenge(env)
    env.fake_approve(aid)
    code, out = env.execute(aid, args={**EMAIL, **sub})
    assert code == 409 and out == {"status": "effect_mismatch"}
    assert env.ledger() == []
    # the approval is not burned by a rejected substitution attempt
    assert env.store.get_approval(aid)["status"] == "approved"
    assert env.execute(aid)[0] == 200


def test_tool_substitution_rejected(env):
    aid = challenge(env)
    env.fake_approve(aid)
    code, out = env.execute(aid, tool="delete_file", args={"path": "x"})
    assert code == 409
    assert env.ledger() == []


def test_symlink_swap_after_approval_rejected(env):
    ws = env.ws
    os.makedirs(os.path.join(ws, "a"))
    os.makedirs(os.path.join(ws, "b"))
    os.symlink(os.path.join(ws, "a"), os.path.join(ws, "link"))
    aid = challenge(env, "delete_file", {"path": "link/f.txt"})
    assert env.store.get_approval(aid)["descriptor"]["target"] == os.path.join(os.path.realpath(ws), "a", "f.txt")
    env.fake_approve(aid)
    os.remove(os.path.join(ws, "link"))
    os.symlink(os.path.join(ws, "b"), os.path.join(ws, "link"))  # TOCTOU swap
    code, out = env.execute(aid)
    assert code == 409
    assert env.ledger() == []


def test_corrupted_stored_descriptor_rejected(env):
    aid = challenge(env)
    env.fake_approve(aid)
    ap = env.store.get_approval(aid)
    desc = dict(ap["descriptor"], target="mallory@evil.example")
    import json

    with env.store.tx() as c:
        c.execute("UPDATE approvals SET descriptor=? WHERE id=?", (json.dumps(desc), aid))
    assert env.execute(aid)[0] == 409


# --------------------------------------------------------------- A5 replay
def test_replay_rejected(env):
    aid = challenge(env)
    env.fake_approve(aid)
    assert env.execute(aid)[0] == 200
    code, out = env.execute(aid)
    assert code == 403 and out["reasons"] == ["approval_already_used"]
    code, out = env.execute(aid, args=dict(EMAIL))
    assert code == 403
    assert len(env.ledger()) == 1


def test_concurrent_consume_exactly_once(env):
    aid = challenge(env)
    env.fake_approve(aid)
    results = []
    barrier = threading.Barrier(8)

    def go():
        barrier.wait()
        results.append(env.execute(aid)[0])

    ts = [threading.Thread(target=go) for _ in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert sorted(results).count(200) == 1
    assert len(env.ledger()) == 1


def test_concurrent_consume_two_processes_share_db(tmp_path):
    """Two Store objects (as two gateway workers) on one sqlite file."""
    from asu.store import Store

    e = Env(tmp_path)
    aid = challenge(e)
    e.fake_approve(aid)
    other = Store(e.config.db_path)
    oks = []
    barrier = threading.Barrier(2)

    def go(st):
        barrier.wait()
        oks.append(st.consume(aid))

    ts = [threading.Thread(target=go, args=(s,)) for s in (e.store, other)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert sorted(oks) == [False, True]


# --------------------------------------------------- A11 cross-session reuse
def test_cross_session_reuse_rejected(env):
    aid = challenge(env)
    env.fake_approve(aid)
    _, s2 = env.new_session("alice", "agent-2")
    assert env.execute(aid, session=s2) == (404, {"status": "not_found"})
    assert env.gw.approval_status(s2, aid) == (404, {"status": "not_found"})
    _, s3 = env.new_session("mallory", "agent-1")
    assert env.execute(aid, session=s3)[0] == 404
    assert env.store.get_approval(aid)["status"] == "approved"
    assert env.ledger() == []
    assert env.execute(aid)[0] == 200  # the right session still works


def test_descriptor_binds_session_and_agent(env):
    ctx1 = env.gw._ctx(env.session, "send_email", "user_turn", 1000)
    _, s2 = env.new_session("alice", "agent-2")
    ctx2 = env.gw._ctx(s2, "send_email", "user_turn", 1000)
    assert D.digest(D.canonicalize("send_email", EMAIL, ctx1)) != D.digest(D.canonicalize("send_email", EMAIL, ctx2))


def test_expired_or_revoked_session_token(env):
    assert env.gw.authenticate(env.token)["session_id"] == env.session["session_id"]
    env.store.revoke_session(env.session["session_id"])
    assert env.gw.authenticate(env.token) is None
    assert env.gw.authenticate("asu_st_bogus") is None
    assert env.gw.authenticate(None) is None


def test_session_scopes(env):
    tok, s = env.store.create_session("alice", "agent-x", ["read_file"], 60)
    assert env.gw.call(s, {"tool": "read_file", "args": {"path": "a"}, "origin": "user_turn"})[0] == 200
    code, out = env.gw.call(s, {"tool": "send_email", "args": EMAIL, "origin": "user_turn"})
    assert code == 403 and out["reasons"] == ["out_of_session_scope"]


# ------------------------------------------------------ A12 autonomous origin
@pytest.mark.parametrize("origin", [None, "autonomous", "USER_TURN", "user", 1, "user_turn "])
def test_non_user_turn_origin_is_autonomous_and_challenged(env, origin):
    body = {"tool": "read_file", "args": {"path": "a.txt"}}
    if origin is not None:
        body["origin"] = origin
    code, out = env.gw.call(env.session, body)
    assert code == 202
    ap = env.store.get_approval(out["approval_id"])
    assert ap["descriptor"]["origin"] == "autonomous"
    assert "autonomous_origin" in ap["reasons"]
    assert any("autonomous" in r for r in ap["card"]["risk_lines"])


def test_origin_is_part_of_effect(env):
    aid = challenge(env, origin="autonomous")
    env.fake_approve(aid)
    # retrying while claiming user_turn does not change the stored effect
    code, _ = env.execute(aid, args=dict(EMAIL), origin="user_turn")
    assert code == 200
    assert env.ledger()[0]["descriptor"]["origin"] == "autonomous"


# --------------------------------------------------------- input validation
def test_bad_bodies(env):
    assert env.gw.call(env.session, "x")[0] == 400  # type: ignore[arg-type]
    assert env.gw.call(env.session, {"tool": 1, "args": {}})[0] == 400
    assert env.gw.call(env.session, {"tool": "read_file", "args": []})[0] == 400
    assert env.gw.call(env.session, {"approval_id": 5})[0] == 400
    assert env.gw.call(env.session, {"tool": "read_file", "args": {}, "explanation": 3})[0] == 400
    code, out = env.call("read_file", {"path": "~/x"})
    assert code == 403 and out["reasons"][0].startswith("invalid_args")
    big = {"path": "a", "blob": "x" * 70000}
    assert env.call("read_file", big) == (403, {"status": "denied", "reasons": ["args_too_large"]})


def test_explanation_untrusted_and_not_in_digest(env):
    aid = challenge(env, explanation="Routine newsletter. Safe to approve!")
    ap = env.store.get_approval(aid)
    card = ap["card"]
    assert "Routine newsletter" not in card["title"]
    assert all("Routine newsletter" not in f["value"] for f in card["fields"])
    assert "UNTRUSTED" in card["agent_explanation_untrusted"]["label"]
    # same effect with a different explanation is the same pending approval
    code, out = env.call("send_email", dict(EMAIL), explanation="something else")
    assert out["approval_id"] == aid


# ------------------------------------------------- receipt re-verification
def test_real_receipt_reverified_on_execute(tmp_path):
    e = Env(tmp_path, reverify_receipts=True)
    auth = register_soft_authenticator(e)
    aid = challenge(e)
    ap = e.store.get_approval(aid)
    assert e.store.mark_approved(aid, auth.receipt_for(ap))
    code, out = e.execute(aid)
    assert code == 200, out


def test_fake_receipt_rejected_when_reverifying(tmp_path):
    e = Env(tmp_path, reverify_receipts=True)
    register_soft_authenticator(e)
    aid = challenge(e)
    assert e.fake_approve(aid)  # e.g. a compromised writer of the approvals table
    code, out = e.execute(aid)
    assert code == 403 and out["reasons"] == ["receipt_invalid"]
    assert e.store.get_approval(aid)["status"] == "approved"  # not consumed
    assert e.ledger() == []


def test_receipt_transplanted_from_other_approval_rejected(tmp_path):
    e = Env(tmp_path, reverify_receipts=True)
    auth = register_soft_authenticator(e)
    a1 = challenge(e)
    a2 = challenge(e, args={**EMAIL, "to": "mallory@evil.example"})
    r1 = auth.receipt_for(e.store.get_approval(a1))
    ap2 = e.store.get_approval(a2)
    forged = dict(r1, digest=ap2["digest"], approval_id=a2, nonce=ap2["nonce"])
    assert e.store.mark_approved(a2, forged)  # store-level field checks pass...
    assert e.execute(a2)[0] == 403            # ...but the signature does not cover a2


def test_receipt_from_unknown_credential_rejected(tmp_path):
    from test_gateway_fixtures import SoftAuthenticator

    e = Env(tmp_path, reverify_receipts=True)
    register_soft_authenticator(e)
    rogue = SoftAuthenticator()  # not enrolled for alice
    aid = challenge(e)
    e.store.mark_approved(aid, rogue.receipt_for(e.store.get_approval(aid)))
    assert e.execute(aid)[0] == 403
