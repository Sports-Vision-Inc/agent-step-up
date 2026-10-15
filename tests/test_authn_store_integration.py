"""AUTHN routes against the gateway's real sqlite Store (asu.store.Store) and
descriptor code, when available. Skipped if the gateway modules are missing."""
from __future__ import annotations

import os
import time

import pytest
from fastapi.testclient import TestClient

store_mod = pytest.importorskip("asu.store")
descriptor = pytest.importorskip("asu.descriptor")

try:
    from fakes_authn import SoftAuthenticator, make_app, unb64u
except ImportError:
    from tests.fakes_authn import SoftAuthenticator, make_app, unb64u

from asu.authn import SESSION_COOKIE, approval_challenge, current_user, grant_digest, verify_receipt
from test_authn_flow import H, ORIGIN, approve, login, register  # noqa: E402


def mk(tmp_path, **cfg):
    app = make_app(**cfg)
    app.state.store = store_mod.Store(os.path.join(str(tmp_path), "asu.db"))
    return app, TestClient(app, base_url=ORIGIN)


def create_approval(store, user="alice", to="bob@example.com", grant=False, mode="asu", explanation=None):
    now = int(time.time())
    ctx = {"principal": user, "session_id": "sess1", "agent_id": "agent-1", "origin": "user_turn",
           "issued_at": now, "expires_at": now + 300, "effect_class": "send", "workspace_root": "/tmp"}
    desc = descriptor.canonicalize("send_email", {"to": to, "subject": "hi"}, ctx)
    gr = None
    if grant:
        gr = {"v": 1, "type": "asu.grant", "principal": user, "session_id": "sess1", "agent_id": "agent-1",
              "tool": "send_email", "effect_class": "send", "target": desc["target"], "origin": "user_turn",
              "max_amount": None, "currency": None, "max_total_amount": None, "max_uses": 3,
              "issued_at": now, "not_after": now + 600}
    return store.create_approval(
        user_id=user, session_id="sess1", agent_id="agent-1", descriptor=desc,
        digest=descriptor.digest(desc), effect_key="k-" + to, raw_args={"to": to}, ctx={}, mode=mode,
        card=descriptor.render_card(desc), explanation=explanation, grant_request=gr, reasons=["first_time_recipient"])


def test_real_store_full_flow(tmp_path):
    app, c = mk(tmp_path)
    auth = SoftAuthenticator()
    register(c, auth)
    store = app.state.store
    # cookie is a server-side web login when the store supports it
    assert c.cookies.get(SESSION_COOKIE).startswith("wl.")
    c.cookies.clear()
    assert login(c, auth).status_code == 200
    ap = create_approval(store, explanation="totally fine")
    pend = c.get("/v1/authn/pending").json()["approvals"]
    assert [p["id"] for p in pend] == [ap["id"]]
    assert any("Policy: first_time_recipient" == r for r in pend[0]["card"]["risk_lines"])
    assert pend[0]["explanation"] == "totally fine"
    opts, _, r = approve(c, auth, ap["id"])
    assert unb64u(opts["challenge"]) == approval_challenge(ap)
    assert r.status_code == 200, r.text
    got = store.get_approval(ap["id"])
    assert got["status"] == "approved"
    pk = store.get_credentials("alice")[0]["public_key"]
    assert verify_receipt(got["receipt"], pk, ap["digest"], ap["id"], ap["nonce"])
    assert store.consume(ap["id"]) and not store.consume(ap["id"])


def test_real_store_grant(tmp_path):
    app, c = mk(tmp_path)
    auth = SoftAuthenticator()
    register(c, auth)
    store = app.state.store
    ap = create_approval(store, grant=True)
    _, _, r = approve(c, auth, ap["id"], grant=True)
    assert r.status_code == 200, r.text
    got = store.get_approval(ap["id"])
    assert got["grant"] == ap["grant_request"]
    assert got["receipt"]["grant_digest"] == grant_digest(ap["grant_request"])
    pk = store.get_credentials("alice")[0]["public_key"]
    assert verify_receipt(got["receipt"], pk, ap["digest"], ap["id"], ap["nonce"],
                          expected_grant_digest=grant_digest(ap["grant_request"]))


def test_real_store_cross_user_and_replay(tmp_path):
    app, c = mk(tmp_path)
    auth = SoftAuthenticator()
    register(c, auth)
    m = TestClient(app, base_url=ORIGIN)
    mauth = SoftAuthenticator()
    register(m, mauth, user="mallory")
    store = app.state.store
    ap = create_approval(store)
    assert m.post(f"/v1/authn/approvals/{ap['id']}/options", json={}, headers=H).status_code == 404
    _, a, r = approve(c, auth, ap["id"])
    assert r.status_code == 200
    ap2 = create_approval(store, to="carol@example.com")
    r = c.post(f"/v1/authn/approvals/{ap2['id']}/verify", json={"credential": a}, headers=H)
    assert r.status_code == 400
    assert store.get_approval(ap2["id"])["status"] == "pending"


def test_current_user_helper(tmp_path):
    from starlette.requests import Request

    app, c = mk(tmp_path)
    register(c, SoftAuthenticator())
    cookie = c.cookies.get(SESSION_COOKIE)

    def req(cv):
        headers = [(b"cookie", f"{SESSION_COOKIE}={cv}".encode())] if cv else []
        return Request({"type": "http", "headers": headers, "app": app})

    assert current_user(req(cookie)) == "alice"
    assert current_user(req(None)) is None
    assert current_user(req("wl.bogus")) is None
    # a signed cookie is not accepted when server-side logins are available
    assert current_user(req("sg.eyJ1IjoiYWxpY2UifQ.x.y")) is None


def test_real_store_totp_baseline_per_approval_mode(tmp_path):
    import pyotp

    app, c = mk(tmp_path, approval_mode="totp")
    register(c, SoftAuthenticator())
    secret = c.post("/v1/authn/totp/enroll", json={}, headers=H).json()["secret"]
    store = app.state.store
    asu_ap = create_approval(store, mode="asu")
    code = pyotp.TOTP(secret).now()
    # TOTP cannot approve an approval created in asu mode
    assert c.post(f"/v1/authn/totp/approvals/{asu_ap['id']}/verify", json={"code": code}).status_code == 404
    t_ap = create_approval(store, mode="totp", to="dave@example.com")
    assert c.post(f"/v1/authn/totp/approvals/{t_ap['id']}/verify", json={"code": code}).status_code == 200
    assert store.get_approval(t_ap["id"])["status"] == "approved"
