"""TOTP insecure-baseline routes: gated by approval_mode, replay-protected,
lockout after repeated failures, and (by design) NOT effect-bound."""
from __future__ import annotations

import pyotp
from fastapi.testclient import TestClient

try:
    from fakes_authn import SoftAuthenticator, make_app
except ImportError:
    from tests.fakes_authn import SoftAuthenticator, make_app

from test_authn_flow import DESC, H, ORIGIN, register  # noqa: E402


def setup(mode="totp"):
    app = make_app(approval_mode=mode)
    c = TestClient(app, base_url=ORIGIN)
    register(c, SoftAuthenticator())
    return app, c


def test_totp_disabled_unless_baseline_mode():
    app, c = setup(mode="asu")
    assert c.post("/v1/authn/totp/enroll", json={}, headers=H).status_code == 404
    ap = app.state.store.add_approval("alice", DESC)
    r = c.post(f"/v1/authn/totp/approvals/{ap['id']}/verify", json={"code": "123456"})
    assert r.status_code == 404


def test_totp_baseline_approves_and_is_relayable():
    app, c = setup()
    r = c.post("/v1/authn/totp/enroll", json={}, headers=H)
    assert r.status_code == 200 and "INSECURE" in r.json()["warning"]
    secret = r.json()["secret"]
    ap = app.state.store.add_approval("alice", DESC)
    # an unauthenticated client (e.g. the agent relaying the code) can approve:
    relay = TestClient(app, base_url=ORIGIN)
    code = pyotp.TOTP(secret).now()
    r = relay.post(f"/v1/authn/totp/approvals/{ap['id']}/verify", json={"code": code})
    assert r.status_code == 200, r.text
    rc = app.state.store.get_approval(ap["id"])["receipt"]
    assert rc["mode"] == "totp" and rc["verifiable"] is False
    # same code cannot be reused for another approval
    ap2 = app.state.store.add_approval("alice", DESC)
    r = relay.post(f"/v1/authn/totp/approvals/{ap2['id']}/verify", json={"code": code})
    assert r.status_code == 400


def test_totp_lockout():
    app, c = setup()
    c.post("/v1/authn/totp/enroll", json={}, headers=H)
    ap = app.state.store.add_approval("alice", DESC)
    for i in range(4):
        r = c.post(f"/v1/authn/totp/approvals/{ap['id']}/verify", json={"code": "000000"})
        assert r.status_code == 400
    r = c.post(f"/v1/authn/totp/approvals/{ap['id']}/verify", json={"code": "000000"})
    assert r.status_code == 403
    assert app.state.store.get_approval(ap["id"])["status"] == "denied"
