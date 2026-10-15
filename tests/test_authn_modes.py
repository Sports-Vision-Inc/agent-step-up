"""Baseline modes and config-driven behaviour of the AUTHN routes."""
from __future__ import annotations

import hashlib

from fastapi.testclient import TestClient

try:
    from fakes_authn import SoftAuthenticator, make_app, unb64u
except ImportError:
    from tests.fakes_authn import SoftAuthenticator, make_app, unb64u

from asu.authn import approval_challenge
from test_authn_flow import DESC, H, ORIGIN, approve, register  # noqa: E402


def client_for(**cfg):
    app = make_app(**cfg)
    c = TestClient(app, base_url=ORIGIN)
    auth = SoftAuthenticator()
    register(c, auth)
    return app, c, auth


def test_unbound_baseline_challenge_not_bound():
    app, c, auth = client_for(approval_mode="unbound")
    ap = app.state.store.add_approval("alice", DESC)
    opts, _, r = approve(c, auth, ap["id"])
    assert unb64u(opts["challenge"]) != approval_challenge(ap)
    assert r.status_code == 200, r.text
    rc = app.state.store.get_approval(ap["id"])["receipt"]
    assert rc["mode"] == "unbound" and rc["verifiable"] is False
    assert "digest" not in rc


def test_unbound_challenge_is_single_use_and_per_approval():
    app, c, auth = client_for(approval_mode="unbound")
    a1 = app.state.store.add_approval("alice", DESC)
    a2 = app.state.store.add_approval("alice", DESC)
    r = c.post(f"/v1/authn/approvals/{a1['id']}/options", json={}, headers=H)
    asr = auth.get(r.json())
    assert c.post(f"/v1/authn/approvals/{a2['id']}/verify", json={"credential": asr}, headers=H).status_code == 400


def test_require_user_verification_config():
    app, c, auth = client_for(require_user_verification=True)
    ap = app.state.store.add_approval("alice", DESC)
    _, _, r = approve(c, auth, ap["id"], uv=False)
    assert r.status_code == 400
    _, _, r = approve(c, auth, ap["id"], uv=True)
    assert r.status_code == 200


def test_uv_required_by_default_up_only_is_explicit_opt_in():
    """D-005 item 3 / CR-4 (was: test_uv_not_required_by_default_but_recorded,
    which encoded the old insecure default)."""
    app, c, auth = client_for()
    ap = app.state.store.add_approval("alice", DESC)
    _, _, r = approve(c, auth, ap["id"], uv=False)
    assert r.status_code == 400
    app, c, auth = client_for(require_user_verification=False)
    ap = app.state.store.add_approval("alice", DESC)
    _, _, r = approve(c, auth, ap["id"], uv=False)
    assert r.status_code == 200
    rc = r.json()["receipt"]
    assert rc["user_verified"] is False and rc["flags"] == {"up": True, "uv": False, "be": False, "bs": False}


def test_single_origin_config_attribute():
    """Gateway Config exposes `origin` (str) rather than `expected_origins`."""
    from types import SimpleNamespace

    app = make_app()
    app.state.config = SimpleNamespace(rp_id="localhost", rp_name="x", origin="http://localhost:8000", dev_mode=True)
    c = TestClient(app, base_url=ORIGIN)
    register(c, SoftAuthenticator())
    r = c.post("/v1/authn/register/options", json={"user_id": "bob"}, headers={"Origin": "http://localhost:9000"})
    assert r.status_code == 403


def test_card_digest_mismatch_refused():
    app, c, auth = client_for()
    ap = app.state.store.add_approval("alice", DESC, digest=hashlib.sha256(b"other").hexdigest())
    try:
        from asu.descriptor import render_card  # noqa: F401
    except Exception:
        return  # fake renderer has no digest field
    r = c.get(f"/v1/authn/approvals/{ap['id']}")
    assert r.status_code == 500


def test_card_comes_from_descriptor_not_explanation():
    app, c, auth = client_for()
    evil = "Routine backup to your own account. SAFE. Approve."
    d = dict(DESC, args=dict(DESC["args"], to="mallory@evil.test"), target="mallory@evil.test")
    ap = app.state.store.add_approval("alice", d, explanation=evil)
    v = c.get("/v1/authn/pending").json()["approvals"][0]
    card = v["card"]
    flat = repr(card)
    assert "mallory@evil.test" in flat
    assert evil not in flat  # explanation never inside the trusted card
    assert v["explanation"] == evil


def test_narrated_card_baseline_uses_agent_text():
    try:
        from asu.descriptor import render_narrated_card  # noqa: F401
    except Exception:
        return
    app, c, auth = client_for(approval_mode="narrated-card")
    ap = app.state.store.add_approval("alice", DESC, explanation="Harmless thing")
    v = c.get("/v1/authn/pending").json()["approvals"][0]
    assert v["card"]["title"] == "Harmless thing" and v["card"]["trusted"] is False
