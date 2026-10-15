"""D-005 item 2 (closed enrollment), item 1 (v1 receipts rejected), CR-5
(logout revocation), CR-7 (offline verification reports flags / grants)."""
from __future__ import annotations

import json
import os
import sys
import time

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fakes_authn import SoftAuthenticator, make_app  # noqa: E402

from asu.app import create_app  # noqa: E402
from asu.authn import SESSION_COOKIE, verify_receipt  # noqa: E402
from asu.config import Config  # noqa: E402

ORIGIN = "http://localhost:8000"
H = {"Origin": ORIGIN}
POLICY = {"tools": {"send_email": {"class": "send", "default": "challenge"}}}


def gw(tmp_path, **kw):
    cfg = Config(db_path=str(tmp_path / "asu.db"), ledger_path=str(tmp_path / "l.jsonl"),
                 token_key_path=str(tmp_path / "k.pem"), workspace_root=str(tmp_path), policy=POLICY, **kw)
    app = create_app(cfg)
    return app, TestClient(app, base_url=ORIGIN)


def enroll(c, auth, user, **body):
    r = c.post("/v1/authn/register/options", json={"user_id": user, **body}, headers=H)
    if r.status_code != 200:
        return r
    return c.post("/v1/authn/register/verify", json={"credential": auth.create(r.json())}, headers=H)


def test_one_time_token_is_single_use_and_user_bound(tmp_path):
    app, c = gw(tmp_path)
    st = app.state.store
    assert enroll(c, SoftAuthenticator(), "alice").status_code == 403          # no token
    tok = st.create_enrollment_token("alice")
    assert enroll(c, SoftAuthenticator(), "bob", enrollment_token=tok).status_code == 403  # other user
    assert enroll(c, SoftAuthenticator(), "alice", enrollment_token=tok).status_code == 200
    c2 = TestClient(app, base_url=ORIGIN)
    st.create_user("carol", "Carol")
    assert enroll(c2, SoftAuthenticator(), "carol", enrollment_token=tok).status_code == 403  # used
    assert len(st.get_credentials("alice")) == 1


def test_token_consumed_once_even_with_two_ceremonies(tmp_path):
    app, c = gw(tmp_path)
    tok = app.state.store.create_enrollment_token("alice")
    a1, a2 = SoftAuthenticator(), SoftAuthenticator()
    o1 = c.post("/v1/authn/register/options", json={"user_id": "alice", "enrollment_token": tok}, headers=H).json()
    o2 = c.post("/v1/authn/register/options", json={"user_id": "alice", "enrollment_token": tok}, headers=H).json()
    assert c.post("/v1/authn/register/verify", json={"credential": a1.create(o1)}, headers=H).status_code == 200
    other = TestClient(app, base_url=ORIGIN)  # attacker racing with the second ceremony, not signed in
    assert other.post("/v1/authn/register/verify", json={"credential": a2.create(o2)}, headers=H).status_code == 403
    assert len(app.state.store.get_credentials("alice")) == 1


def test_expired_token_refused(tmp_path):
    app, c = gw(tmp_path)
    tok = app.state.store.create_enrollment_token("alice", ttl_s=-1)
    assert enroll(c, SoftAuthenticator(), "alice", enrollment_token=tok).status_code == 403


def test_dev_mode_only_for_new_user_ids(tmp_path, capsys):
    app, c = gw(tmp_path, dev_mode=True)
    assert "INSECURE" in capsys.readouterr().err
    assert enroll(c, SoftAuthenticator(), "newbie").status_code == 200
    # a provisioned user (has agent sessions, no passkey) is never open, even in dev mode
    app.state.store.create_user("alice", "Alice")
    assert enroll(TestClient(app, base_url=ORIGIN), SoftAuthenticator(), "alice").status_code == 403


def test_cli_enroll_link(tmp_path, capsys):
    from asu.cli import main

    db = str(tmp_path / "x.db")
    assert main(["enroll-link", "--db", db, "--user", "alice"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["enrollment_url"].startswith("http://localhost:8000/app/#enroll=asu_en_")
    from asu.store import Store

    assert Store(db).check_enrollment_token("alice", out["enrollment_token"])


def test_v1_receipt_rejected():
    from test_authn_flow import DESC  # noqa: F401  (shape only)

    assert not verify_receipt({"v": 1}, b"", "ab" * 32, "apr_1", "n")


def test_logout_revokes_signed_cookie_too():
    app = make_app()  # FakeStore: no server-side logins -> signed cookies
    c = TestClient(app, base_url=ORIGIN)
    assert enroll(c, SoftAuthenticator(), "alice").status_code == 200
    stolen = c.cookies.get(SESSION_COOKIE)
    assert stolen.startswith("sg.")
    assert c.post("/v1/authn/logout", json={}, headers=H).status_code == 200
    o = TestClient(app, base_url=ORIGIN)
    o.cookies.set(SESSION_COOKIE, stolen)
    assert o.get("/v1/authn/me").status_code == 401


def test_verify_bundle_reports_flags_and_refuses_hidden_grant(tmp_path):
    from test_gateway_fixtures import Env, register_soft_authenticator

    from asu.cli import verify_bundle
    from asu.gateway import export_bundle

    e = Env(tmp_path, reverify_receipts=True)
    auth = register_soft_authenticator(e)
    c, o = e.call("send_email", {"to": "bob@example.com", "subject": "s", "body": "b"})
    ap = e.store.get_approval(o["approval_id"])
    assert ap["grant_request"] is not None
    assert e.store.mark_approved(ap["id"], auth.receipt_for(ap, with_grant=True), ap["grant_request"])
    ap = e.store.get_approval(ap["id"])
    b = export_bundle(ap, e.store.get_credentials("alice"))
    pk = [auth.cose_public_key()]
    res = verify_bundle(b, pk, rp_id="localhost")
    assert res["ok"] and res["grant_digest"] and res["flags"]["uv"] and res["grant"] == ap["grant"]
    assert not verify_bundle(b, pk, rp_id=None)["ok"]
    assert not verify_bundle(b, [], rp_id="localhost")["ok"]
    hidden = dict(b, grant=None)
    r = verify_bundle(hidden, pk, rp_id="localhost")
    assert not r["ok"] and "does not disclose" in r["error"]
    assert time.time() > 0
