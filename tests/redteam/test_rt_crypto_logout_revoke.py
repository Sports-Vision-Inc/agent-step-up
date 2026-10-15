"""RED TEAM (crypto lens): POST /v1/authn/logout only asks the browser to drop
the cookie. With the real Store the cookie is an opaque server-side web-login
token ("wl.<token>") that stays valid in ``web_logins`` until it expires
(default 8 h); there is no revoke path. A copied cookie keeps working after
the user signs out: it can mint agent session tokens (POST /v1/sessions),
read every pending card and deny approvals.

Secure behaviour asserted: after logout the old cookie value no longer
authenticates.
"""
from __future__ import annotations

import os
import sys

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from fakes_authn import SoftAuthenticator, make_app  # noqa: E402

from asu.authn import SESSION_COOKIE  # noqa: E402
from asu.store import Store  # noqa: E402

ORIGIN = "http://localhost:8000"
H = {"Origin": ORIGIN}


def test_logout_revokes_server_side_login(tmp_path):
    app = make_app()
    app.state.store = Store(str(tmp_path / "asu.db"))
    c = TestClient(app, base_url=ORIGIN)
    auth = SoftAuthenticator()
    r = c.post("/v1/authn/register/options", json={"user_id": "alice"}, headers=H)
    r = c.post("/v1/authn/register/verify", json={"credential": auth.create(r.json())}, headers=H)
    assert r.status_code == 200
    stolen = c.cookies.get(SESSION_COOKIE)
    assert stolen and stolen.startswith("wl.")
    assert c.post("/v1/authn/logout", json={}, headers=H).status_code == 200

    other = TestClient(app, base_url=ORIGIN)
    other.cookies.set(SESSION_COOKIE, stolen)
    assert other.get("/v1/authn/me").status_code == 401, "server-side login survives logout"
