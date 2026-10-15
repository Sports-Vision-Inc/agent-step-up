"""RED TEAM (crypto lens): user verification is not required by default.

``Config.require_user_verification`` defaults to False and every ceremony asks
for ``userVerification: "preferred"``. An approval assertion with UP=1, UV=0
(touch only, no PIN/biometric) is accepted, stored as a valid receipt and
executed. The SPEC's *principal factor* is "proof the human principal (not a
speaker claiming to be them) is present"; UP alone proves only that someone
touched an authenticator holding the credential (e.g. an unlocked phone or a
security key left plugged in).

Secure behaviour asserted: under the default config an approval whose
authenticatorData lacks the UV flag is rejected.
"""
from __future__ import annotations

import os
import sys

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from fakes_authn import SoftAuthenticator  # noqa: E402

from asu.app import create_app  # noqa: E402
from asu.config import Config  # noqa: E402

ORIGIN = "http://localhost:8000"
H = {"Origin": ORIGIN}


def test_default_config_requires_uv_for_approval(tmp_path):
    cfg = Config(db_path=str(tmp_path / "asu.db"), ledger_path=str(tmp_path / "l.jsonl"),
                 workspace_root=str(tmp_path), token_key_path=str(tmp_path / "k.pem"),
                 policy={"tools": {"send_email": {"class": "send", "default": "challenge"}}})
    app = create_app(cfg)
    human = TestClient(app, base_url=ORIGIN)
    auth = SoftAuthenticator()
    # D-005 item 2: the legitimate human enrolls with the out-of-band one-time
    # enrollment token (setup only; the UV assertion below is unchanged).
    tok = app.state.store.create_enrollment_token("alice")
    r = human.post("/v1/authn/register/options", json={"user_id": "alice", "enrollment_token": tok}, headers=H)
    assert human.post("/v1/authn/register/verify", json={"credential": auth.create(r.json())},
                      headers=H).status_code == 200
    r = human.post("/v1/sessions", json={"agent_id": "agent-1"}, headers=H)
    token = r.json()["session_token"]

    agent = TestClient(app, base_url=ORIGIN)
    r = agent.post("/v1/tools/call", headers={"Authorization": f"Bearer {token}"},
                   json={"tool": "send_email", "args": {"to": "bob@example.com"}, "origin": "user_turn"})
    ap_id = r.json()["approval_id"]

    r = human.post(f"/v1/authn/approvals/{ap_id}/options", json={"grant": False}, headers=H)
    a = auth.get(r.json(), uv=False)
    r = human.post(f"/v1/authn/approvals/{ap_id}/verify", json={"credential": a, "grant": False}, headers=H)
    assert r.status_code != 200, "approval accepted with UP only (UV=0) under the default config"
