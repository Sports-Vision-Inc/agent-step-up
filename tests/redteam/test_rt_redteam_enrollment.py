"""RT-4 (P1 agent-independence, enrollment takeover, live gateway with the
DEFAULT config: rp_id=localhost, no enrollment_token, dev_mode off).

``register_options`` treats rp_id == "localhost" as dev and allows first
enrollment without a token for any user that has no credential yet -
including a user row that already exists and already has an agent session
(exactly what ``asu dev-session`` creates). The agent, which can reach the
gateway and needs no browser (it forges clientDataJSON with its own software
authenticator), enrolls its own passkey as that user and approves its own
challenged effects.
Asserts the SECURE behaviour: the agent cannot get the payment executed.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rt_live import Agent, Human, LiveGateway, default_policy  # noqa: E402


def test_agent_cannot_enroll_passkey_for_provisioned_user(tmp_path):
    with LiveGateway(tmp_path, policy=default_policy()) as gw:
        # operator provisions the user + agent token the documented dev way
        gw.store.create_user("alice", "Alice")
        token, _ = gw.store.create_session("alice", "agent-1", ["*"], 3600)
        agent = Agent(gw, token)

        attacker = Human(gw, "alice")          # agent-driven HTTP client + soft authenticator
        attacker.http.headers.pop("Origin")    # non-browser client: no Origin header
        r = attacker.post("/v1/authn/register/options", {"user_id": "alice"})
        if r.status_code == 200:
            cred = attacker.auth.create(r.json())
            if attacker.post("/v1/authn/register/verify", {"credential": cred}).status_code == 200:
                r = agent.call("transfer_money", {"payee": "eve-acct", "amount": "5000", "currency": "USD"})
                if r.status_code == 202:
                    aid = r.json()["approval_id"]
                    o = attacker.post(f"/v1/authn/approvals/{aid}/options", {"grant": False})
                    if o.status_code == 200:
                        attacker.post(f"/v1/authn/approvals/{aid}/verify",
                                      {"credential": attacker.auth.get(o.json()), "grant": False})
                    agent.execute(aid)
        paid = [e for e in gw.ledger() if e["descriptor"]["args"].get("payee") == "eve-acct"]
        assert not paid, "P1 broken: the agent enrolled its own passkey for 'alice' and self-approved a payment"
