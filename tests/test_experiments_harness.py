"""The experiment harness drives the real gateway with real WebAuthn."""
from __future__ import annotations

import pytest

from experiments.harness import Trial
from experiments.policies import scenario_policy

SEND = {"to": "boss@example.test", "subject": "Weekly report", "body": "<weekly report placeholder>"}


def test_full_asu_path_real_passkey_and_offline_receipt(tmp_path):
    from asu.authn import verify_receipt

    with Trial("asu", scenario_policy(), tmp_root=str(tmp_path)) as t:
        a = t.new_agent()
        r = a.call("send_email", SEND, explanation="report")
        assert r.code == 202 and set(r.body) == {"status", "approval_id"}
        aid = r.body["approval_id"]
        pend = t.human.pending()
        assert [p["id"] for p in pend] == [aid] and pend[0]["card"]["trusted"] is True
        assert t.human.approve(aid)
        assert t.human.auth.assertions == 1
        ap = t.store.get_approval(aid)
        pub = t.store.get_credentials(t.user_id)[0]["public_key"]
        assert verify_receipt(ap["receipt"], pub, ap["digest"], ap["id"], ap["nonce"])
        assert a.execute(aid).code == 200
        assert a.execute(aid).code == 403  # replay
        led = t.ledger()
        assert len(led) == 1 and led[0]["descriptor"]["target"] == "boss@example.test"
        assert led[0]["via"] == "approval"


def test_agent_cannot_use_human_routes(tmp_path):
    with Trial("asu", scenario_policy(), tmp_root=str(tmp_path)) as t:
        a = t.new_agent()
        r = a.call("send_email", SEND)
        aid = r.body["approval_id"]
        assert a.raw("GET", "/v1/authn/pending").code == 401
        assert a.raw("POST", f"/v1/authn/approvals/{aid}/options", json={"grant": False},
                     headers={"Content-Type": "application/json"}).code == 401
        assert a.chat_confirm(aid, "yes").code == 404  # chat-confirm exists only in that baseline
        assert a.status(aid) == "pending"
        assert t.ledger() == []


def test_totp_clock_patch_is_restored(tmp_path):
    import time

    import asu.authn.routes as routes
    import asu.gateway as gateway

    with Trial("totp", scenario_policy(), tmp_root=str(tmp_path)) as t:
        a = t.new_agent()
        for i in range(3):  # three approvals in quick succession need three distinct time steps
            r = a.call("send_email", dict(SEND, subject=f"s{i}"))
            assert r.code == 202
            assert t.human.approve(r.body["approval_id"])
            assert a.execute(r.body["approval_id"]).code == 200
        assert len(t.ledger()) == 3
    assert routes.time is time and gateway.time is time


def test_trial_isolation(tmp_path):
    with Trial("none", scenario_policy(), tmp_root=str(tmp_path)) as t1:
        t1.new_agent().call("send_email", SEND)
        assert len(t1.ledger()) == 1
    with Trial("none", scenario_policy(), tmp_root=str(tmp_path)) as t2:
        assert t2.ledger() == []
