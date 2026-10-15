"""Policy decisions (SPEC section 9)."""
from __future__ import annotations

import copy
import os

import pytest

from asu.descriptor import canonicalize
from asu.policy import decide, glob_to_regex, host_matches, path_matches

from test_gateway_fixtures import TEST_POLICY, Env, env  # noqa: F401


def mk(env, tool, args, origin="user_turn"):
    ctx = env.gw._ctx(env.session, tool, origin, 1_000_000)
    return canonicalize(tool, args, ctx)


def dec(env, tool, args, origin="user_turn"):
    d = mk(env, tool, args, origin)
    return decide(d, env.config.policy, env.store, "alice", None, env.config.workspace_root)


def test_globs():
    assert path_matches("/etc/passwd", "/etc/**")
    assert path_matches("/etc", "/etc/**")
    assert not path_matches("/etcetera/x", "/etc/**")
    assert path_matches("/home/u/.ssh/id_rsa", "**/.ssh/**")
    assert path_matches("/.ssh/x", "**/.ssh/**")
    assert not path_matches("/home/u/x.ssh/id", "**/.ssh/**")
    assert path_matches("/a/b.txt", "/a/*.txt") and not path_matches("/a/b/c.txt", "/a/*.txt")
    assert glob_to_regex("/x/[a]").match("/x/[a]")  # brackets are literal
    assert host_matches("a.evil.example", "evil.example") and not host_matches("notevil.example", "evil.example")


def test_basic_outcomes(env):
    assert dec(env, "read_file", {"path": "a.txt"}).outcome == "allow"
    d = dec(env, "send_email", {"to": "bob@x.com", "body": "hi"})
    assert d.outcome == "challenge" and "tool_default_challenge" in d.reasons
    assert any(r.startswith("first_time_recipient:bob@x.com") for r in d.reasons)
    assert dec(env, "nope", {}).outcome == "deny"
    assert dec(env, "forbidden_tool", {}).outcome == "deny"


def test_unknown_tool_challenge_mode(tmp_path):
    pol = copy.deepcopy(TEST_POLICY)
    pol["unknown_tool"] = "challenge"
    e = Env(tmp_path, policy=pol)
    d = dec(e, "mystery", {"x": 1})
    assert d.outcome == "challenge" and not d.grantable


def test_path_deny_via_dotdot_and_symlink(env, tmp_path):
    d = dec(env, "write_file", {"path": "../" * 30 + "etc/cron.d/x"})
    assert d.outcome == "deny" and d.reasons[0].startswith("path_denied:/etc/**")
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    os.symlink(str(home / ".ssh"), os.path.join(env.ws, "notes"))
    d = dec(env, "write_file", {"path": "notes/authorized_keys"})
    assert d.outcome == "deny"  # lexical path looks harmless, resolved one is ~/.ssh


def test_host_deny(env):
    assert dec(env, "http_request", {"url": "https://API.Evil.Example./x"}).outcome == "deny"
    assert dec(env, "http_request", {"url": "https://evil.example.com/x"}).outcome == "allow"


def test_step_up_triggers(env):
    # destructive class
    d = dec(env, "delete_file", {"path": "a"})
    assert "destructive_class:delete" in d.reasons
    # amount over + destructive pay
    d = dec(env, "transfer_money", {"amount": "150.00", "currency": "USD", "payee": "acct-1"})
    assert "amount_over:100" in d.reasons and d.outcome == "challenge"
    # autonomous origin (also the default when origin is missing/garbage)
    d = dec(env, "write_file", {"path": "a"}, origin="autonomous")
    assert d.outcome == "challenge" and "autonomous_origin" in d.reasons and not d.grantable
    # outside workspace
    d = dec(env, "write_file", {"path": "/tmp/elsewhere.txt"})
    assert any(r.startswith("outside_workspace") for r in d.reasons)
    # reading outside the workspace is not stepped up (read-only leakage out of scope)
    assert dec(env, "read_file", {"path": "/tmp/elsewhere.txt"}).outcome == "allow"


def test_first_time_recipient_learns_after_execution(env):
    code, body = env.call("send_message", {"to": "bob@x.com", "text": "1"})
    assert code == 202  # first time
    env.fake_approve(body["approval_id"])
    assert env.execute(body["approval_id"])[0] == 200
    code, body = env.call("send_message", {"to": "BOB@X.COM", "text": "2"})
    assert code == 200  # now known (case-normalised)
    code, _ = env.call("send_message", {"to": ["bob@x.com", "carol@x.com"], "text": "3"})
    assert code == 202  # any new recipient triggers


def test_aggregate_count_window(tmp_path):
    pol = copy.deepcopy(TEST_POLICY)
    pol["step_up"]["aggregate"] = {"window_s": 600, "max_effects": 3, "max_amount": 1000}
    e = Env(tmp_path, policy=pol)
    for i in range(3):
        assert e.call("write_file", {"path": f"f{i}"})[0] == 200
    code, body = e.call("write_file", {"path": "f3"})
    assert code == 202
    d = e.store.get_approval(body["approval_id"])
    assert any(r.startswith("aggregate_effects") for r in d["reasons"])
    # reads are not counted / not limited
    assert e.call("read_file", {"path": "f0"})[0] == 200


def test_risk_score_bounded(env):
    d = dec(env, "transfer_money", {"amount": "5000", "currency": "USD", "payee": "x"}, origin="autonomous")
    assert 0 < d.risk <= 100
