"""Defense revisions (D-005 items 1, 4, 5, 6, 9 and the crypto / red-team
findings): typed closed schemas, union of targets, single amount, grants that
bind every argument, injective card rendering, tokens, sign-count CAS, keyed
audit chain, per-user flood caps, MCP schemas. See docs/notes/defense.md."""
from __future__ import annotations

import copy
import json
import os
import random
import sqlite3
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_gateway_fixtures import Env  # noqa: E402

from asu import descriptor as D  # noqa: E402
from asu import tokens as T  # noqa: E402
from asu.config import load_policy  # noqa: E402

CTX = {"principal": "alice", "session_id": "ses_1", "agent_id": "agent-1", "origin": "user_turn",
       "issued_at": 1700000000, "expires_at": 1700000300, "effect_class": "send", "workspace_root": "/tmp"}


def default_env(tmp_path, **flood):
    pol = load_policy(None)
    pol["flood"].update({"max_pending_per_session": 5, "max_requests_per_min": 1000, "deny_lockout": 100})
    pol["flood"].update(flood)
    return Env(tmp_path, policy=pol)


# ------------------------------------------------------------ schemas (D-005 4)
def test_packaged_policy_declares_schemas_for_every_tool():
    pol = load_policy(None)
    for name, spec in pol["tools"].items():
        assert "args" in spec, name


def test_experiment_and_agentdojo_tools_have_library_schemas():
    from asu.config import load_schema_library

    lib = load_schema_library()
    pytest.importorskip("experiments")
    from experiments.policies import SCENARIO_TOOLS

    for t in SCENARIO_TOOLS:
        assert t in lib, t
    p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "experiments", "results",
                     "agentdojo_workloads.json")
    if os.path.exists(p):
        w = json.load(open(p))
        for rec in w["suites"].values():
            for t in rec["tools"]:
                assert t in lib, t


def test_unknown_argument_denied_for_typed_tool(tmp_path):
    e = default_env(tmp_path)
    c, o = e.call("send_email", {"to": "bob@example.com", "subject": "s", "body": "b", "account": "x"})
    assert c == 403 and o["reasons"] == ["unknown_argument:account"]
    # escaped, never a raw control / bidi character in the reason
    c, o = e.call("send_email", {"to": "bob@example.com", "x‮": 1})
    assert c == 403 and "‮" not in json.dumps(o, ensure_ascii=False)


def test_untyped_tool_is_stepped_up(tmp_path):
    pol = copy.deepcopy(load_policy(None))
    pol["tools"]["custom_write"] = {"class": "write", "default": "allow"}
    e = Env(tmp_path, policy=pol)
    c, o = e.call("custom_write", {"path": "a.txt"})
    assert c == 202
    assert "no_arg_schema" in e.store.get_approval(o["approval_id"])["reasons"]


def test_at_most_one_amount_never_summed():
    ctx = dict(CTX, effect_class="pay")
    with pytest.raises(D.CanonicalizationError):
        D.canonicalize("t", {"amount": "10000", "total": "-10000"}, ctx)
    with pytest.raises(Exception):
        load_policy({"tools": {"p": {"class": "pay", "args": {"a": "amount", "b": "amount"}}}})


def test_targets_are_the_union_of_all_addressing_args():
    d = D.canonicalize("t", {"payee": "eve-acct", "account": "bob-acct", "amount": 5}, dict(CTX, effect_class="pay"))
    assert d["targets"] == ["bob-acct", "eve-acct"]
    assert D.recipients(d) == ["bob-acct", "eve-acct"]
    d = D.canonicalize("send_email", {"to": "eve@evil.example", "cc": ["Bob@Example.com"]},
                       dict(CTX, arg_types={"to": "recipient", "cc": "recipient"}, arg_schema_closed=True))
    assert d["targets"] == ["bob@example.com", "eve@evil.example"] and d["schema"] == "declared"


def test_typed_values_are_checked():
    sch = {"n": "int", "f": "flag", "p": {"type": "enum", "values": ["r", "rw"]}, "t": "text"}
    ctx = dict(CTX, arg_types=sch, arg_schema_closed=True)
    D.canonicalize("t", {"n": 3, "f": True, "p": "r", "t": "x"}, ctx)
    for bad in ({"n": True}, {"n": "3"}, {"f": 0}, {"p": "x"}, {"t": 5}):
        with pytest.raises(D.CanonicalizationError):
            D.canonicalize("t", bad, ctx)


# ------------------------------------------------------------- grants (D-005 5)
def _grant(e, tool, args):
    c, o = e.call(tool, args)
    assert c == 202, o
    assert e.fake_approve(o["approval_id"], grant=True)
    assert e.execute(o["approval_id"])[0] == 200
    return e.store.get_approval(o["approval_id"])["grant"]


def test_grant_binds_every_argument_except_bounded_free_ones(tmp_path):
    e = default_env(tmp_path)
    g = _grant(e, "transfer_money", {"payee": "bob-acct", "amount": "10", "currency": "USD", "memo": "a"})
    assert g["v"] == 2 and g["bound_args"] == {"currency": "USD", "payee": "bob-acct"}
    assert g["free_args"] == {"amount": {"type": "amount", "max": "10"}, "memo": {"type": "text", "max_len": 4000}}
    # within the grant: smaller amount, other memo
    c, o = e.call("transfer_money", {"payee": "bob-acct", "amount": "7", "currency": "USD", "memo": "b"})
    assert c == 200 and e.ledger()[-1]["via"] == "grant"
    # outside: other payee, more money, other currency, missing/extra args
    for args in ({"payee": "eve-acct", "amount": "7", "currency": "USD", "memo": "b"},
                 {"payee": "bob-acct", "amount": "11", "currency": "USD", "memo": "b"},
                 {"payee": "bob-acct", "amount": "7", "currency": "EUR", "memo": "b"},
                 {"payee": "bob-acct", "amount": "7", "currency": "USD"}):
        c, o = e.call("transfer_money", args)
        assert c != 200, args


def test_grant_never_frees_recipients(tmp_path):
    e = default_env(tmp_path)
    g = _grant(e, "send_email", {"to": "bob@example.com", "subject": "s", "body": "b"})
    assert g["bound_args"] == {"to": "bob@example.com"}
    assert e.call("send_email", {"to": "bob@example.com", "subject": "x", "body": "new body"})[0] == 200
    assert e.call("send_email", {"to": ["bob@example.com", "eve@evil.example"], "subject": "x", "body": "y"})[0] != 200
    assert e.call("send_email", {"to": "bob@example.com", "cc": "eve@evil.example", "subject": "x",
                                 "body": "y"})[0] != 200


# ------------------------------------------------------ rendering (D-005 6)
def _full(card):
    return (card["effect_class"], tuple(card["risk_lines"]),
            tuple((f.get("label_full", f["label"]), f.get("type"), f.get("full", f["value"])) for f in card["fields"]))


def _rand_value(R, depth=0):
    c = R.random()
    if depth > 2 or c < 0.2:
        return R.choice([None, True, False, 0, 1, -1, 0.5, "0", "1", "true", "null", "", " ", "⠀", "a"])
    if c < 0.5:
        alphabet = ['a', 'b', ' ', '"', '\\', '\n', '\t', '⠀', '‮', '​', 'é', 'é', '[', '×',
                    'u', '{', '}', '0']
        return "".join(R.choice(alphabet) for _ in range(R.randint(0, 24)))
    if c < 0.7:
        return R.randint(-5, 5)
    if c < 0.85:
        return [_rand_value(R, depth + 1) for _ in range(R.randint(0, 3))]
    return {R.choice(["k", "k ", "\\u{202E}", "‮", "a\"b"]): _rand_value(R, depth + 1) for _ in range(2)}


def test_property_distinct_digests_render_distinct_cards():
    """D-005 item 6: the rendering is injective on descriptors (on the full,
    un-truncated values), so distinct effects never look the same."""
    R = random.Random(7)
    seen = {}
    keys = ["a", "b", "arg.a", "Target", "a ", "‮a"]
    for _ in range(4000):
        args = {k: _rand_value(R) for k in R.sample(keys, R.randint(0, 3))}
        try:
            d = D.canonicalize("t", args, dict(CTX, effect_class="write"))
        except D.CanonicalizationError:
            continue
        h = D.digest(d)
        v = _full(D.render_card(d))
        if v in seen:
            assert seen[v] == h, f"two different descriptors render the same card: {seen[v]} vs {h}"
        seen[v] = h
    assert len(set(seen.values())) > 1000


def test_escaping_is_injective_on_tricky_strings():
    pairs = [("‮", "\\u{202E}"), ("a" * 20, "\\[20× \"a\"]"), (" " * 4, "\\[4× space]"),
             ("\\n", "\n"), ('"', '\\"'), ("⠀" * 5, "\\[5× U+2800]")]
    for a, b in pairs:
        assert D._lit(a, set()) != D._lit(b, set()), (a, b)


def test_long_values_are_capped_with_full_value_and_risk_line():
    d = D.canonicalize("t", {"body": "".join(chr(97 + i % 26) for i in range(600)) + "y" * 600},
                       dict(CTX, effect_class="write"))
    card = D.render_card(d)
    row = [f for f in card["fields"] if f["label"] == "arg.body"][0]
    assert row["truncated"] and row["length"] > D.FIELD_MAX and len(row["value"]) < 320
    assert "y" * 600 not in row["full"]  # repeated run collapsed even in the full value
    assert any("shortened" in r or "expand" in r for r in card["risk_lines"])


@pytest.mark.parametrize("argv", [["bash", "-c", "x"], ["sh", "-lc", "x"], ["/usr/bin/python3.11", "-c", "x"],
                                  ["node", "-e", "x"], ["perl", "-e", "x"], ["ruby", "-e", "x"],
                                  ["pwsh", "-Command", "x"], ["env", "FOO=1", "zsh", "-c", "x"],
                                  ["sudo", "-u", "root", "bash", "-c", "x"]])
def test_interpreters_with_inline_code_are_flagged(argv):
    d = D.canonicalize("run_shell", {"command": argv}, dict(CTX, effect_class="exec"))
    assert any("shell/interpreter" in r for r in D.render_card(d)["risk_lines"]), argv


def test_plain_commands_not_flagged():
    d = D.canonicalize("run_shell", {"command": ["ls", "-c"]}, dict(CTX, effect_class="exec"))
    assert not any("shell/interpreter" in r for r in D.render_card(d)["risk_lines"])


def test_argument_names_only_in_arguments_section():
    d = D.canonicalize("t", {"Target": "x", "Tool": "y"}, dict(CTX, effect_class="write"))
    card = D.render_card(d, explanation="trust me")
    trusted = [f["label"] for f in card["fields"] if f["section"] == "effect"]
    args = [f["label"] for f in card["fields"] if f["section"] == "arguments"]
    assert trusted.count("Target") == 1 and trusted.count("Tool") == 1
    assert args == ["arg.Target", "arg.Tool"]
    assert card["agent_explanation_untrusted"]["collapsed"] is True


# ----------------------------------------------------------- crypto findings
def test_lone_surrogate_anywhere_is_a_clean_deny(tmp_path):
    e = default_env(tmp_path)
    for body in ({"tool": "send_email", "args": json.loads('{"\\ud800": 1}')},
                 {"tool": "send\ud800", "args": {}},
                 {"tool": "send_email", "args": {"to": "bob@example.com"}, "explanation": "x\ud800"},
                 {"approval_id": "apr_\ud800"}):
        code, out = e.gw.call(e.session, body)
        assert code in (202, 403, 404), (body, code, out)
    assert e.store.audit.verify()[0]


def test_sqlite_jti_store_survives_restart_and_checks_iss(tmp_path):
    key = T.generate_private_key()
    pub = T.public_key_bytes(key)
    h = "ab" * 32
    tok = T.issue_token(key, h, "asu-resource:send_email", 60)
    db = str(tmp_path / "jti.db")
    assert T.verify_token(tok, pub, h, "asu-resource:send_email", T.SqliteJtiStore(db))
    # "restart" of the resource: a new store on the same file still knows the jti
    assert not T.verify_token(tok, pub, h, "asu-resource:send_email", T.SqliteJtiStore(db))
    tok2 = T.issue_token(key, h, "asu-resource:send_email", 60, iss="other")
    assert not T.verify_token(tok2, pub, h, "asu-resource:send_email", T.SqliteJtiStore(db))
    tok3 = T.issue_token(key, h, "asu-resource:send_email", 60, now=10 ** 10)  # issued in the future
    assert not T.verify_token(tok3, pub, h, "asu-resource:send_email", T.SqliteJtiStore(db), now=10 ** 10 - 3600)


def test_sign_count_compare_and_set(tmp_path):
    from asu.store import Store

    st = Store(str(tmp_path / "a.db"))
    st.create_user("alice", "A")
    st.add_credential("alice", b"c1", b"k", 5, [])
    assert st.update_sign_count(b"c1", 6) is True
    assert st.update_sign_count(b"c1", 6) is False      # replay of the same counter
    assert st.update_sign_count(b"c1", 3) is False      # moving backwards
    st.add_credential("alice", b"c0", b"k", 0, [])
    assert st.update_sign_count(b"c0", 0) is True       # counter-less authenticators


def test_audit_chain_is_keyed(tmp_path):
    from asu.audit import verify_db

    from asu.config import Config
    from asu.gateway import open_store

    cfg = Config(db_path=str(tmp_path / "keyed.db"), workspace_root=str(tmp_path))
    st = open_store(cfg)
    assert oct(os.stat(str(tmp_path / "keyed.db.auditkey")).st_mode & 0o777) == "0o600"
    st.log("x", {"a": 1})
    st.log("y", {"b": 2})
    key = st.audit.key
    assert verify_db(cfg.db_path, key=key)[0]
    # rewrite + rehash without the key: the plain chain still verifies, the keyed one does not
    from asu.audit import entry_hash

    con = sqlite3.connect(cfg.db_path)
    rows = con.execute("SELECT seq, ts, event, data, prev FROM audit ORDER BY seq").fetchall()
    prev = "0" * 64
    for seq, ts, ev, data, _ in rows:
        data = json.loads(data)
        if ev == "x":
            data = {"a": 999}
        h = entry_hash(seq, ts, ev, data, prev)
        con.execute("UPDATE audit SET data=?, prev=?, hash=? WHERE seq=?", (json.dumps(data), prev, h, seq))
        prev = h
    con.commit()
    con.close()
    assert verify_db(cfg.db_path)[0]
    assert not verify_db(cfg.db_path, key=key)[0]


def test_per_user_pending_cap_across_sessions(tmp_path):
    e = default_env(tmp_path, max_pending_per_user=2)
    s2 = e.new_session()[1]
    s3 = e.new_session()[1]
    assert e.call("send_email", {"to": "a@x.com"})[0] == 202
    assert e.call("send_email", {"to": "b@x.com"}, session=s2)[0] == 202
    c, o = e.call("send_email", {"to": "c@x.com"}, session=s3)
    assert c == 429 and o["reason"] == "max_pending_per_user"


def test_per_user_deny_lockout_across_sessions(tmp_path):
    e = default_env(tmp_path, deny_lockout_per_user=2)
    for i in range(2):
        s = e.new_session()[1]
        c, o = e.call("send_email", {"to": f"x{i}@x.com"}, session=s)
        e.store.mark_denied(o["approval_id"])
    c, o = e.call("send_email", {"to": "y@x.com"}, session=e.new_session()[1])
    assert c == 429 and o["reason"] == "deny_lockout_user"


def test_deny_globs_case_insensitive(tmp_path):
    e = default_env(tmp_path)
    c, o = e.call("write_file", {"path": "/home/u/.SSH/authorized_keys", "content": "k"})
    assert c == 403 and o["reasons"][0].startswith("path_denied")


def test_mcp_tools_list_advertises_closed_schema(tmp_path):
    from asu.mcp import input_schema_for

    pol = load_policy(None)
    s = input_schema_for(pol["tools"]["send_email"])
    assert s["additionalProperties"] is False and "to" in s["properties"]


def test_security_headers(tmp_path):
    from fastapi.testclient import TestClient

    from asu.app import create_app

    e = Env(tmp_path)
    c = TestClient(create_app(e.config, e.store))
    r = c.get("/healthz")
    assert r.headers["x-frame-options"] == "DENY" and "frame-ancestors 'none'" in r.headers["content-security-policy"]
