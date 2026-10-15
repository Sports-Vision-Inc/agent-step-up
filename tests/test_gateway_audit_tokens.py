"""Audit hash chain, Ed25519 authz tokens, executors and the ``asu`` CLI."""
from __future__ import annotations

import base64
import io
import json
import os
from contextlib import redirect_stdout

import pytest

from asu import audit as A
from asu import tokens as T
from asu.cli import main
from test_gateway_fixtures import Env, b64u, env, register_soft_authenticator  # noqa: F401

EMAIL = {"to": "bob@example.com", "subject": "hi", "body": "hello"}


def run_cli(*argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(list(argv))
    return rc, buf.getvalue()


def busy(env):
    env.call("read_file", {"path": "a"})
    c, o = env.call("send_email", EMAIL)
    env.fake_approve(o["approval_id"])
    env.execute(o["approval_id"])
    env.execute(o["approval_id"])  # replay attempt -> audited
    return o["approval_id"]


# -------------------------------------------------------------------- audit
def test_chain_records_and_verifies(env):
    busy(env)
    events = [e["event"] for e in env.store.audit.entries()]
    for ev in ("session_created", "decision", "approval_created", "approval_approved", "approval_consumed",
               "effect_executed", "replay_rejected"):
        assert ev in events
    assert env.store.audit.verify()[0]
    es = env.store.audit.entries()
    assert es[0]["prev"] == A.GENESIS
    assert all(es[i]["prev"] == es[i - 1]["hash"] for i in range(1, len(es)))


@pytest.mark.parametrize("tamper", [
    "UPDATE audit SET data='{\"x\":1}' WHERE seq=3",
    "UPDATE audit SET event='nothing' WHERE seq=4",
    "UPDATE audit SET ts=ts+1 WHERE seq=2",
    "DELETE FROM audit WHERE seq=3",
])
def test_tamper_detected(env, tamper):
    busy(env)
    with env.store.tx() as c:
        c.execute(tamper)
    ok, seq, msg = env.store.audit.verify()
    assert not ok and seq is not None
    ok2, _, _ = A.verify_db(env.config.db_path)
    assert not ok2


def test_rewritten_suffix_detected_only_with_anchor(env):
    busy(env)
    n, head = env.store.audit.head()
    with env.store.tx() as c:
        c.execute("DELETE FROM audit WHERE seq>?", (n - 2,))
    assert env.store.audit.verify()[0]  # truncation alone is self-consistent...
    assert not env.store.audit.verify(expected_head=head)[0]  # ...but not with an anchored head


def test_recomputed_hashes_after_edit_detected_by_anchor(env):
    busy(env)
    _, head = env.store.audit.head()
    es = env.store.audit.entries()
    es[2]["data"] = {"forged": True}
    prev = es[1]["hash"]
    for e in es[2:]:  # attacker recomputes the whole suffix
        e["prev"] = prev
        e["hash"] = A.entry_hash(e["seq"], e["ts"], e["event"], e["data"], e["prev"])
        prev = e["hash"]
    assert A.verify_entries(es)[0]
    assert not A.verify_entries(es, expected_head=head)[0]


def test_export_jsonl_and_cli_verify_chain(env, tmp_path):
    busy(env)
    p = str(tmp_path / "audit.jsonl")
    n = env.store.audit.export_jsonl(p)
    assert n > 5 and A.verify_jsonl(p)[0]
    rc, out = run_cli("verify-chain", "--db", env.config.db_path)
    assert rc == 0 and json.loads(out)["ok"]
    rc, out = run_cli("verify-chain", "--jsonl", p, "--head", env.store.audit.head()[1])
    assert rc == 0
    lines = open(p).read().splitlines()
    rec = json.loads(lines[1])
    rec["data"] = {"tampered": 1}
    lines[1] = json.dumps(rec)
    open(p, "w").write("\n".join(lines) + "\n")
    rc, out = run_cli("verify-chain", "--jsonl", p)
    assert rc == 1 and json.loads(out)["first_bad_seq"] == 2


def test_audit_never_contains_session_tokens(env):
    busy(env)
    dump = json.dumps(env.store.audit.entries())
    assert env.token not in dump


# ------------------------------------------------------------------- tokens
def test_token_roundtrip_and_single_use():
    k = T.generate_private_key()
    pub = T.public_key_bytes(k)
    h = "ab" * 32
    tok = T.issue_token(k, h, "bank", 60)
    cache = T.JtiCache()
    assert T.verify_token(tok, pub, h, "bank", cache)
    assert not T.verify_token(tok, pub, h, "bank", cache)  # jti replay


def test_token_rejections():
    k = T.generate_private_key()
    pub = T.public_key_bytes(k)
    h = "ab" * 32
    tok = T.issue_token(k, h, "bank", 60)
    assert not T.verify_token(tok, pub, "cd" * 32, "bank", T.JtiCache())
    assert not T.verify_token(tok, pub, h, "other-aud", T.JtiCache())
    assert not T.verify_token(tok, T.public_key_bytes(T.generate_private_key()), h, "bank", T.JtiCache())
    assert not T.verify_token(tok, pub, h, "bank", T.JtiCache(), now=int(__import__("time").time()) + 61)
    p, payload, sig = tok.split(".")
    forged = json.loads(base64.urlsafe_b64decode(payload + "=="))
    forged["h"] = "cd" * 32
    fp = base64.urlsafe_b64encode(json.dumps(forged).encode()).rstrip(b"=").decode()
    assert not T.verify_token(f"{p}.{fp}.{sig}", pub, "cd" * 32, "bank", T.JtiCache())
    assert not T.verify_token("garbage", pub, h, "bank", T.JtiCache())
    assert not T.verify_token(tok + "x", pub, h, "bank", T.JtiCache())
    assert not T.verify_token(None, pub, h, "bank", T.JtiCache())  # type: ignore[arg-type]


def test_key_persistence(tmp_path):
    p = str(tmp_path / "k.pem")
    k1 = T.load_or_create_key(p)
    assert oct(os.stat(p).st_mode & 0o777) == "0o600"
    assert T.public_key_bytes(T.load_or_create_key(p)) == T.public_key_bytes(k1)


def test_token_executor_end_to_end(tmp_path):
    e = Env(tmp_path, executor="token")
    c, o = e.call("send_email", EMAIL)
    ap = e.store.get_approval(o["approval_id"])
    e.fake_approve(ap["id"])
    c, out = e.execute(ap["id"])
    assert c == 200
    tok = out["result"]["token"]
    assert T.decode_token(tok)["h"] == ap["digest"]
    cache = T.JtiCache()
    pub = e.gw.token_public_key()
    # CR-8: one audience per resource (<token_audience>:<tool> by default);
    # the shared audience of v1 tokens is no longer accepted.
    from asu.executors import token_audience_for

    aud = token_audience_for(e.config, "send_email")
    assert aud == e.config.token_audience + ":send_email"
    assert not T.verify_token(tok, pub, ap["digest"], e.config.token_audience, T.JtiCache())
    assert not T.verify_token(tok, pub, ap["digest"], aud, T.JtiCache(), expected_iss="someone-else")
    assert T.verify_token(tok, pub, ap["digest"], aud, cache)
    assert not T.verify_token(tok, pub, ap["digest"], aud, cache)


# ---------------------------------------------------------------- executors
def test_python_executor(tmp_path):
    e = Env(tmp_path, executor="python:test_gateway_fixtures:py_exec")
    c, out = e.call("read_file", {"path": "a"})
    assert c == 200 and out["result"]["seen_tool"] == "read_file" and len(out["result"]["seen_digest"]) == 64


def test_python_executor_keyword_only_signature(tmp_path):
    e = Env(tmp_path, executor="python:json:dumps")
    c, out = e.call("read_file", {"path": "a"})
    assert c == 200 and json.loads(out["result"])["tool"] == "read_file"


def test_per_tool_executor_override(tmp_path):
    from test_gateway_fixtures import TEST_POLICY
    import copy

    p = copy.deepcopy(TEST_POLICY)
    p["tools"]["read_file"]["executor"] = "python:test_gateway_fixtures:py_exec"
    e = Env(tmp_path, policy=p)
    assert "seen_tool" in e.call("read_file", {"path": "a"})[1]["result"]
    assert e.call("write_file", {"path": "a", "content": "x"})[1]["result"]["ledger"] == "appended"


def test_http_forward_resolves_credentials_on_gateway(tmp_path, monkeypatch):
    import httpx

    seen = {}

    class R:
        status_code = 201

        def json(self):
            return {"ok": True}

    def fake_post(url, json=None, headers=None, timeout=None):
        seen.update(url=url, body=json, headers=headers)
        return R()

    monkeypatch.setattr(httpx, "post", fake_post)
    monkeypatch.setenv("ASU_TEST_SECRET", "s3cret")
    e = Env(tmp_path, executor="http_forward", http_forward_url="http://resource.local/do",
            http_forward_headers_env={"Authorization": "ASU_TEST_SECRET"})
    c, out = e.call("read_file", {"path": "a"})
    assert c == 200 and out["result"] == {"http_status": 201, "body": {"ok": True}}
    assert seen["headers"]["Authorization"] == "s3cret"
    assert seen["body"]["descriptor"]["tool"] == "read_file"
    assert "s3cret" not in json.dumps(out)


def test_executor_failure_records_no_effect(tmp_path, monkeypatch):
    monkeypatch.delenv("ASU_MISSING", raising=False)
    e = Env(tmp_path, executor="http_forward", http_forward_url="http://x/",
            http_forward_headers_env={"Authorization": "ASU_MISSING"})
    c, out = e.call("read_file", {"path": "a"})
    assert c == 500 and out == {"status": "error", "error": "execution_failed"}
    with e.store.tx() as cx:
        assert cx.execute("SELECT COUNT(*) FROM effects").fetchone()[0] == 0


def test_ledger_line_per_effect(env):
    for i in range(3):
        env.call("write_file", {"path": f"f{i}", "content": "x"})
    led = env.ledger()
    assert len(led) == 3 and all(len(r["digest"]) == 64 for r in led)


# ---------------------------------------------------------------------- CLI
def test_cli_dev_session(tmp_path):
    db = str(tmp_path / "x.db")
    # D-005 item 2: refused for a principal without a passkey; prints a
    # one-time enrollment link instead of a token.
    rc, out = run_cli("dev-session", "--db", db, "--user", "bob", "--agent", "a7")
    assert rc == 2
    refused = json.loads(out)
    assert "session_token" not in refused and "#enroll=" in refused["enroll_first"]
    rc, out = run_cli("dev-session", "--db", db, "--user", "bob", "--agent", "a7", "--scopes", "read_file",
                      "--login-cookie", "--force-insecure")
    assert rc == 0
    d = json.loads(out)
    from asu.store import Store

    st = Store(db)
    s = st.get_session_by_token(d["session_token"])
    assert s["user_id"] == "bob" and s["agent_id"] == "a7" and s["scopes"] == ["read_file"]
    from asu.authn import SESSION_COOKIE

    assert d["login_cookie"]["name"] == SESSION_COOKIE
    assert st.get_web_login(d["login_cookie"]["value"].split(".", 1)[1]) == "bob"


def test_cli_export_and_verify_receipt(tmp_path):
    e = Env(tmp_path, reverify_receipts=True)
    auth = register_soft_authenticator(e)
    c, o = e.call("send_email", EMAIL)
    ap = e.store.get_approval(o["approval_id"])
    assert e.store.mark_approved(ap["id"], auth.receipt_for(ap))
    assert e.execute(ap["id"])[0] == 200
    bundle = str(tmp_path / "r.json")
    rc, _ = run_cli("export-receipt", "--db", e.config.db_path, ap["id"], "--out", bundle)
    assert rc == 0
    keyf = str(tmp_path / "pk.txt")
    open(keyf, "w").write(b64u(auth.cose_public_key()))
    # CR-7: --public-key and --rp-id are mandatory; flags and grant are reported
    rc, out = run_cli("verify-receipt", bundle, "--public-key", keyf, "--rp-id", "localhost")
    res = json.loads(out)
    assert rc == 0 and res["ok"] and res["digest"] == ap["digest"]
    assert res["flags"]["up"] and res["flags"]["uv"] and res["grant_digest"] is None
    rc, out = run_cli("verify-receipt", bundle, "--public-key", keyf, "--rp-id", "evil.example")
    assert rc == 1
    # a descriptor edited after the fact no longer matches what was signed
    b = json.load(open(bundle))
    b["descriptor"]["args"]["to"] = "mallory@evil.example"
    json.dump(b, open(bundle, "w"))
    rc, out = run_cli("verify-receipt", bundle, "--public-key", keyf, "--rp-id", "localhost")
    assert rc == 1
    # both digest and descriptor swapped: signature no longer verifies
    from asu.descriptor import digest

    b["digest"] = digest(b["descriptor"])
    json.dump(b, open(bundle, "w"))
    rc, out = run_cli("verify-receipt", bundle, "--public-key", keyf, "--rp-id", "localhost")
    assert rc == 1
    # wrong key
    from test_gateway_fixtures import SoftAuthenticator

    open(keyf, "w").write(b64u(SoftAuthenticator().cose_public_key()))
    run_cli("export-receipt", "--db", e.config.db_path, ap["id"], "--out", bundle)
    rc, _ = run_cli("verify-receipt", bundle, "--public-key", keyf, "--rp-id", "localhost")
    assert rc == 1


def test_cli_parser_has_commands():
    from asu.cli import build_parser

    p = build_parser()
    extra = {"verify-receipt": ["x", "--public-key", "k", "--rp-id", "localhost"], "export-receipt": ["x"],
             "enroll-link": ["--user", "alice"]}
    for cmd in ("serve", "dev-session", "verify-chain", "verify-receipt", "export-receipt", "enroll-link"):
        assert p.parse_known_args([cmd] + extra.get(cmd, []))
