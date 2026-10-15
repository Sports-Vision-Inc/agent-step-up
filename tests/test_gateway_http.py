"""HTTP API (SPEC section 8) and MCP JSON-RPC front-end."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from asu.app import create_app
from test_gateway_fixtures import Env

EMAIL = {"to": "bob@example.com", "subject": "hi", "body": "hello"}


@pytest.fixture
def h(tmp_path):
    e = Env(tmp_path)
    app = create_app(e.config, e.store)
    e.gw = app.state.gateway
    e.client = TestClient(app)
    e.auth = {"Authorization": f"Bearer {e.token}"}
    return e


def call(h, body, headers=None):
    return h.client.post("/v1/tools/call", json=body, headers=h.auth if headers is None else headers)


def test_app_state_and_mounts(h):
    app = h.client.app
    assert app.state.store is h.store and app.state.config is h.config
    paths = {getattr(r, "path", "") for r in app.routes}
    assert "/v1/tools/call" in paths and "/mcp" in paths
    # AUTHN router mounted lazily: its routes answer (401 = not signed in), unknown paths 404
    assert h.client.get("/v1/authn/pending").status_code == 401
    assert h.client.get("/v1/nothing").status_code == 404


def test_create_app_without_authn(tmp_path):
    e = Env(tmp_path, mount_authn=False)
    c = TestClient(create_app(e.config, e.store))
    assert c.get("/v1/authn/pending").status_code == 404


def test_web_served_at_app(tmp_path):
    web = tmp_path / "web"
    web.mkdir()
    (web / "index.html").write_text("<html>ok</html>")
    e = Env(tmp_path, web_dir=str(web))
    c = TestClient(create_app(e.config, e.store))
    assert c.get("/app/").text == "<html>ok</html>"


def test_unauthenticated(h):
    assert call(h, {"tool": "read_file", "args": {}}, headers={}).status_code == 401
    assert call(h, {"tool": "read_file", "args": {}}, headers={"Authorization": "Bearer nope"}).status_code == 401
    assert h.client.get("/v1/approvals/x").status_code == 401


def test_rest_status_codes(h):
    r = call(h, {"tool": "read_file", "args": {"path": "a"}, "origin": "user_turn"})
    assert r.status_code == 200 and r.json()["status"] == "executed" and r.json()["receipt_id"]
    r = call(h, {"tool": "read_file", "args": {"path": "/etc/passwd"}, "origin": "user_turn"})
    assert r.status_code == 403 and r.json()["status"] == "denied"
    r = call(h, {"tool": "send_email", "args": EMAIL, "origin": "user_turn"})
    assert r.status_code == 202 and set(r.json()) == {"status", "approval_id"}
    aid = r.json()["approval_id"]
    g = h.client.get(f"/v1/approvals/{aid}", headers=h.auth)
    assert g.status_code == 200 and g.json() == {"status": "pending"}  # status only
    h.fake_approve(aid)
    r = call(h, {"approval_id": aid, "args": {**EMAIL, "to": "m@evil.example"}})
    assert r.status_code == 409 and r.json() == {"status": "effect_mismatch"}
    r = call(h, {"approval_id": aid})
    assert r.status_code == 200
    assert h.client.get(f"/v1/approvals/{aid}", headers=h.auth).json() == {"status": "consumed"}
    assert call(h, {"approval_id": aid}).status_code == 403
    r = h.client.post("/v1/tools/call", content=b"not json", headers=h.auth)
    assert r.status_code == 400


def test_rest_rate_limited(tmp_path):
    import copy

    from test_gateway_fixtures import TEST_POLICY

    p = copy.deepcopy(TEST_POLICY)
    p["flood"]["max_requests_per_min"] = 2
    e = Env(tmp_path, policy=p)
    c = TestClient(create_app(e.config, e.store))
    hd = {"Authorization": f"Bearer {e.token}"}
    codes = [c.post("/v1/tools/call", json={"tool": "read_file", "args": {"path": "a"}, "origin": "user_turn"},
                    headers=hd).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


def test_sessions_endpoint_requires_user_login(h):
    from asu.authn import SESSION_COOKIE

    assert h.client.post("/v1/sessions", json={}).status_code == 401
    cookie = "wl." + h.store.create_web_login("alice", 600)
    h.client.cookies.set(SESSION_COOKIE, cookie)
    r = h.client.post("/v1/sessions", json={"agent_id": "agent-9", "scopes": ["read_file"], "ttl_s": 10 ** 9})
    assert r.status_code == 200, r.text
    tok = r.json()["session_token"]
    s = h.store.get_session_by_token(tok)
    assert s["agent_id"] == "agent-9" and s["scopes"] == ["read_file"]
    assert s["expires_at"] - s["created_at"] <= h.config.session_ttl_s  # ttl capped
    r = h.client.post("/v1/sessions", json={}, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
    r = h.client.post("/v1/sessions", content=b"agent_id=x",
                      headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert r.status_code == 415
    # an agent session token is not a user login
    h.client.cookies.clear()
    assert h.client.post("/v1/sessions", json={}, headers=h.auth).status_code == 401


def test_token_key_endpoint(h):
    r = h.client.get("/v1/gateway/token-key").json()
    assert r["alg"] == "Ed25519" and r["public_key_b64"]


# ---------------------------------------------------------------------- MCP
def rpc(h, method, params=None, id_=1, accept="application/json, text/event-stream", headers=None):
    msg = {"jsonrpc": "2.0", "method": method}
    if id_ is not None:
        msg["id"] = id_
    if params is not None:
        msg["params"] = params
    hd = dict(headers if headers is not None else h.auth)
    hd["Accept"] = accept
    return h.client.post("/mcp", json=msg, headers=hd)


def sse_messages(text):
    out = []
    for block in text.strip().split("\n\n"):
        for line in block.splitlines():
            if line.startswith("data: "):
                out.append(json.loads(line[6:]))
    return out


def test_mcp_initialize_and_list(h):
    r = rpc(h, "initialize", {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "t"}})
    res = r.json()["result"]
    assert res["protocolVersion"] == "2025-03-26" and "tools" in res["capabilities"]
    tools = rpc(h, "tools/list", {}).json()["result"]["tools"]
    names = {t["name"] for t in tools}
    assert {"send_email", "read_file"} <= names
    assert all("inputSchema" in t for t in tools)
    assert rpc(h, "notifications/initialized", id_=None).status_code == 202
    assert rpc(h, "nope").json()["error"]["code"] == -32601
    assert rpc(h, "ping").json()["result"] == {}


def test_mcp_call_allow_and_approval_required(h):
    r = rpc(h, "tools/call", {"name": "read_file", "arguments": {"path": "a"}, "origin": "user_turn"})
    res = r.json()["result"]
    assert res["isError"] is False and res["structuredContent"]["status"] == "executed"
    r = rpc(h, "tools/call", {"name": "send_email", "arguments": EMAIL, "_meta": {"origin": "user_turn"}}, id_=7)
    body = r.json()
    assert body["id"] == 7
    err = body["error"]
    assert err["code"] == -32010 and err["message"] == "approval_required"
    assert set(err["data"]) == {"approval_id"}
    aid = err["data"]["approval_id"]
    h.fake_approve(aid)
    r = rpc(h, "tools/call", {"name": "send_email", "arguments": {**EMAIL, "to": "m@evil.example"},
                              "approval_id": aid})
    assert r.json()["error"]["code"] == -32012
    r = rpc(h, "tools/call", {"name": "send_email", "arguments": EMAIL, "approval_id": aid})
    assert r.json()["result"]["structuredContent"]["status"] == "executed"
    r = rpc(h, "tools/call", {"name": "send_email", "approval_id": aid})
    assert r.json()["error"]["code"] == -32011  # replay -> denied


def test_mcp_sse(h):
    r = rpc(h, "tools/call", {"name": "send_email", "arguments": EMAIL}, accept="text/event-stream")
    assert r.headers["content-type"].startswith("text/event-stream")
    msgs = sse_messages(r.text)
    assert len(msgs) == 1 and msgs[0]["error"]["code"] == -32010
    assert msgs[0]["error"]["data"]["approval_id"]
    r = rpc(h, "tools/list", {}, accept="text/event-stream, application/json")
    assert sse_messages(r.text)[0]["result"]["tools"]
    r = rpc(h, "tools/list", {}, accept="application/json")
    assert r.headers["content-type"].startswith("application/json")


def test_mcp_errors(h):
    assert rpc(h, "tools/list", headers={}).status_code == 401
    assert rpc(h, "tools/list", headers={}).json()["error"]["code"] == -32001
    r = h.client.post("/mcp", content=b"{bad", headers={**h.auth, "Accept": "application/json"})
    assert r.json()["error"]["code"] == -32700
    r = h.client.post("/mcp", json={"id": 1, "method": "x"}, headers=h.auth)
    assert r.json()["error"]["code"] == -32600
    r = rpc(h, "tools/call", {"name": "read_file", "arguments": {"path": "/etc/shadow"}, "origin": "user_turn"})
    assert r.json()["error"]["code"] == -32011 and r.json()["error"]["data"]["reasons"]
    r = rpc(h, "tools/call", {"name": "read_file", "arguments": 5})
    assert r.json()["error"]["code"] == -32602
    assert h.client.get("/mcp").status_code == 405


def test_mcp_batch(h):
    msgs = [{"jsonrpc": "2.0", "id": 1, "method": "ping"},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]
    r = h.client.post("/mcp", json=msgs, headers={**h.auth, "Accept": "application/json"})
    assert [m["id"] for m in r.json()] == [1, 2]
