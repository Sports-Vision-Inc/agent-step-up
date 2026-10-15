"""Agno AgentOS measured over a real HTTP server (uvicorn on 127.0.0.1).

This exercises AgentOS's documented remote continue endpoint
``POST /agents/{id}/runs/{run_id}/continue`` and the approvals router
``POST /approvals/{id}/resolve`` the way a networked client does -- every call
goes over a socket to a uvicorn-hosted FastAPI app. It measures:

  * whether the approval decision can be produced out of process (P1 input),
  * the capability ladder for P2/P3 at the documented HTTP layer, and
  * the @approval admin-only-resolve behaviour under user_isolation.

Run with any agno venv python; it prints one line ``AGENTOS_RESULT <json>``.
Version-tolerant so run_all.py can sweep several agno releases.

Terminology: the recorded side effect is a two-field record. ``REC_A`` is the
field set shown to the reviewer; ``REC_B`` is a different field set a later caller
may supply instead. "executed REC_B" means the effect ran with values the
reviewer never saw (a binding gap). Neutral names, no persons.
"""
import json
import os
import socket
import tempfile
import threading
import time
import importlib.metadata as M

VER = M.version("agno")
LEDGER = []
REC_A = {"amount": 10, "to": "acct-a"}
REC_B = {"amount": 9999, "to": "acct-b"}


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _stub_model(tool_name, n_calls=1):
    from agno.models.openai.chat import OpenAIChat

    class Stub(OpenAIChat):
        def __init__(self):
            super().__init__(id="stub", api_key="x")

        def _fill(self, messages, am, mr):
            am.role = "assistant"
            if not any(getattr(m, "role", None) == "tool" for m in messages):
                calls = []
                for i in range(n_calls):
                    args = REC_A if n_calls == 1 else {"amount": 1, "to": f"acct-{i}"}
                    calls.append({"id": f"call{i+1}", "type": "function",
                                  "function": {"name": tool_name,
                                               "arguments": json.dumps(args)}})
                am.tool_calls = calls
                mr.tool_calls = calls
            else:
                am.content = "done"
                mr.content = "done"

        def _process_model_response(self, messages, assistant_message, model_response, *a, **k):
            self._fill(messages, assistant_message, model_response)

        async def _aprocess_model_response(self, messages, assistant_message, model_response, *a, **k):
            self._fill(messages, assistant_message, model_response)

    return Stub()


def _db():
    from agno.db.sqlite import SqliteDb
    d = tempfile.mkdtemp(prefix="agno_os_")
    return SqliteDb(db_file=os.path.join(d, "os.db"))


class Server:
    def __init__(self, app):
        import uvicorn
        self.port = _free_port()
        cfg = uvicorn.Config(app, host="127.0.0.1", port=self.port,
                             log_level="error", lifespan="on")
        self.srv = uvicorn.Server(cfg)
        self.th = threading.Thread(target=self.srv.run, daemon=True)

    def __enter__(self):
        import httpx
        self.th.start()
        for _ in range(200):
            if self.srv.started:
                break
            time.sleep(0.05)
        self.http = httpx.Client(base_url=f"http://127.0.0.1:{self.port}",
                                 trust_env=False, timeout=60)
        return self

    def __exit__(self, *a):
        self.http.close()
        self.srv.should_exit = True
        self.th.join(timeout=10)


def _start(http, sid, headers=None, msg="pay"):
    r = http.post("/agents/payer/runs",
                  data={"message": msg, "stream": "false", "session_id": sid},
                  headers=headers or {})
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, {}


def _cont(http, run_id, sid, tools, headers=None):
    data = {"tools": json.dumps(tools) if tools is not None else "",
            "session_id": sid, "stream": "false"}
    r = http.post(f"/agents/payer/runs/{run_id}/continue", data=data, headers=headers or {})
    return r.status_code, r.text[:200]


def _plain_tool():
    from agno.tools import tool

    @tool(requires_confirmation=True)
    def wire_transfer(amount: int, to: str) -> str:
        """Send a wire transfer."""
        LEDGER.append({"amount": amount, "to": to})
        return "ok"
    return wire_transfer


def _approval_tool():
    from agno.tools import tool
    try:
        from agno.approval import approval
    except Exception as e:
        return None, repr(e)

    @approval
    @tool(requires_confirmation=True)
    def wire_transfer(amount: int, to: str) -> str:
        """Send a wire transfer (approval required)."""
        LEDGER.append({"amount": amount, "to": to})
        return "ok"
    return wire_transfer, None


def _os_app(tool_obj, db, auth=None, user_isolation=False, n_calls=1):
    from agno.agent import Agent
    from agno.os import AgentOS
    tname = getattr(tool_obj, "name", None) or "wire_transfer"
    agent = Agent(id="payer", name="payer", model=_stub_model(tname, n_calls),
                  tools=[tool_obj], db=db, telemetry=False)
    kw = dict(agents=[agent], db=db, telemetry=False)
    if auth is not None:
        kw["authorization"] = auth
        kw["user_isolation"] = user_isolation
    return AgentOS(**kw).get_app()


def _exp_default():
    """No-authorization AgentOS: measure the remote continue capability ladder."""
    out = {}
    db = _db()
    app = _os_app(_plain_tool(), db)
    with Server(app) as s:
        LEDGER.clear()
        code, run = _start(s.http, "s1")
        shown = [t["tool_args"] for t in run.get("tools") or []]
        out["start_status"] = run.get("status")
        out["shown"] = shown
        # L2 (resumer via documented HTTP continue API): supply the returned tools
        # JSON but with the second field set, as a networked client can.
        tools = [dict(t, confirmed=True, tool_args=dict(REC_B)) for t in run["tools"]]
        _cont(s.http, run["run_id"], "s1", tools)
        out["L2_executed_B"] = REC_B in LEDGER
        # same-call replay: identical continue payload posted again
        LEDGER.clear()
        code, run = _start(s.http, "s2")
        tools = [dict(t, confirmed=True) for t in run["tools"]]
        _cont(s.http, run["run_id"], "s2", tools)
        n1 = len(LEDGER)
        _cont(s.http, run["run_id"], "s2", tools)
        out["replay_executions"] = len(LEDGER)
        out["replay_first"] = n1
    # P7 single-run flood: one model turn emits 20 tool calls
    db2 = _db()
    app2 = _os_app(_plain_tool(), db2, n_calls=20)
    with Server(app2) as s:
        LEDGER.clear()
        code, run = _start(s.http, "f1")
        out["flood_pending_single_run"] = len(run.get("tools") or [])
    return out


def _auth(user_isolation):
    import jwt  # noqa: F401 (ensure present)
    from agno.os.authz import Authorization
    secret = "k" * 48
    return Authorization(verification_keys=[secret], algorithm="HS256",
                         verify_audience=False), secret


def _tok(secret, sub, scopes):
    import jwt
    return "Bearer " + jwt.encode(
        {"sub": sub, "scopes": scopes, "exp": int(time.time()) + 3600},
        secret, algorithm="HS256")


def _exp_approval(user_isolation):
    """@approval tool under AgentOS authorization; admin-only resolve is the secure
    (non-default) configuration when user_isolation=True."""
    out = {"user_isolation": user_isolation}
    tool_obj, err = _approval_tool()
    if tool_obj is None:
        out["unsupported"] = err
        return out
    db = _db()
    auth, secret = _auth(user_isolation)
    app = _os_app(tool_obj, db, auth=auth, user_isolation=user_isolation)
    # Requester scopes: run the agent + read its own rows, but NOT approvals:write
    # (approvals:write is the operator/admin authority; granting it to the requester
    # would make the requester an approval-admin and bypass the resolve gate).
    user_scopes = ["agents:*:run", "agents:read", "sessions:read", "approvals:read"]
    U = {"Authorization": _tok(secret, "user-1", user_scopes)}
    # A requester who additionally holds approvals:write (to show that the gate is a
    # scope boundary, not an isolation boundary).
    W = {"Authorization": _tok(secret, "user-1", user_scopes + ["approvals:write"])}
    A = {"Authorization": _tok(secret, "admin-1", ["agent_os:admin"])}
    with Server(app) as s:
        LEDGER.clear()
        code, run = _start(s.http, "s1", headers=U)
        out["start_status"] = run.get("status")
        tools0 = run.get("tools") or []
        aid = tools0[0].get("approval_id") if tools0 else None
        out["approval_id_present"] = bool(aid)
        # requester (non-admin, no approvals:write) resolves its own approval
        r = s.http.post(f"/approvals/{aid}/resolve", json={"status": "approved"}, headers=U)
        out["self_resolve_status"] = r.status_code
        # a requester who holds approvals:write resolves its own approval
        r = s.http.post(f"/approvals/{aid}/resolve", json={"status": "approved"}, headers=W)
        out["self_resolve_with_write_status"] = r.status_code
        # requester continues while still pending (no approvals:write)
        tools = [dict(t, confirmed=True) for t in tools0]
        code, _ = _cont(s.http, run["run_id"], "s1", tools, headers=U)
        out["continue_while_pending_status"] = code
        out["executed_before_admin"] = len(LEDGER)
        # admin approves, then requester continues with the second field set (L2)
        r = s.http.post(f"/approvals/{aid}/resolve", json={"status": "approved"}, headers=A)
        out["admin_resolve_status"] = r.status_code
        tools = [dict(t, confirmed=True, tool_args=dict(REC_B)) for t in tools0]
        _cont(s.http, run["run_id"], "s1", tools, headers=U)
        out["L2_executed_B_after_admin"] = REC_B in LEDGER
    return out


def main():
    result = {"version": VER, "default": _exp_default()}
    try:
        result["approval_isolated"] = _exp_approval(True)
    except Exception as e:
        result["approval_isolated"] = {"error": repr(e)}
    try:
        result["approval_default_isolation"] = _exp_approval(False)
    except Exception as e:
        result["approval_default_isolation"] = {"error": repr(e)}
    print("AGENTOS_RESULT " + json.dumps(result))


if __name__ == "__main__":
    main()
