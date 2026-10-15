"""Red-team harness: a REAL gateway (create_app served by uvicorn on a unique
localhost port, approval_mode=asu, reverify_receipts on, AUTHN mounted) plus
a scripted human who enrolls/logs in/approves with a software passkey, and a
fully compromised agent that only holds its bearer session token.

Used by tests/redteam/test_rt_redteam_*.py. Critics do not fix; tests assert
the SECURE behaviour.
"""
from __future__ import annotations

import copy
import os
import socket
import sys
import threading
import time
from typing import Any, Dict, Optional

import httpx
import uvicorn

HERE = os.path.dirname(os.path.abspath(__file__))
TESTS = os.path.dirname(HERE)
ROOT = os.path.dirname(TESTS)
for p in (TESTS, ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from fakes_authn import SoftAuthenticator  # noqa: E402

from asu.app import create_app  # noqa: E402
from asu.config import Config, load_policy  # noqa: E402


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class LiveGateway:
    """uvicorn-served create_app(config) in asu mode (packaged default policy
    unless overridden)."""

    def __init__(self, tmp_path, policy: Optional[Dict[str, Any]] = None, **cfg: Any):
        self.port = free_port()
        self.origin = f"http://localhost:{self.port}"
        self.ws = os.path.join(str(tmp_path), "ws")
        os.makedirs(self.ws, exist_ok=True)
        kw = dict(
            db_path=os.path.join(str(tmp_path), "asu.db"),
            ledger_path=os.path.join(str(tmp_path), "ledger.jsonl"),
            token_key_path=os.path.join(str(tmp_path), "gw.pem"),
            workspace_root=self.ws,
            approval_mode="asu",
            rp_id="localhost",
            origin=self.origin,
            reverify_receipts=True,
        )
        if policy is not None:
            kw["policy"] = copy.deepcopy(policy)
        kw.update(cfg)
        self.config = Config(**kw)
        self.app = create_app(self.config)
        self.store = self.app.state.store
        self.server = uvicorn.Server(uvicorn.Config(self.app, host="127.0.0.1", port=self.port,
                                                    log_level="warning"))
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def __enter__(self) -> "LiveGateway":
        self.thread.start()
        for _ in range(200):
            if self.server.started:
                return self
            time.sleep(0.025)
        raise RuntimeError("gateway did not start")

    def __exit__(self, *a) -> None:
        self.server.should_exit = True
        self.thread.join(5)

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def ledger(self) -> list:
        import json

        p = self.config.ledger_path
        if not os.path.exists(p):
            return []
        with open(p) as f:
            return [json.loads(line) for line in f if line.strip()]


class Human:
    """The legitimate user on the authenticator page (browser + passkey)."""

    def __init__(self, gw: LiveGateway, user_id: str = "alice"):
        self.gw = gw
        self.user_id = user_id
        self.auth = SoftAuthenticator(origin=gw.origin, rp_id="localhost")
        # Browser: same-origin fetches carry Origin + JSON content type.
        self.http = httpx.Client(base_url=gw.base, headers={"Origin": gw.origin}, timeout=10)

    def post(self, path: str, body: Any = None) -> httpx.Response:
        return self.http.post(path, json=body if body is not None else {})

    def enroll(self) -> None:
        # D-005 item 2: first enrollment needs the one-time token the operator
        # delivers out of band (what `asu enroll-link` prints); the attacker
        # paths in the tests never call enroll() and do not have it.
        token = self.gw.store.create_enrollment_token(self.user_id)
        r = self.post("/v1/authn/register/options", {"user_id": self.user_id, "enrollment_token": token})
        assert r.status_code == 200, r.text
        cred = self.auth.create(r.json())
        r = self.post("/v1/authn/register/verify", {"credential": cred})
        assert r.status_code == 200, r.text

    def login(self) -> None:
        r = self.post("/v1/authn/login/options", {"user_id": self.user_id})
        assert r.status_code == 200, r.text
        r = self.post("/v1/authn/login/verify", {"credential": self.auth.get(r.json())})
        assert r.status_code == 200, r.text

    def agent_session(self, agent_id: str = "agent-1") -> str:
        r = self.post("/v1/sessions", {"agent_id": agent_id})
        assert r.status_code == 200, r.text
        return r.json()["session_token"]

    def pending(self) -> list:
        r = self.http.get("/v1/authn/pending")
        assert r.status_code == 200, r.text
        return r.json()["approvals"]

    def view(self, approval_id: str) -> Dict[str, Any]:
        r = self.http.get(f"/v1/authn/approvals/{approval_id}")
        assert r.status_code == 200, r.text
        return r.json()

    def approve(self, approval_id: str, grant: bool = False) -> Dict[str, Any]:
        r = self.post(f"/v1/authn/approvals/{approval_id}/options", {"grant": grant})
        assert r.status_code == 200, r.text
        cred = self.auth.get(r.json())
        r = self.post(f"/v1/authn/approvals/{approval_id}/verify", {"credential": cred, "grant": grant})
        assert r.status_code == 200, r.text
        return r.json()


class Agent:
    """Fully compromised agent: holds only its bearer token."""

    def __init__(self, gw: LiveGateway, token: str):
        self.gw = gw
        self.http = httpx.Client(base_url=gw.base, headers={"Authorization": f"Bearer {token}"}, timeout=10)

    def call(self, tool: Optional[str] = None, args: Any = None, **body: Any) -> httpx.Response:
        b: Dict[str, Any] = {}
        if tool is not None:
            b["tool"] = tool
        if args is not None:
            b["args"] = args
        b.setdefault("origin", "user_turn")
        b.update(body)
        return self.http.post("/v1/tools/call", json=b)

    def execute(self, approval_id: str, **body: Any) -> httpx.Response:
        return self.http.post("/v1/tools/call", json={"approval_id": approval_id, **body})


def setup(tmp_path, policy: Optional[Dict[str, Any]] = None, **cfg: Any):
    """Start a gateway, enroll + log in the human, mint an agent session.
    Returns (gw, human, agent); caller must close gw (use as context)."""
    gw = LiveGateway(tmp_path, policy=policy, **cfg).__enter__()
    human = Human(gw)
    human.enroll()
    human.login()
    agent = Agent(gw, human.agent_session())
    return gw, human, agent


def default_policy(**over: Any) -> Dict[str, Any]:
    pol = load_policy(None)
    for k, v in over.items():
        pol[k] = v
    return pol


# ---------------------------------------------------------------- fixture
import pytest  # noqa: E402

# Permissive flood settings so the scripted attacks are not throttled; the
# attacks in the redteam lens do not depend on flooding.
RT_FLOOD = {"max_pending_per_session": 5, "max_requests_per_min": 1000, "deny_lockout": 3}


@pytest.fixture
def live(tmp_path):
    gw, human, agent = setup(tmp_path, policy=default_policy(flood=dict(RT_FLOOD)))
    try:
        yield gw, human, agent
    finally:
        gw.__exit__()
