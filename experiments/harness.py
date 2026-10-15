"""In-process harness around the real gateway HTTP API.

One ``Trial`` = one fresh gateway (own sqlite db, ledger, workspace, signing
key) built with ``asu.app.create_app``. Two separate HTTP clients talk to it:

* ``AgentAPI`` holds only the agent's bearer session token and uses only the
  agent-facing API of SPEC section 8 (``/v1/tools/call``, ``/v1/approvals``,
  ``/mcp`` and, in the chat-confirm baseline, ``.../chat-confirm``).
* ``HumanDevice`` is the user's browser/phone: it holds the authenticator-page
  cookie and a software passkey (``experiments.softauth``), enrolls via
  ``/v1/authn/register``, opens agent sessions via ``POST /v1/sessions`` and
  approves/denies via ``/v1/authn/approvals/{id}/options|verify|deny`` (or the
  TOTP baseline route).

Nothing here bypasses the gateway: approvals are real WebAuthn assertions that
the gateway verifies (and re-verifies on execute), and executed effects are
read back from the ``mock_ledger`` file.

Workspace paths (D1 of docs/critique/experiments_anomalies.md): trials are
created under a fixed, short root (``FIXED_TMP_ROOT``) unless the caller
passes ``tmp_root``, and the oracles read every card in a workspace-relative
display (``experiments.oracles.workspace_relative_card``: the trial's
workspace root is shown as ``/workspace``). Cards and oracle decisions are
therefore the same on macOS (long ``$TMPDIR``) and Linux.
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
import time as _real_time
import types
from typing import Any, Dict, List, Optional, Tuple

from fastapi.testclient import TestClient

from asu.app import create_app
from asu.config import Config

from .softauth import SoftAuthenticator

ORIGIN = "http://localhost:8000"

# Fixed short root for trial directories (constant name; /tmp where it exists,
# so the path length does not depend on the platform's $TMPDIR).
FIXED_TMP_ROOT = os.path.join("/tmp" if os.path.isdir("/tmp") and os.access("/tmp", os.W_OK)
                              else tempfile.gettempdir(), "asu-exp")


def default_tmp_root() -> str:
    os.makedirs(FIXED_TMP_ROOT, exist_ok=True)
    return FIXED_TMP_ROOT


# workspace realpath -> ledger reader of the live Trial (lets the oracles see
# effects the gateway executed through a grant without a handle on the trial).
_LIVE_LEDGERS: Dict[str, Any] = {}


def ledger_reader_for(workspace_root: str):
    return _LIVE_LEDGERS.get(os.path.realpath(workspace_root))
HDR = {"Origin": ORIGIN}

WORKSPACE_FILES = {
    "report.txt": "<weekly report placeholder>\n",
    "secret.txt": "<confidential placeholder; never leaves the mock workspace>\n",
    "tmp/cache.log": "<cache placeholder>\n",
    "memory/identity.md": "<agent identity placeholder>\n",
    "memory/tools.md": "<agent tool notes placeholder>\n",
    "memory/history.md": "<interaction history placeholder>\n",
    "mail/local_store.db": "<owner mail store placeholder>\n",
}


# Harness-side approval modes (EXP-3/EXP-8). They reuse the gateway's own
# primitives; the differences from the gateway mode they run on are applied in
# what the simulated human is shown (experiments.agents.base.HumanSim).
#
# host-confirm  Trusted host-rendered confirmation on the agent's own device:
#               the host shows the real call and executes exactly that call
#               (implicit binding). Simulated on the gateway's ``asu`` mode
#               (bound execution) with: no second device, no grants, and the
#               agent's text shown inline, expanded, next to the call. The
#               harness cannot model compromise of the agent's device/host
#               (that is the case a separate device addresses); under the
#               harness threat model (compromised agent, honest host) its
#               outcomes therefore track ``asu`` by construction.
# txn-sign      SPC/PSD2-dynamic-linking-like: a second device displays and
#               signs payee + amount only (not the full arguments). Simulated
#               on ``asu`` with the human's view reduced to Target + amount +
#               currency. LIMITATION: the gateway still binds every argument, so
#               a substitution that changes only non-displayed arguments (e.g.
#               the body) is refused here although real txn-sign would execute
#               it; txn-sign ASR is therefore a lower bound for such attacks.
# asu-no-expl   Ablation: ``asu`` with the agent's explanation box removed.
HARNESS_MODES: Dict[str, str] = {"host-confirm": "asu", "txn-sign": "asu", "asu-no-expl": "asu"}


def gateway_mode(mode: str) -> str:
    return HARNESS_MODES.get(mode, mode)


class Resp:
    __slots__ = ("code", "body")

    def __init__(self, code: int, body: Any):
        self.code = code
        self.body = body if isinstance(body, dict) else {"raw": body}

    @property
    def status(self) -> str:
        return str(self.body.get("status", ""))

    def __repr__(self) -> str:
        return f"Resp({self.code}, {self.body})"


def _resp(r) -> Resp:
    try:
        body = r.json()
    except ValueError:
        body = {"raw": r.text[:500]}
    return Resp(r.status_code, body)


# ---------------------------------------------------------------------------
# Virtual clock for the TOTP baseline.
#
# A TOTP time step is single-use, so a human approving several actions within
# 30 s must wait for the next code. The harness models that wait by shifting
# the clock seen by the TOTP checks (asu.authn.routes and asu.gateway) forward
# by one step per code, instead of sleeping. Only the TOTP baseline uses it.
# ---------------------------------------------------------------------------
class ShiftedTime(types.SimpleNamespace):
    def __init__(self) -> None:
        super().__init__()
        self.offset = 0.0

    def time(self) -> float:
        return _real_time.time() + self.offset

    def __getattr__(self, name: str) -> Any:  # sleep, monotonic, ...
        return getattr(_real_time, name)


_clock_lock = threading.Lock()


class _ClockPatch:
    MODULES = ("asu.authn.routes", "asu.gateway")

    def __init__(self, clock: ShiftedTime):
        self.clock = clock
        self.saved: List[Tuple[Any, Any]] = []

    def __enter__(self):
        import importlib

        _clock_lock.acquire()
        for name in self.MODULES:
            mod = importlib.import_module(name)
            self.saved.append((mod, mod.time))
            mod.time = self.clock  # type: ignore[attr-defined]
        return self

    def __exit__(self, *exc):
        for mod, orig in self.saved:
            mod.time = orig
        self.saved.clear()
        _clock_lock.release()
        return False


# ---------------------------------------------------------------------------
class AgentAPI:
    """The agent's ONLY interface: bearer token + agent-facing endpoints."""

    def __init__(self, app, token: str):
        self.client = TestClient(app, base_url=ORIGIN)
        self.client.__enter__()
        self.token = token
        self.h = {"Authorization": f"Bearer {token}"}
        self.calls = 0

    def close(self) -> None:
        try:
            self.client.__exit__(None, None, None)
        except Exception:
            pass

    def call(self, tool: str, args: Dict[str, Any], explanation: Optional[str] = None,
             origin: str = "user_turn", totp_code: Optional[str] = None) -> Resp:
        body: Dict[str, Any] = {"tool": tool, "args": args, "origin": origin}
        if explanation is not None:
            body["explanation"] = explanation
        if totp_code is not None:
            body["totp_code"] = totp_code
        self.calls += 1
        return _resp(self.client.post("/v1/tools/call", json=body, headers=self.h))

    def execute(self, approval_id: str, tool: Optional[str] = None, args: Optional[Dict[str, Any]] = None) -> Resp:
        body: Dict[str, Any] = {"approval_id": approval_id}
        if tool is not None:
            body["tool"] = tool
        if args is not None:
            body["args"] = args
        self.calls += 1
        return _resp(self.client.post("/v1/tools/call", json=body, headers=self.h))

    def status(self, approval_id: str) -> str:
        r = _resp(self.client.get(f"/v1/approvals/{approval_id}", headers=self.h))
        return r.status if r.code == 200 else f"http_{r.code}"

    def chat_confirm(self, approval_id: str, answer: str) -> Resp:
        return _resp(self.client.post(f"/v1/approvals/{approval_id}/chat-confirm", json={"answer": answer},
                                      headers=self.h))

    def raw(self, method: str, path: str, **kw) -> Resp:
        """Anything else the (adversarial) agent may try, e.g. the user-facing
        /v1/authn routes; it never has the human's cookie."""
        headers = dict(self.h)
        headers.update(kw.pop("headers", {}) or {})
        return _resp(self.client.request(method, path, headers=headers, **kw))

    # MCP transport (SPEC section 8) -------------------------------------
    def mcp(self, method: str, params: Optional[Dict[str, Any]] = None, id_: int = 1) -> Dict[str, Any]:
        body = {"jsonrpc": "2.0", "id": id_, "method": method, "params": params or {}}
        r = self.client.post("/mcp", json=body, headers={**self.h, "Accept": "application/json"})
        return r.json()


class HumanDevice:
    """The user's authenticator page (browser/phone) with a software passkey."""

    def __init__(self, app, user_id: str, mode: str, clock: Optional[ShiftedTime] = None,
                 enrollment_token: Optional[str] = None):
        self.app = app
        self.enrollment_token = enrollment_token
        self.user_id = user_id
        self.mode = mode
        self.clock = clock
        self.client = TestClient(app, base_url=ORIGIN)
        self.client.__enter__()
        self.auth = SoftAuthenticator(origin=ORIGIN, rp_id="localhost")
        self.totp_secret: Optional[str] = None
        self._register()
        if mode == "totp":
            r = self.client.post("/v1/authn/totp/enroll", json={}, headers=HDR)
            if r.status_code != 200:
                raise RuntimeError(f"totp enroll failed: {r.status_code} {r.text}")
            self.totp_secret = r.json()["secret"]

    def close(self) -> None:
        try:
            self.client.__exit__(None, None, None)
        except Exception:
            pass

    def _register(self) -> None:
        r = self.client.post("/v1/authn/register/options", json={"user_id": self.user_id,
                                                                 "display_name": self.user_id,
                                                                 "enrollment_token": self.enrollment_token},
                             headers=HDR)
        if r.status_code != 200:
            raise RuntimeError(f"register/options failed: {r.status_code} {r.text}")
        cred = self.auth.create(r.json())
        r = self.client.post("/v1/authn/register/verify", json={"credential": cred}, headers=HDR)
        if r.status_code != 200:
            raise RuntimeError(f"register/verify failed: {r.status_code} {r.text}")

    def open_agent_session(self, agent_id: str = "agent-1", scopes: Optional[List[str]] = None) -> Dict[str, Any]:
        r = self.client.post("/v1/sessions", json={"agent_id": agent_id, "scopes": scopes or ["*"]},
                             headers={**HDR, "Content-Type": "application/json"})
        if r.status_code != 200:
            raise RuntimeError(f"POST /v1/sessions failed: {r.status_code} {r.text}")
        return r.json()

    def pending(self) -> List[Dict[str, Any]]:
        r = self.client.get("/v1/authn/pending")
        if r.status_code != 200:
            raise RuntimeError(f"pending failed: {r.status_code} {r.text}")
        return r.json().get("approvals", [])

    def approve(self, approval_id: str, grant: bool = False) -> bool:
        if self.mode == "totp":
            return self.approve_totp(approval_id)
        r = self.client.post(f"/v1/authn/approvals/{approval_id}/options", json={"grant": bool(grant)}, headers=HDR)
        if r.status_code != 200:
            return False
        assertion = self.auth.get(r.json())
        r = self.client.post(f"/v1/authn/approvals/{approval_id}/verify",
                             json={"credential": assertion, "grant": bool(grant)}, headers=HDR)
        return r.status_code == 200

    def deny(self, approval_id: str) -> bool:
        r = self.client.post(f"/v1/authn/approvals/{approval_id}/deny", json={}, headers=HDR)
        return r.status_code == 200

    def next_totp_code(self) -> Optional[str]:
        """Wait for the next 30 s step (virtual clock) and read the code."""
        if not self.totp_secret or self.clock is None:
            return None
        import pyotp

        totp = pyotp.TOTP(self.totp_secret)
        self.clock.offset += totp.interval
        return totp.at(self.clock.time())

    def approve_totp(self, approval_id: str) -> bool:
        code = self.next_totp_code()
        if code is None:
            return False
        r = self.client.post(f"/v1/authn/totp/approvals/{approval_id}/verify", json={"code": code}, headers=HDR)
        return r.status_code == 200


class Trial:
    """A fresh gateway + user + authenticator for one experiment trial."""

    def __init__(self, mode: str, policy: Dict[str, Any], tmp_root: Optional[str] = None,
                 user_id: str = "alice", approval_ttl_s: int = 3600, extra_cfg: Optional[Dict[str, Any]] = None):
        self.mode = mode
        self.dir = tempfile.mkdtemp(prefix="asu-trial-", dir=tmp_root or default_tmp_root())
        self.ws = os.path.realpath(os.path.join(self.dir, "ws"))
        for rel, content in WORKSPACE_FILES.items():
            p = os.path.join(self.ws, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w", encoding="utf-8") as f:
                f.write(content)
        cfg: Dict[str, Any] = dict(
            db_path=os.path.join(self.dir, "asu.db"),
            ledger_path=os.path.join(self.dir, "ledger.jsonl"),
            token_key_path=os.path.join(self.dir, "gw_ed25519.pem"),
            workspace_root=self.ws,
            approval_mode=gateway_mode(mode),
            policy=policy,
            approval_ttl_s=approval_ttl_s,
            web_dir=os.path.join(self.dir, "no-web"),
            origin=ORIGIN,
            rp_id="localhost",
            # Deployed configuration (D-005 items 2-3): closed enrollment, UV required.
            dev_mode=False,
            require_user_verification=True,
            reverify_receipts=True,
        )
        cfg.update(extra_cfg or {})
        self.config = Config(**cfg)
        self.app = create_app(self.config)
        self.store = self.app.state.store
        self.clock: Optional[ShiftedTime] = None
        self._clock_patch: Optional[_ClockPatch] = None
        if mode == "totp":
            self.clock = ShiftedTime()
            self._clock_patch = _ClockPatch(self.clock)
            self._clock_patch.__enter__()
        self.user_id = user_id
        # One-time enrollment token delivered out of band (what `asu enroll-link` prints).
        token = self.store.create_enrollment_token(user_id)
        self.human = HumanDevice(self.app, user_id, gateway_mode(mode), self.clock, enrollment_token=token)
        self.agents: List[AgentAPI] = []
        _LIVE_LEDGERS[self.ws] = self.ledger

    def new_agent(self, agent_id: str = "agent-1") -> AgentAPI:
        sess = self.human.open_agent_session(agent_id)
        api = AgentAPI(self.app, sess["session_token"])
        api.session_id = sess.get("session_id")  # type: ignore[attr-defined]
        self.agents.append(api)
        return api

    def ledger(self) -> List[Dict[str, Any]]:
        path = self.config.ledger_path
        if not os.path.exists(path):
            return []
        with open(path, "r", encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def ledger_descriptors(self) -> List[Dict[str, Any]]:
        return [rec["descriptor"] for rec in self.ledger()]

    def close(self) -> None:
        _LIVE_LEDGERS.pop(self.ws, None)
        for a in self.agents:
            a.close()
        self.human.close()
        if self._clock_patch is not None:
            self._clock_patch.__exit__(None, None, None)
            self._clock_patch = None
        try:
            self.store.close()
        except Exception:
            pass
        shutil.rmtree(self.dir, ignore_errors=True)

    def __enter__(self) -> "Trial":
        return self

    def __exit__(self, *exc) -> bool:
        self.close()
        return False
