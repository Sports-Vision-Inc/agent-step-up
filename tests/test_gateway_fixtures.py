"""Shared helpers for gateway tests (imported by the other test_gateway_* files)."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
from typing import Any, Dict, Optional

import pytest

from asu.config import Config
from asu.gateway import Gateway
from asu.store import Store

TEST_POLICY: Dict[str, Any] = {
    "tools": {
        "read_file": {"class": "read", "default": "allow"},
        "write_file": {"class": "write", "default": "allow"},
        "delete_file": {"class": "delete", "default": "challenge"},
        "send_email": {"class": "send", "default": "challenge"},
        "send_message": {"class": "send", "default": "allow"},
        "transfer_money": {"class": "pay", "default": "allow"},
        "http_request": {"class": "net", "default": "allow"},
        "run_shell": {"class": "exec", "default": "challenge"},
        "forbidden_tool": {"class": "admin", "default": "deny"},
    },
    "unknown_tool": "deny",
    "step_up": {
        "first_time_recipient": True,
        "amount_over": 100,
        "autonomous_origin": True,
        "destructive_classes": ["delete", "pay", "admin", "exec"],
        "outside_workspace": True,
        "aggregate": {"window_s": 600, "max_effects": 50, "max_amount": 200},
    },
    "deny": {"path_globs": ["/etc/**", "**/.ssh/**"], "hosts": ["evil.example"]},
    "grants": {"max_ttl_s": 3600, "max_uses": 3},
    "flood": {"max_pending_per_session": 5, "max_requests_per_min": 1000, "deny_lockout": 100},
}


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class Env:
    def __init__(self, tmp_path, mode: str = "asu", policy: Optional[Dict[str, Any]] = None, **cfg: Any):
        self.tmp = tmp_path
        self.ws = os.path.join(str(tmp_path), "ws")
        os.makedirs(self.ws, exist_ok=True)
        kw = dict(
            db_path=os.path.join(str(tmp_path), "asu.db"),
            ledger_path=os.path.join(str(tmp_path), "ledger.jsonl"),
            token_key_path=os.path.join(str(tmp_path), "gw.pem"),
            workspace_root=self.ws,
            approval_mode=mode,
            policy=copy.deepcopy(policy if policy is not None else TEST_POLICY),
            reverify_receipts=False,
            web_dir=os.path.join(str(tmp_path), "noweb"),
        )
        kw.update(cfg)
        self.config = Config(**kw)
        self.store = Store(self.config.db_path)
        self.gw = Gateway(self.config, self.store)
        if self.store.get_user("alice") is None:
            self.store.create_user("alice", "Alice")
        self.token, self.session = self.store.create_session("alice", "agent-1", ["*"], 3600)

    def new_session(self, user: str = "alice", agent: str = "agent-1"):
        if self.store.get_user(user) is None:
            self.store.create_user(user, user)
        return self.store.create_session(user, agent, ["*"], 3600)

    def call(self, tool: str, args: Optional[dict] = None, session: Optional[dict] = None, **body: Any):
        b = {"tool": tool, "args": args or {}, "origin": body.pop("origin", "user_turn")}
        b.update(body)
        return self.gw.call(session or self.session, b)

    def execute(self, approval_id: str, session: Optional[dict] = None, **body: Any):
        b = {"approval_id": approval_id}
        b.update(body)
        return self.gw.call(session or self.session, b)

    def fake_approve(self, approval_id: str, grant: bool = False) -> bool:
        ap = self.store.get_approval(approval_id)
        receipt = {"type": "test-fake", "digest": ap["digest"], "approval_id": ap["id"], "nonce": ap["nonce"]}
        return self.store.mark_approved(approval_id, receipt, ap["grant_request"] if grant else None)

    def ledger(self):
        if not os.path.exists(self.config.ledger_path):
            return []
        with open(self.config.ledger_path) as f:
            return [json.loads(line) for line in f if line.strip()]


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


# ---------------------------------------------------------------------------
# A real WebAuthn-style ES256 assertion over the ASU challenge (no browser):
# used to exercise receipt re-verification on the execute path.
# ---------------------------------------------------------------------------
class SoftAuthenticator:
    def __init__(self, rp_id: str = "localhost", origin: str = "http://localhost:8000"):
        from cryptography.hazmat.primitives.asymmetric import ec

        self.rp_id = rp_id
        self.origin = origin
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(16)
        self.counter = 0

    def cose_public_key(self) -> bytes:
        import cbor2

        nums = self.key.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})

    def sign(self, challenge: bytes, flags: int = 0x05) -> Dict[str, str]:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec

        self.counter += 1
        auth_data = hashlib.sha256(self.rp_id.encode()).digest() + bytes([flags]) + self.counter.to_bytes(4, "big")
        cdj = json.dumps({"type": "webauthn.get", "challenge": b64u(challenge), "origin": self.origin,
                          "crossOrigin": False}).encode()
        sig = self.key.sign(auth_data + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))
        return {"authenticator_data": b64u(auth_data), "client_data_json": b64u(cdj), "signature": b64u(sig)}

    def receipt_for(self, ap: Dict[str, Any], with_grant: bool = False) -> Dict[str, Any]:
        from asu.authn import approval_challenge, grant_digest

        ch = approval_challenge(ap, with_grant=with_grant)
        r = {"v": 2, "credential_id": b64u(self.credential_id), **self.sign(ch), "digest": ap["digest"],
             "approval_id": ap["id"], "nonce": ap["nonce"], "alg": -7, "rp_id": self.rp_id,
             "grant_digest": grant_digest(ap["grant_request"]) if with_grant else None,
             "grant": ap["grant_request"] if with_grant else None}
        return r


def py_exec(desc: Dict[str, Any], digest: str) -> Dict[str, Any]:
    """Target for the ``python:test_gateway_fixtures:py_exec`` executor test."""
    return {"seen_tool": desc["tool"], "seen_digest": digest}


def register_soft_authenticator(env: "Env", user: str = "alice") -> SoftAuthenticator:
    auth = SoftAuthenticator()
    env.store.add_credential(user, auth.credential_id, auth.cose_public_key(), 0, ["internal"])
    return auth
