"""Test helpers for the AUTHN area.

* ``FakeStore``: in-memory implementation of the SPEC section 7 Store interface
  (used when the gateway's ``asu.store`` / ``asu.app`` are not available, and
  to keep authn tests independent of the gateway).
* ``SoftAuthenticator``: a software WebAuthn authenticator that produces
  attestation ("none") and assertion responses byte-for-byte the way a browser
  + platform authenticator would (clientDataJSON, authenticatorData, COSE key,
  DER ECDSA / raw Ed25519 signatures).
* ``make_app``: minimal FastAPI app mounting ``asu.authn.router`` and serving
  ``web/`` at ``/app``.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import secrets
import struct
import threading
import time
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ----------------------------------------------------------------------------
# FakeStore (SPEC section 7)
# ----------------------------------------------------------------------------
class FakeStore:
    def __init__(self, path: str = ":memory:"):
        self.path = path
        self._lock = threading.Lock()
        self.users: Dict[str, Dict[str, Any]] = {}
        self.creds: Dict[bytes, Dict[str, Any]] = {}
        self.totp: Dict[str, str] = {}
        self.approvals: Dict[str, Dict[str, Any]] = {}
        self.grants: List[Dict[str, Any]] = []

    def create_user(self, user_id: str, display_name: str) -> None:
        with self._lock:
            if user_id in self.users:
                raise ValueError("user exists")
            self.users[user_id] = {"user_id": user_id, "display_name": display_name}

    def get_user(self, user_id: str):
        u = self.users.get(user_id)
        return dict(u) if u else None

    def add_credential(self, user_id, credential_id, public_key, sign_count, transports):
        with self._lock:
            if credential_id in self.creds:
                raise ValueError("duplicate credential")
            self.creds[bytes(credential_id)] = {
                "user_id": user_id,
                "credential_id": bytes(credential_id),
                "public_key": bytes(public_key),
                "sign_count": int(sign_count),
                "transports": list(transports),
            }

    def get_credentials(self, user_id):
        return [dict(c) for c in self.creds.values() if c["user_id"] == user_id]

    def update_sign_count(self, credential_id, sign_count):
        with self._lock:
            self.creds[bytes(credential_id)]["sign_count"] = int(sign_count)

    def set_totp_secret(self, user_id, secret):
        self.totp[user_id] = secret

    def get_totp_secret(self, user_id):
        return self.totp.get(user_id)

    # approvals -------------------------------------------------------------
    def add_approval(self, user_id, descriptor, digest=None, ttl=300, grant_request=None,
                     explanation=None, session_id="s1") -> Dict[str, Any]:
        """Test-only helper (the gateway creates approvals in its own code)."""
        if digest is None:
            import rfc8785

            digest = hashlib.sha256(rfc8785.dumps(descriptor)).hexdigest()
        now = int(time.time())
        ap = {
            "id": "ap_" + secrets.token_hex(8),
            "user_id": user_id,
            "session_id": session_id,
            "digest": digest,
            "descriptor": copy.deepcopy(descriptor),
            "nonce": secrets.token_hex(16),
            "status": "pending",
            "created_at": now,
            "expires_at": now + ttl,
            "receipt": None,
            "grant_request": grant_request,
            "explanation": explanation,
        }
        self.approvals[ap["id"]] = ap
        return copy.deepcopy(ap)

    def get_approval(self, approval_id):
        ap = self.approvals.get(approval_id)
        return copy.deepcopy(ap) if ap else None

    def list_pending(self, user_id):
        return [copy.deepcopy(a) for a in self.approvals.values()
                if a["user_id"] == user_id and a["status"] == "pending"]

    def mark_approved(self, approval_id, receipt, grant=None):
        with self._lock:
            ap = self.approvals.get(approval_id)
            if not ap or ap["status"] != "pending":
                return False
            ap["status"] = "approved"
            ap["receipt"] = copy.deepcopy(receipt)
            if grant is not None:
                self.grants.append({"approval_id": approval_id, **grant})
            return True

    def mark_denied(self, approval_id):
        with self._lock:
            ap = self.approvals.get(approval_id)
            if not ap or ap["status"] != "pending":
                return False
            ap["status"] = "denied"
            return True

    def consume(self, approval_id):
        with self._lock:
            ap = self.approvals.get(approval_id)
            if not ap or ap["status"] != "approved":
                return False
            ap["status"] = "consumed"
            return True


def fake_render_card(desc: Dict[str, Any]) -> Dict[str, Any]:
    """Stand-in for asu.descriptor.render_card used only if the gateway's is
    not importable. Derives everything from the descriptor."""
    args = desc.get("args", {})
    return {
        "title": f"{desc.get('tool')} → {desc.get('target')}",
        "effect_class": desc.get("effect_class"),
        "risk_lines": [f"This will {desc.get('effect_class')} via {desc.get('tool')}"],
        "fields": [{"label": k, "value": json.dumps(v) if not isinstance(v, str) else v}
                   for k, v in sorted(args.items())],
    }


def make_app(origins: Optional[List[str]] = None, rp_id: str = "localhost", **cfg):
    """Minimal authn app for unit tests. It runs in ``dev_mode`` by default
    (D-005 item 2: tokenless first enrollment for NEW user ids only) so that
    tests about ceremonies do not each need an enrollment link; tests about
    enrollment pass ``dev_mode=False``."""
    from fastapi import FastAPI
    from fastapi.staticfiles import StaticFiles

    from asu.authn import router

    cfg.setdefault("dev_mode", True)
    app = FastAPI()
    app.state.config = SimpleNamespace(
        rp_id=rp_id,
        rp_name="ASU test",
        expected_origins=origins or ["http://localhost:8000"],
        **cfg,
    )
    app.state.store = FakeStore()
    try:
        from asu.descriptor import render_card  # noqa: F401
    except Exception:
        app.state.render_card = fake_render_card
    app.include_router(router)
    app.mount("/app", StaticFiles(directory=os.path.join(ROOT, "web"), html=True), name="app")
    return app


# ----------------------------------------------------------------------------
# Software authenticator
# ----------------------------------------------------------------------------
class SoftAuthenticator:
    """Software platform authenticator + client (browser) behaviour."""

    AAGUID = b"\x00" * 16

    def __init__(self, alg: int = -7, origin: str = "http://localhost:8000", rp_id: str = "localhost"):
        self.alg = alg
        self.origin = origin
        self.rp_id = rp_id
        self.creds: Dict[bytes, Dict[str, Any]] = {}

    # --- key material ----------------------------------------------------
    def _new_key(self):
        if self.alg == -7:
            priv = ec.generate_private_key(ec.SECP256R1())
            nums = priv.public_key().public_numbers()
            cose = {1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")}
        elif self.alg == -8:
            priv = ed25519.Ed25519PrivateKey.generate()
            from cryptography.hazmat.primitives import serialization

            raw = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            cose = {1: 1, 3: -8, -1: 6, -2: raw}
        else:
            raise ValueError("alg")
        return priv, cbor2.dumps(cose)

    def _sign(self, priv, data: bytes) -> bytes:
        if isinstance(priv, ec.EllipticCurvePrivateKey):
            return priv.sign(data, ec.ECDSA(hashes.SHA256()))
        return priv.sign(data)

    def _cdj(self, typ: str, challenge_b64: str, origin: Optional[str] = None, cross_origin=False) -> bytes:
        # Same member order Chromium emits.
        return json.dumps(
            {"type": typ, "challenge": challenge_b64, "origin": origin or self.origin, "crossOrigin": cross_origin},
            separators=(",", ":"),
        ).encode()

    # --- navigator.credentials.create ------------------------------------
    def create(self, options: Dict[str, Any], *, origin: Optional[str] = None, up=True, uv=True) -> Dict[str, Any]:
        rp_id = options["rp"].get("id", self.rp_id)
        algs = [p["alg"] for p in options["pubKeyCredParams"]]
        assert self.alg in algs, "authenticator alg not offered"
        priv, cose = self._new_key()
        cred_id = secrets.token_bytes(32)
        flags = (0x01 if up else 0) | (0x04 if uv else 0) | 0x40
        auth_data = (
            hashlib.sha256(rp_id.encode()).digest()
            + bytes([flags])
            + struct.pack(">I", 0)
            + self.AAGUID
            + struct.pack(">H", len(cred_id))
            + cred_id
            + cose
        )
        att_obj = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        cdj = self._cdj("webauthn.create", options["challenge"], origin)
        self.creds[cred_id] = {
            "priv": priv,
            "cose": cose,
            "rp_id": rp_id,
            "user_handle": unb64u(options["user"]["id"]),
            "count": 0,
        }
        return {
            "id": b64u(cred_id),
            "rawId": b64u(cred_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64u(cdj),
                "attestationObject": b64u(att_obj),
                "transports": ["internal"],
            },
            "clientExtensionResults": {},
            "authenticatorAttachment": "platform",
        }

    # --- navigator.credentials.get ---------------------------------------
    def get(self, options: Dict[str, Any], *, origin: Optional[str] = None, up=True, uv=True,
            cred_id: Optional[bytes] = None, count: Optional[int] = None, typ="webauthn.get",
            cross_origin=False) -> Dict[str, Any]:
        rp_id = options.get("rpId", self.rp_id)
        allowed = [unb64u(c["id"]) for c in options.get("allowCredentials") or []]
        if cred_id is None:
            cands = [c for c in self.creds if not allowed or c in allowed]
            if not cands:
                raise LookupError("no matching credential")
            cred_id = cands[0]
        c = self.creds[cred_id]
        if count is None:
            c["count"] += 1
            count = c["count"]
        flags = (0x01 if up else 0) | (0x04 if uv else 0)
        auth_data = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + struct.pack(">I", count)
        cdj = self._cdj(typ, options["challenge"], origin, cross_origin)
        sig = self._sign(c["priv"], auth_data + hashlib.sha256(cdj).digest())
        return {
            "id": b64u(cred_id),
            "rawId": b64u(cred_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64u(cdj),
                "authenticatorData": b64u(auth_data),
                "signature": b64u(sig),
                "userHandle": b64u(c["user_handle"]),
            },
            "clientExtensionResults": {},
            "authenticatorAttachment": "platform",
        }
