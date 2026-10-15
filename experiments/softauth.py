"""Software WebAuthn platform authenticator (ES256) + browser client behaviour.

Produces registration (attestation "none") and assertion responses in the
same wire format a browser returns from ``navigator.credentials.create/get``:
clientDataJSON, authenticatorData (rpIdHash | flags | signCount [| attested
credential data]), COSE_Key public key and DER ECDSA signature over
``authenticatorData || SHA-256(clientDataJSON)``. The gateway verifies these
with the real ``webauthn`` library, so the full cryptographic approval path
is exercised in every experiment.

This module is written independently of ``tests/fakes_authn.py`` so that the
experiments package does not import from ``tests/``.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import struct
from typing import Any, Dict, Optional

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class SoftAuthenticator:
    """One user's authenticator device (holds ES256 passkeys)."""

    AAGUID = b"\x00" * 16

    def __init__(self, origin: str = "http://localhost:8000", rp_id: str = "localhost"):
        self.origin = origin
        self.rp_id = rp_id
        self._creds: Dict[bytes, Dict[str, Any]] = {}
        self.assertions = 0

    @staticmethod
    def _cose(priv: ec.EllipticCurvePrivateKey) -> bytes:
        n = priv.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})

    def _client_data(self, typ: str, challenge_b64u: str) -> bytes:
        return json.dumps({"type": typ, "challenge": challenge_b64u, "origin": self.origin, "crossOrigin": False},
                          separators=(",", ":")).encode()

    def create(self, options: Dict[str, Any], user_verified: bool = True) -> Dict[str, Any]:
        """navigator.credentials.create(options) -> PublicKeyCredential JSON."""
        rp_id = (options.get("rp") or {}).get("id") or self.rp_id
        algs = [p.get("alg") for p in options.get("pubKeyCredParams") or []]
        if -7 not in algs:
            raise ValueError("relying party does not offer ES256")
        priv = ec.generate_private_key(ec.SECP256R1())
        cred_id = secrets.token_bytes(32)
        flags = 0x01 | (0x04 if user_verified else 0) | 0x40  # UP | UV | AT
        auth_data = (hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + struct.pack(">I", 0)
                     + self.AAGUID + struct.pack(">H", len(cred_id)) + cred_id + self._cose(priv))
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        cdj = self._client_data("webauthn.create", options["challenge"])
        self._creds[cred_id] = {"priv": priv, "rp_id": rp_id, "count": 0,
                                "user_handle": unb64u(options["user"]["id"])}
        return {"id": b64u(cred_id), "rawId": b64u(cred_id), "type": "public-key",
                "response": {"clientDataJSON": b64u(cdj), "attestationObject": b64u(att),
                             "transports": ["internal"]},
                "clientExtensionResults": {}, "authenticatorAttachment": "platform"}

    def get(self, options: Dict[str, Any], user_verified: bool = True) -> Dict[str, Any]:
        """navigator.credentials.get(options) -> PublicKeyCredential JSON.
        Signs whatever challenge the relying party (the gateway) put in the
        options; for an approval that is SHA-256("ASU-APPROVAL-v1"||h||id||nonce)."""
        rp_id = options.get("rpId") or self.rp_id
        allowed = [unb64u(c["id"]) for c in options.get("allowCredentials") or []]
        cands = [c for c in self._creds if not allowed or c in allowed]
        if not cands:
            raise LookupError("no matching credential on this authenticator")
        cred_id = cands[0]
        c = self._creds[cred_id]
        c["count"] += 1
        flags = 0x01 | (0x04 if user_verified else 0)
        auth_data = hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + struct.pack(">I", c["count"])
        cdj = self._client_data("webauthn.get", options["challenge"])
        sig = c["priv"].sign(auth_data + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))
        self.assertions += 1
        return {"id": b64u(cred_id), "rawId": b64u(cred_id), "type": "public-key",
                "response": {"clientDataJSON": b64u(cdj), "authenticatorData": b64u(auth_data),
                             "signature": b64u(sig), "userHandle": b64u(c["user_handle"])},
                "clientExtensionResults": {}, "authenticatorAttachment": "platform"}

    def sign_raw(self, challenge: bytes) -> Optional[Dict[str, str]]:
        """Raw assertion fields over ``challenge`` (latency microbenchmarks)."""
        if not self._creds:
            return None
        opts = {"challenge": b64u(challenge), "rpId": self.rp_id}
        a = self.get(opts)
        return {"credential_id": a["id"], "authenticator_data": a["response"]["authenticatorData"],
                "client_data_json": a["response"]["clientDataJSON"], "signature": a["response"]["signature"]}
