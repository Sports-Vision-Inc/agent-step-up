"""RED TEAM (crypto lens): the approval challenge concatenates variable-length
fields without length prefixes or separators:

    c = SHA-256("ASU-APPROVAL-v1" || h || approval_id || nonce [|| h_grant])

so (approval_id="apr_X", nonce="YZ") and (approval_id="apr_XY", nonce="Z")
yield the same challenge. ``verify_receipt`` only compares the *unsigned*
receipt fields ``approval_id``/``nonce`` with the caller's values, and those
fields can be rewritten by whoever holds the receipt. One genuine signature
therefore verifies offline (P5) as an approval of a *different* approval id.
Gateway-generated ids/nonces are fixed-length today, so this is not
exploitable against the live gateway, but the offline verifier's binding claim
("which approval was approved") does not hold as specified.

Secure behaviour asserted: a receipt does not verify for an (id, nonce) pair
other than the one that was signed.
"""
from __future__ import annotations

import hashlib
import os
import struct
import sys

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from asu.authn.receipt import approval_challenge, b64u_encode, verify_receipt

DIGEST = hashlib.sha256(b"some descriptor").hexdigest()
ORIGIN = "http://localhost:8000"


def _sign_receipt(priv, ap):
    import json

    ch = approval_challenge(ap)
    cdj = json.dumps({"type": "webauthn.get", "challenge": b64u_encode(ch), "origin": ORIGIN,
                      "crossOrigin": False}, separators=(",", ":")).encode()
    auth_data = hashlib.sha256(b"localhost").digest() + bytes([0x05]) + struct.pack(">I", 1)
    sig = priv.sign(auth_data + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))
    return {"credential_id": "AA", "authenticator_data": b64u_encode(auth_data),
            "client_data_json": b64u_encode(cdj), "signature": b64u_encode(sig),
            "digest": ap["digest"], "approval_id": ap["id"], "nonce": ap["nonce"], "alg": -7,
            "rp_id": "localhost"}


def test_receipt_not_valid_for_resplit_id_and_nonce():
    priv = ec.generate_private_key(ec.SECP256R1())
    n = priv.public_key().public_numbers()
    pub = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})

    ap = {"id": "apr_victim", "nonce": "N0nce123", "digest": DIGEST}
    rc = _sign_receipt(priv, ap)
    assert verify_receipt(rc, pub, DIGEST, ap["id"], ap["nonce"], expected_rp_id="localhost")

    forged = dict(rc, approval_id="apr_victimN0", nonce="nce123")
    assert not verify_receipt(forged, pub, DIGEST, "apr_victimN0", "nce123", expected_rp_id="localhost"), (
        "one signature verifies for two different (approval_id, nonce) pairs: challenge is not injective")
