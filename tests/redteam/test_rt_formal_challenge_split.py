"""Formal-lens red team: the Tamarin model encodes the WebAuthn challenge as the
tuple <'ASU-APPROVAL-v1', h, aid, n>, which is injective. The implementation
(asu/authn/receipt.py compute_challenge) concatenates the variable-length
UTF-8 approval_id and nonce with no length prefix or separator, so a receipt
for (aid, n) also verifies, offline, for any (aid', n') with aid'||n' == aid||n.
L4 (JudgeAccepts(U, aid, hd) => Signed(U, aid, hd)) therefore does not hold
for the code's judge (verify_receipt / `asu verify-receipt`).

Secure behaviour asserted: a receipt verifies only for the approval id and
nonce that were actually signed.
"""
from __future__ import annotations

import base64
import hashlib
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from asu.authn.receipt import compute_challenge, verify_receipt

ORIGIN = "http://localhost:8000"
DIGEST = hashlib.sha256(b"some canonical descriptor").hexdigest()


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _signed_receipt(approval_id: str, nonce: str):
    sk = ec.generate_private_key(ec.SECP256R1())
    pem = sk.public_key().public_bytes(serialization.Encoding.PEM,
                                       serialization.PublicFormat.SubjectPublicKeyInfo)
    chal = compute_challenge(DIGEST, approval_id, nonce)
    auth_data = hashlib.sha256(b"localhost").digest() + bytes([0x05]) + (1).to_bytes(4, "big")
    cdj = json.dumps({"type": "webauthn.get", "challenge": _b64u(chal), "origin": ORIGIN}).encode()
    sig = sk.sign(auth_data + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))
    receipt = {
        "credential_id": _b64u(b"cred"), "authenticator_data": _b64u(auth_data),
        "client_data_json": _b64u(cdj), "signature": _b64u(sig), "digest": DIGEST,
        "approval_id": approval_id, "nonce": nonce, "alg": -7, "rp_id": "localhost",
    }
    return receipt, pem


def test_positive_control_receipt_verifies():
    receipt, pem = _signed_receipt("apr_AAAABBBB", "NONCE123")
    assert verify_receipt(receipt, pem, DIGEST, "apr_AAAABBBB", "NONCE123",
                          expected_origins=[ORIGIN], expected_rp_id="localhost")


def test_receipt_does_not_verify_for_resplit_approval_id_and_nonce():
    receipt, pem = _signed_receipt("apr_AAAABBBB", "NONCE123")
    forged = dict(receipt, approval_id="apr_AAAA", nonce="BBBBNONCE123")
    # A judge must not accept the user's signature as approving a *different*
    # approval id (the model's L4 binds aid). Currently this returns True.
    assert not verify_receipt(forged, pem, DIGEST, "apr_AAAA", "BBBBNONCE123",
                              expected_origins=[ORIGIN], expected_rp_id="localhost")
