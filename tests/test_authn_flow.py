"""End-to-end (in-process) tests of the AUTHN routes with a software
authenticator: register -> login -> approve -> verify_receipt, plus negatives."""
from __future__ import annotations

import copy
import hashlib
import json
import time

import pytest
from fastapi.testclient import TestClient

try:
    from fakes_authn import FakeStore, SoftAuthenticator, b64u, make_app, unb64u
except ImportError:  # tests/ became a package
    from tests.fakes_authn import FakeStore, SoftAuthenticator, b64u, make_app, unb64u

from asu.authn import approval_challenge, verify_receipt, SESSION_COOKIE
from asu.authn.receipt import grant_digest

ORIGIN = "http://localhost:8000"
H = {"Origin": ORIGIN}

DESC = {
    "v": 1,
    "tool": "send_email",
    "effect_class": "send",
    "args": {"to": "bob@example.com", "subject": "Q3 numbers", "body": "attached"},
    "target": "bob@example.com",
    "principal": "alice",
    "session_id": "s1",
    "agent_id": "agent-1",
    "origin": "user_turn",
    "issued_at": 1700000000,
    "expires_at": 1700000300,
}


def new_client(**cfg):
    app = make_app(**cfg)
    return app, TestClient(app, base_url=ORIGIN)


def register(client, auth, user="alice", **kw):
    r = client.post("/v1/authn/register/options", json={"user_id": user, "display_name": user.title(), **kw}, headers=H)
    assert r.status_code == 200, r.text
    opts = r.json()
    cred = auth.create(opts)
    r = client.post("/v1/authn/register/verify", json={"credential": cred}, headers=H)
    assert r.status_code == 200, r.text
    return opts, cred


def login(client, auth, user="alice", **get_kw):
    r = client.post("/v1/authn/login/options", json={"user_id": user}, headers=H)
    assert r.status_code == 200, r.text
    a = auth.get(r.json(), **get_kw)
    return client.post("/v1/authn/login/verify", json={"credential": a}, headers=H)


def approve(client, auth, ap_id, grant=False, **get_kw):
    r = client.post(f"/v1/authn/approvals/{ap_id}/options", json={"grant": grant}, headers=H)
    assert r.status_code == 200, r.text
    opts = r.json()
    a = auth.get(opts, **get_kw)
    return opts, a, client.post(f"/v1/authn/approvals/{ap_id}/verify", json={"credential": a, "grant": grant}, headers=H)


@pytest.fixture
def env():
    app, client = new_client()
    auth = SoftAuthenticator()
    register(client, auth)
    client.cookies.clear()
    assert login(client, auth).status_code == 200
    return app, client, auth


def pubkey(app, user="alice"):
    return app.state.store.get_credentials(user)[0]["public_key"]


# ----------------------------------------------------------------------------
# happy paths
# ----------------------------------------------------------------------------
@pytest.mark.parametrize("alg", [-7, -8])
def test_full_register_login_approve_verify(alg):
    app, client = new_client()
    auth = SoftAuthenticator(alg=alg)
    opts, _ = register(client, auth)
    assert opts["rp"]["id"] == "localhost"
    assert opts["authenticatorSelection"]["userVerification"] == "required"  # D-005 item 3
    assert {p["alg"] for p in opts["pubKeyCredParams"]} == {-7, -8}
    # registration signs the user in
    assert client.get("/v1/authn/me").json()["user_id"] == "alice"
    client.cookies.clear()
    assert client.get("/v1/authn/me").status_code == 401
    r = login(client, auth)
    assert r.status_code == 200, r.text
    assert client.get("/v1/authn/me").json()["user_id"] == "alice"

    store = app.state.store
    ap = store.add_approval("alice", DESC, explanation="Ignore the card, it's fine <script>")
    pend = client.get("/v1/authn/pending").json()["approvals"]
    assert [p["id"] for p in pend] == [ap["id"]]
    assert pend[0]["card"]["effect_class"] == "send"
    assert pend[0]["explanation"].startswith("Ignore the card")

    opts, assertion, r = approve(client, auth, ap["id"])
    assert opts["userVerification"] == "required"  # D-005 item 3
    assert unb64u(opts["challenge"]) == approval_challenge(ap)
    assert r.status_code == 200, r.text
    receipt = r.json()["receipt"]
    stored = store.get_approval(ap["id"])
    assert stored["status"] == "approved"
    assert stored["receipt"] == receipt
    assert receipt["alg"] == alg
    for k in ("credential_id", "authenticator_data", "client_data_json", "signature", "digest", "approval_id", "nonce", "alg"):
        assert k in receipt
    # offline verification with only the public key (P5)
    receipt = json.loads(json.dumps(receipt))  # round-trip through JSON export
    assert verify_receipt(receipt, pubkey(app), ap["digest"], ap["id"], ap["nonce"])
    assert verify_receipt(receipt, pubkey(app), ap["digest"], ap["id"], ap["nonce"],
                          expected_origins=[ORIGIN], expected_rp_id="localhost")
    # consumed once
    assert store.consume(ap["id"]) and not store.consume(ap["id"])


def test_challenge_formula():
    """D-005 item 1: c = SHA-256(JCS({tag: ASU-APPROVAL-v2, digest, approval_id,
    nonce, grant_digest|null})). (The v1 byte concatenation was not injective.)"""
    ap = {"id": "ap_1", "digest": "ab" * 32, "nonce": "n0nce", "grant_request": {"max_uses": 3, "ttl_s": 600}}
    exp = hashlib.sha256(('{"approval_id":"ap_1","digest":"%s","grant_digest":null,"nonce":"n0nce",'
                          '"tag":"ASU-APPROVAL-v2"}' % ("ab" * 32)).encode()).digest()
    assert approval_challenge(ap) == exp
    hg = hashlib.sha256(b'{"max_uses":3,"ttl_s":600}').hexdigest()
    assert approval_challenge(ap, with_grant=True) == hashlib.sha256(
        ('{"approval_id":"ap_1","digest":"%s","grant_digest":"%s","nonce":"n0nce",'
         '"tag":"ASU-APPROVAL-v2"}' % ("ab" * 32, hg)).encode()).digest()
    # injective: re-splitting id/nonce gives a different challenge (CR-2)
    assert approval_challenge(dict(ap, id="ap_1n", nonce="0nce")) != exp
    with pytest.raises(ValueError):
        approval_challenge({**ap, "digest": "zz"})
    with pytest.raises(ValueError):
        approval_challenge({**ap, "grant_request": None}, with_grant=True)


def test_grant_similar_is_signed(env):
    app, client, auth = env
    gr = {"tool": "send_email", "constraints": {"to": "bob@example.com"}, "max_uses": 3, "ttl_s": 600}
    ap = app.state.store.add_approval("alice", DESC, grant_request=gr)
    pend = client.get("/v1/authn/pending").json()["approvals"][0]
    assert pend["grant_request"] == gr and pend["grant_digest"] == grant_digest(gr)
    opts, a, r = approve(client, auth, ap["id"], grant=True)
    assert unb64u(opts["challenge"]) == approval_challenge(ap, with_grant=True)
    assert r.status_code == 200, r.text
    rc = r.json()["receipt"]
    assert rc["grant_digest"] == grant_digest(gr)
    assert app.state.store.grants and app.state.store.grants[0]["max_uses"] == 3
    pk = pubkey(app)
    assert verify_receipt(rc, pk, ap["digest"], ap["id"], ap["nonce"], expected_grant_digest=grant_digest(gr))
    # stretching the grant in the receipt breaks verification (P6)
    bad = copy.deepcopy(rc)
    bad["grant"]["max_uses"] = 100
    assert not verify_receipt(bad, pk, ap["digest"], ap["id"], ap["nonce"])
    bad["grant_digest"] = grant_digest(bad["grant"])
    assert not verify_receipt(bad, pk, ap["digest"], ap["id"], ap["nonce"])
    # dropping the grant digest also breaks it
    bad2 = dict(rc, grant=None, grant_digest=None)
    assert not verify_receipt(bad2, pk, ap["digest"], ap["id"], ap["nonce"])


def test_grant_box_ticked_but_signature_without_grant_rejected(env):
    app, client, auth = env
    ap = app.state.store.add_approval("alice", DESC, grant_request={"max_uses": 2})
    r = client.post(f"/v1/authn/approvals/{ap['id']}/options", json={"grant": False}, headers=H)
    a = auth.get(r.json())
    r = client.post(f"/v1/authn/approvals/{ap['id']}/verify", json={"credential": a, "grant": True}, headers=H)
    assert r.status_code == 400
    assert app.state.store.get_approval(ap["id"])["status"] == "pending"
    assert not app.state.store.grants


def test_deny(env):
    app, client, auth = env
    ap = app.state.store.add_approval("alice", DESC)
    r = client.post(f"/v1/authn/approvals/{ap['id']}/deny", json={}, headers=H)
    assert r.status_code == 200
    assert app.state.store.get_approval(ap["id"])["status"] == "denied"
    assert client.get("/v1/authn/pending").json()["approvals"] == []
    r = client.post(f"/v1/authn/approvals/{ap['id']}/options", json={}, headers=H)
    assert r.status_code == 409
    assert client.post(f"/v1/authn/approvals/{ap['id']}/deny", json={}, headers=H).status_code == 409


# ----------------------------------------------------------------------------
# negatives
# ----------------------------------------------------------------------------
def test_wrong_digest_rejected(env):
    app, client, auth = env
    ap = app.state.store.add_approval("alice", DESC)
    _, _, r = approve(client, auth, ap["id"])
    rc = r.json()["receipt"]
    other = hashlib.sha256(b"different effect").hexdigest()
    assert not verify_receipt(rc, pubkey(app), other, ap["id"], ap["nonce"])
    forged = dict(rc, digest=other)
    assert not verify_receipt(forged, pubkey(app), other, ap["id"], ap["nonce"])


def test_assertion_for_other_digest_rejected_by_server(env):
    """Agent swaps the effect: an assertion over approval A's challenge must not
    approve approval B (different digest)."""
    app, client, auth = env
    store = app.state.store
    a1 = store.add_approval("alice", DESC)
    d2 = dict(DESC, args=dict(DESC["args"], to="mallory@evil.test"), target="mallory@evil.test")
    a2 = store.add_approval("alice", d2)
    r = client.post(f"/v1/authn/approvals/{a1['id']}/options", json={}, headers=H)
    assertion = auth.get(r.json())
    r = client.post(f"/v1/authn/approvals/{a2['id']}/verify", json={"credential": assertion}, headers=H)
    assert r.status_code == 400
    assert store.get_approval(a2["id"])["status"] == "pending"


def test_wrong_approval_id_and_nonce(env):
    app, client, auth = env
    ap = app.state.store.add_approval("alice", DESC)
    _, _, r = approve(client, auth, ap["id"])
    rc = r.json()["receipt"]
    pk = pubkey(app)
    assert not verify_receipt(rc, pk, ap["digest"], "ap_other", ap["nonce"])
    assert not verify_receipt(dict(rc, approval_id="ap_other"), pk, ap["digest"], "ap_other", ap["nonce"])
    assert not verify_receipt(rc, pk, ap["digest"], ap["id"], "othernonce")
    assert not verify_receipt(dict(rc, nonce="othernonce"), pk, ap["digest"], ap["id"], "othernonce")


def test_replayed_assertion_rejected(env):
    app, client, auth = env
    store = app.state.store
    ap = store.add_approval("alice", DESC)
    _, assertion, r = approve(client, auth, ap["id"])
    assert r.status_code == 200
    # same assertion again on the same approval
    r = client.post(f"/v1/authn/approvals/{ap['id']}/verify", json={"credential": assertion}, headers=H)
    assert r.status_code == 409
    # same descriptor, new approval (new id + nonce): old assertion is useless
    ap2 = store.add_approval("alice", DESC)
    r = client.post(f"/v1/authn/approvals/{ap2['id']}/verify", json={"credential": assertion}, headers=H)
    assert r.status_code == 400
    # replay of login assertion
    r = client.post("/v1/authn/login/options", json={"user_id": "alice"}, headers=H)
    la = auth.get(r.json())
    assert client.post("/v1/authn/login/verify", json={"credential": la}, headers=H).status_code == 200
    assert client.post("/v1/authn/login/verify", json={"credential": la}, headers=H).status_code == 400


def test_wrong_origin_rejected(env):
    app, client, auth = env
    ap = app.state.store.add_approval("alice", DESC)
    _, _, r = approve(client, auth, ap["id"], origin="http://evil.localhost:8000")
    assert r.status_code == 400
    _, _, r = approve(client, auth, ap["id"], origin="https://localhost.evil.com")
    assert r.status_code == 400
    # cross-origin iframe ceremony rejected
    _, _, r = approve(client, auth, ap["id"], cross_origin=True)
    assert r.status_code == 400
    assert app.state.store.get_approval(ap["id"])["status"] == "pending"
    # registration from wrong origin
    _, c2 = new_client()
    r = c2.post("/v1/authn/register/options", json={"user_id": "bob"}, headers=H)
    cred = SoftAuthenticator(origin="http://evil.test").create(r.json())
    assert c2.post("/v1/authn/register/verify", json={"credential": cred}, headers=H).status_code == 400


def test_receipt_origin_checks_offline(env):
    app, client, auth = env
    ap = app.state.store.add_approval("alice", DESC)
    _, _, r = approve(client, auth, ap["id"])
    rc = r.json()["receipt"]
    pk = pubkey(app)
    assert not verify_receipt(rc, pk, ap["digest"], ap["id"], ap["nonce"], expected_origins=["https://gw.example"])
    assert not verify_receipt(rc, pk, ap["digest"], ap["id"], ap["nonce"], expected_rp_id="example.com")
    # tamper with clientDataJSON origin -> signature breaks too
    cd = json.loads(unb64u(rc["client_data_json"]))
    cd["origin"] = "http://localhost:9999"
    assert not verify_receipt(dict(rc, client_data_json=b64u(json.dumps(cd).encode())), pk, ap["digest"], ap["id"], ap["nonce"])


def test_up_flag_missing_rejected(env):
    app, client, auth = env
    ap = app.state.store.add_approval("alice", DESC)
    _, a, r = approve(client, auth, ap["id"], up=False)
    assert r.status_code == 400
    assert "present" in r.json()["detail"]
    # offline verifier also rejects UP=0 even with a valid signature
    c = auth.creds[unb64u(a["id"])]
    import struct
    ad = hashlib.sha256(b"localhost").digest() + bytes([0x04]) + struct.pack(">I", 999)
    cdj = unb64u(a["response"]["clientDataJSON"])
    sig = auth._sign(c["priv"], ad + hashlib.sha256(cdj).digest())
    rc = {"credential_id": a["id"], "authenticator_data": b64u(ad), "client_data_json": b64u(cdj),
          "signature": b64u(sig), "digest": ap["digest"], "approval_id": ap["id"], "nonce": ap["nonce"], "alg": -7}
    assert not verify_receipt(rc, pubkey(app), ap["digest"], ap["id"], ap["nonce"])
    rc_ok = dict(rc)
    ad_ok = ad[:32] + bytes([0x05]) + ad[33:]
    rc_ok.update(authenticator_data=b64u(ad_ok), signature=b64u(auth._sign(c["priv"], ad_ok + hashlib.sha256(cdj).digest())))
    assert verify_receipt(rc_ok, pubkey(app), ap["digest"], ap["id"], ap["nonce"])


def test_sign_count_regression_rejected(env):
    app, client, auth = env
    ap1 = app.state.store.add_approval("alice", DESC)
    _, _, r = approve(client, auth, ap1["id"])
    assert r.status_code == 200
    current = app.state.store.get_credentials("alice")[0]["sign_count"]
    assert current >= 2
    ap2 = app.state.store.add_approval("alice", DESC)
    _, _, r = approve(client, auth, ap2["id"], count=current)  # cloned authenticator
    assert r.status_code == 400 and "sign count" in r.json()["detail"]
    _, _, r = approve(client, auth, ap2["id"], count=1)
    assert r.status_code == 400
    _, _, r = approve(client, auth, ap2["id"])
    assert r.status_code == 200


def test_other_users_credential_rejected(env):
    app, client, auth = env
    store = app.state.store
    # mallory registers her own passkey in a separate browser
    mc = TestClient(app, base_url=ORIGIN)
    mauth = SoftAuthenticator()
    register(mc, mauth, user="mallory")
    ap = store.add_approval("alice", DESC)
    # mallory cannot see or act on alice's approval with her own cookie
    assert mc.get("/v1/authn/pending").json()["approvals"] == []
    assert mc.post(f"/v1/authn/approvals/{ap['id']}/options", json={}, headers=H).status_code == 404
    assert mc.post(f"/v1/authn/approvals/{ap['id']}/deny", json={}, headers=H).status_code == 404
    # alice's session + mallory's credential over the correct challenge -> rejected
    r = client.post(f"/v1/authn/approvals/{ap['id']}/options", json={}, headers=H)
    opts = r.json()
    opts_any = dict(opts, allowCredentials=[])
    ma = mauth.get(opts_any)
    r = client.post(f"/v1/authn/approvals/{ap['id']}/verify", json={"credential": ma}, headers=H)
    assert r.status_code == 400
    assert store.get_approval(ap["id"])["status"] == "pending"
    # and offline: a receipt signed by mallory doesn't verify under alice's key
    mrc = {"credential_id": ma["id"], "authenticator_data": ma["response"]["authenticatorData"],
           "client_data_json": ma["response"]["clientDataJSON"], "signature": ma["response"]["signature"],
           "digest": ap["digest"], "approval_id": ap["id"], "nonce": ap["nonce"], "alg": -7}
    assert verify_receipt(mrc, store.get_credentials("mallory")[0]["public_key"], ap["digest"], ap["id"], ap["nonce"])
    assert not verify_receipt(mrc, pubkey(app), ap["digest"], ap["id"], ap["nonce"])


def test_expired_approval_rejected(env):
    app, client, auth = env
    ap = app.state.store.add_approval("alice", DESC, ttl=-1)
    assert client.get("/v1/authn/pending").json()["approvals"] == []
    r = client.post(f"/v1/authn/approvals/{ap['id']}/options", json={}, headers=H)
    assert r.status_code == 410


def test_approve_requires_signed_in_session(env):
    app, client, auth = env
    ap = app.state.store.add_approval("alice", DESC)
    r = client.post(f"/v1/authn/approvals/{ap['id']}/options", json={}, headers=H)
    a = auth.get(r.json())
    anon = TestClient(app, base_url=ORIGIN)
    assert anon.post(f"/v1/authn/approvals/{ap['id']}/verify", json={"credential": a}, headers=H).status_code == 401
    assert anon.get("/v1/authn/pending").status_code == 401
    # forged cookie
    anon.cookies.set(SESSION_COOKIE, "eyJ1IjoiYWxpY2UifQ.forged.sig")
    assert anon.get("/v1/authn/pending").status_code == 401


def test_csrf_guards(env):
    app, client, auth = env
    ap = app.state.store.add_approval("alice", DESC)
    r = client.post(f"/v1/authn/approvals/{ap['id']}/deny", json={}, headers={"Origin": "https://evil.test"})
    assert r.status_code == 403
    r = client.post(f"/v1/authn/approvals/{ap['id']}/deny", content=b"x=1",
                    headers={"Origin": ORIGIN, "Content-Type": "application/x-www-form-urlencoded"})
    assert r.status_code == 415
    assert app.state.store.get_approval(ap["id"])["status"] == "pending"


def test_tampered_signature_and_type(env):
    app, client, auth = env
    ap = app.state.store.add_approval("alice", DESC)
    _, _, r = approve(client, auth, ap["id"], typ="webauthn.create")
    assert r.status_code == 400
    r = client.post(f"/v1/authn/approvals/{ap['id']}/options", json={}, headers=H)
    a = auth.get(r.json())
    sig = bytearray(unb64u(a["response"]["signature"]))
    sig[-1] ^= 1
    a["response"]["signature"] = b64u(bytes(sig))
    r = client.post(f"/v1/authn/approvals/{ap['id']}/verify", json={"credential": a}, headers=H)
    assert r.status_code == 400
    # malformed receipts never raise
    assert verify_receipt({}, pubkey(app), ap["digest"], ap["id"], ap["nonce"]) is False
    assert verify_receipt({"credential_id": 1}, b"junk", "x", "y", "z") is False


def test_add_second_passkey_requires_sign_in():
    app, client = new_client()
    auth = SoftAuthenticator()
    register(client, auth)
    attacker = TestClient(app, base_url=ORIGIN)
    r = attacker.post("/v1/authn/register/options", json={"user_id": "alice"}, headers=H)
    assert r.status_code == 403
    # signed-in user may add one
    r = client.post("/v1/authn/register/options", json={"user_id": "alice"}, headers=H)
    assert r.status_code == 200
    assert len(r.json()["excludeCredentials"]) == 1
    cred = SoftAuthenticator().create(r.json())
    assert client.post("/v1/authn/register/verify", json={"credential": cred}, headers=H).status_code == 200
    assert len(app.state.store.get_credentials("alice")) == 2


def test_enrollment_token():
    app, client = new_client(enrollment_token="s3cret-enroll", dev_mode=False)
    r = client.post("/v1/authn/register/options", json={"user_id": "alice"}, headers=H)
    assert r.status_code == 403
    r = client.post("/v1/authn/register/options", json={"user_id": "alice", "enrollment_token": "nope"}, headers=H)
    assert r.status_code == 403
    register(client, SoftAuthenticator(), enrollment_token="s3cret-enroll")


def test_unknown_registration_challenge_rejected():
    app, client = new_client()
    auth = SoftAuthenticator()
    r = client.post("/v1/authn/register/options", json={"user_id": "alice"}, headers=H)
    opts = r.json()
    opts["challenge"] = b64u(b"\x01" * 32)
    cred = auth.create(opts)
    assert client.post("/v1/authn/register/verify", json={"credential": cred}, headers=H).status_code == 400
    assert app.state.store.get_user("alice") is None


def test_open_enrollment_refused_outside_localhost():
    app, client = new_client(rp_id="gw.example.com", origins=["https://gw.example.com"], dev_mode=False)
    r = client.post("/v1/authn/register/options", json={"user_id": "alice"}, headers={"Origin": "https://gw.example.com"})
    assert r.status_code == 403
    app, client = new_client(rp_id="gw.example.com", origins=["https://gw.example.com"], enrollment_token="t0k",
                             dev_mode=False)
    r = client.post("/v1/authn/register/options", json={"user_id": "alice", "enrollment_token": "t0k"},
                    headers={"Origin": "https://gw.example.com"})
    assert r.status_code == 200 and r.json()["rp"]["id"] == "gw.example.com"


def test_duplicate_credential_id_across_users_rejected():
    app, client = new_client()
    auth = SoftAuthenticator()
    register(client, auth)
    cid = next(iter(auth.creds))
    other = TestClient(app, base_url=ORIGIN)
    r = other.post("/v1/authn/register/options", json={"user_id": "eve"}, headers=H)
    cred = auth.create(r.json())
    # replay alice's credential id under eve
    new_id = unb64u(cred["id"])
    import cbor2
    att = cbor2.loads(unb64u(cred["response"]["attestationObject"]))
    ad = att["authData"]
    ad = ad[:55] + cid + ad[55 + len(new_id):]
    att["authData"] = ad
    cred["response"]["attestationObject"] = b64u(cbor2.dumps(att))
    cred["id"] = cred["rawId"] = b64u(cid)
    r = other.post("/v1/authn/register/verify", json={"credential": cred}, headers=H)
    assert r.status_code == 409
    assert app.state.store.get_credentials("alice")[0]["credential_id"] == cid
