"""User-facing authenticator routes, mounted at /v1/authn (SPEC sections 7, 8).

The agent never calls these. Every approval requires a fresh WebAuthn
assertion whose challenge is derived from the approval's effect digest
(``approval_challenge``); the session cookie only gates *viewing* and
*denying* and is never sufficient to approve.
"""
from __future__ import annotations

import base64
import binascii
import json
import secrets
import threading
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.exceptions import (
    InvalidAuthenticationResponse,
    InvalidRegistrationResponse,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from . import session as sess
from .receipt import (
    RECEIPT_VERSION,
    alg_of_public_key,
    approval_challenge,
    authenticator_flags,
    b64u_decode,
    b64u_encode,
    grant_digest,
    verify_receipt,
)

router = APIRouter(prefix="/v1/authn", tags=["authn"])

SUPPORTED_ALGS = [COSEAlgorithmIdentifier.ECDSA_SHA_256, COSEAlgorithmIdentifier.EDDSA]
MAX_USER_ID_LEN = 64
MAX_EXPLANATION_LEN = 4000
TOTP_MAX_FAILURES = 5


# ----------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------
def _store(request: Request):
    store = getattr(request.app.state, "store", None)
    if store is None:
        raise HTTPException(503, "store not configured")
    return store


def _as_bytes(v: Any) -> bytes:
    if isinstance(v, (bytes, bytearray, memoryview)):
        return bytes(v)
    if isinstance(v, str):
        try:
            return b64u_decode(v)
        except (ValueError, binascii.Error):
            return bytes.fromhex(v)
    raise TypeError("expected bytes")


def _valid_user_id(uid: str) -> bool:
    return (
        isinstance(uid, str)
        and 0 < len(uid) <= MAX_USER_ID_LEN
        and all(c.isalnum() or c in "-_.@+" for c in uid)
    )


def guard_post(request: Request) -> None:
    """CSRF / cross-site defence for state-changing requests.

    Browsers always send Origin on fetch POSTs; when present it must be one of
    the configured origins. A JSON content type is required so that a
    cross-site form or no-cors fetch (which cannot set it) is rejected.
    """
    origin = request.headers.get("origin")
    if origin is not None and origin not in sess.expected_origins(request.app):
        raise HTTPException(403, "bad origin")
    ctype = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if ctype != "application/json":
        raise HTTPException(415, "application/json required")


def require_user(request: Request) -> str:
    uid = sess.current_user(request)
    if uid is None:
        raise HTTPException(401, "not signed in")
    return uid


def _uv_requirement(request: Request) -> UserVerificationRequirement:
    # D-005 item 3: REQUIRED unless explicitly opted out
    return UserVerificationRequirement.REQUIRED if sess.require_uv(request.app) \
        else UserVerificationRequirement.PREFERRED


def _cas_sign_count(store, credential_id: bytes, new_count: int) -> None:
    """Sign count compare-and-set (CR-9): refuse an assertion whose counter
    does not move forward (cloned authenticator or concurrent replay)."""
    ok = store.update_sign_count(credential_id, new_count)
    if ok is False:
        raise HTTPException(409, "signature counter did not increase (possible cloned authenticator)")


def _options_response(options) -> Response:
    return Response(content=options_to_json(options), media_type="application/json")


def _parse_client_data(credential: Dict[str, Any]) -> Dict[str, Any]:
    try:
        raw = b64u_decode(credential["response"]["clientDataJSON"])
        cd = json.loads(raw.decode("utf-8"))
        if not isinstance(cd, dict):
            raise ValueError
        return cd
    except Exception:
        raise HTTPException(400, "malformed clientDataJSON")


def _check_not_cross_origin(cd: Dict[str, Any]) -> None:
    if cd.get("crossOrigin") is True:
        raise HTTPException(400, "cross-origin ceremony rejected")


def _find_credential(store, user_id: str, raw_id: bytes) -> Optional[Dict[str, Any]]:
    for c in store.get_credentials(user_id):
        if _as_bytes(c["credential_id"]) == raw_id:
            return c
    return None


def _credential_raw_id(credential: Dict[str, Any]) -> bytes:
    try:
        raw = b64u_decode(credential.get("rawId") or credential["id"])
    except Exception:
        raise HTTPException(400, "malformed credential id")
    if b64u_encode(raw) != credential.get("id"):
        raise HTTPException(400, "id and rawId differ")
    return raw


def _check_user_handle(credential: Dict[str, Any], user_id: str) -> None:
    uh = (credential.get("response") or {}).get("userHandle")
    if uh:
        try:
            if b64u_decode(uh) != sess.user_handle(user_id):
                raise HTTPException(400, "user handle mismatch")
        except ValueError:
            raise HTTPException(400, "malformed user handle")


def _audit(request: Request, event: str, data: Dict[str, Any]) -> None:
    """Best-effort hook into the gateway's audit log if it exposes one as
    ``app.state.audit`` with an ``append(event, data)`` method."""
    audit = getattr(request.app.state, "audit", None)
    fn = getattr(audit, "append", None)
    if callable(fn):
        try:
            fn(event, data)
        except TypeError:
            try:
                fn({"event": event, **data})
            except Exception:
                pass
        except Exception:
            pass


def _render_card(request: Request, ap: Dict[str, Any]) -> Dict[str, Any]:
    """Card from the gateway's trusted renderer (asu.descriptor.render_card).

    In the ``narrated-card`` BASELINE the gateway's render_narrated_card is
    used instead (P4 deliberately violated, for comparison only)."""
    app = request.app
    descriptor = ap["descriptor"]
    expl = ap.get("explanation")
    if _mode(request, ap) == "narrated-card":
        try:
            from asu.descriptor import render_narrated_card  # type: ignore

            return render_narrated_card(descriptor, expl)
        except ImportError:
            raise HTTPException(503, "card renderer unavailable")
    fn = getattr(app.state, "render_card", None)
    if fn is None:
        try:
            from asu.descriptor import render_card as fn  # type: ignore
        except Exception:
            raise HTTPException(503, "card renderer unavailable")
    try:
        card = fn(descriptor, reasons=ap.get("reasons"), explanation=expl,
                  workspace_root=sess.cfg(app, "workspace_root"))
    except TypeError:
        card = fn(descriptor)
    if not isinstance(card, dict):
        raise HTTPException(500, "bad card")
    # Consistency check: the card must describe exactly the approved digest.
    if card.get("digest") is not None and card["digest"] != ap.get("digest"):
        raise HTTPException(500, "card digest does not match approval digest")
    return card


def _mode(request: Request, ap: Dict[str, Any]) -> Optional[str]:
    """Approval mode: the mode recorded on the approval by the gateway (if
    any), else the configured ``approval_mode``."""
    return ap.get("mode") or sess.approval_mode(request.app)


def _expired(ap: Dict[str, Any]) -> bool:
    exp = ap.get("expires_at")
    return exp is not None and float(exp) <= time.time()


def _load_user_approval(request: Request, approval_id: str, user_id: str) -> Dict[str, Any]:
    ap = _store(request).get_approval(approval_id)
    # Same 404 for "missing" and "someone else's" so ids do not leak.
    if ap is None or ap.get("user_id") != user_id:
        raise HTTPException(404, "approval not found")
    return ap


def _require_pending(ap: Dict[str, Any]) -> None:
    if ap.get("status") != "pending":
        raise HTTPException(409, "approval is not pending")
    if _expired(ap):
        raise HTTPException(410, "approval expired")


# ----------------------------------------------------------------------------
# request bodies
# ----------------------------------------------------------------------------
class RegisterOptionsIn(BaseModel):
    user_id: str
    display_name: Optional[str] = None
    enrollment_token: Optional[str] = None


class CredentialIn(BaseModel):
    credential: Dict[str, Any]


class LoginOptionsIn(BaseModel):
    user_id: str


class ApprovalOptionsIn(BaseModel):
    grant: bool = False


class ApprovalVerifyIn(BaseModel):
    credential: Dict[str, Any]
    grant: bool = False


class TotpVerifyIn(BaseModel):
    code: str = Field(..., min_length=6, max_length=8)


# ----------------------------------------------------------------------------
# registration
# ----------------------------------------------------------------------------
@router.post("/register/options", dependencies=[Depends(guard_post)])
def register_options(body: RegisterOptionsIn, request: Request):
    """Start passkey enrollment (D-005 item 2: enrollment is CLOSED by default).

    * A user who already has a passkey can add another only while signed in
      as that user.
    * First enrollment for ANY user requires a one-time enrollment token that
      the operator delivers out of band (``asu enroll-link --user U`` prints a
      one-time URL), or the legacy static ``enrollment_token`` secret.
    * Only an explicit ``dev_mode: true`` relaxes this, and even then only for
      a user id that does not exist yet (never for a provisioned user that
      already has agent sessions: CR-1 / RT-4).
    """
    if not _valid_user_id(body.user_id):
        raise HTTPException(400, "invalid user_id")
    store = _store(request)
    app = request.app
    user_exists = store.get_user(body.user_id) is not None
    existing = store.get_credentials(body.user_id) if user_exists else []
    enroll_mode = None
    if existing:
        if sess.current_user(request) != body.user_id:
            raise HTTPException(403, "sign in with an existing passkey to add another")
        enroll_mode = "add"
    else:
        import hmac

        tok = body.enrollment_token
        static = sess.cfg(app, "enrollment_token")
        if tok and callable(getattr(store, "check_enrollment_token", None)) \
                and store.check_enrollment_token(body.user_id, tok):
            enroll_mode = "one_time"
        elif tok and static and hmac.compare_digest(tok.encode(), str(static).encode()):
            enroll_mode = "static"
        elif tok:
            raise HTTPException(403, "invalid or expired enrollment token")
        elif sess.dev_mode(app) and not user_exists:
            enroll_mode = "dev"
        else:
            raise HTTPException(403, "enrollment is closed: open the one-time enrollment link from "
                                     "`asu enroll-link --user <id>` on the gateway host")

    display = (body.display_name or body.user_id)[:64]
    options = generate_registration_options(
        rp_id=sess.rp_id(app),
        rp_name=sess.rp_name(app),
        user_name=body.user_id,
        user_id=sess.user_handle(body.user_id),
        user_display_name=display,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=_uv_requirement(request),
        ),
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=_as_bytes(c["credential_id"])) for c in existing
        ],
        supported_pub_key_algs=SUPPORTED_ALGS,
    )
    try:
        sess.ceremonies(app).put(
            options.challenge, "register", user_id=body.user_id, display_name=display,
            enroll_mode=enroll_mode, enroll_token=body.enrollment_token if enroll_mode == "one_time" else None,
        )
    except OverflowError:
        raise HTTPException(429, "too many pending ceremonies")
    return _options_response(options)


@router.post("/register/verify", dependencies=[Depends(guard_post)])
def register_verify(body: CredentialIn, request: Request, response: Response):
    app = request.app
    store = _store(request)
    cd = _parse_client_data(body.credential)
    _check_not_cross_origin(cd)
    try:
        challenge = b64u_decode(cd.get("challenge", ""))
    except ValueError:
        raise HTTPException(400, "malformed challenge")
    cer = sess.ceremonies(app).pop(challenge, "register")
    if cer is None:
        raise HTTPException(400, "unknown or expired registration challenge")
    user_id = cer["user_id"]
    # Re-check the enrollment rules at verify time (race with another enrollment).
    if store.get_user(user_id) and store.get_credentials(user_id):
        if sess.current_user(request) != user_id:
            raise HTTPException(403, "sign in with an existing passkey to add another")
    elif cer.get("enroll_mode") == "dev":
        if not sess.dev_mode(app) or store.get_user(user_id) is not None:
            raise HTTPException(403, "enrollment is closed")
    elif cer.get("enroll_mode") not in ("one_time", "static"):
        raise HTTPException(403, "enrollment is closed")
    try:
        v = verify_registration_response(
            credential=body.credential,
            expected_challenge=challenge,
            expected_rp_id=sess.rp_id(app),
            expected_origin=sess.expected_origins(app),
            require_user_presence=True,
            require_user_verification=sess.require_uv(app),
            supported_pub_key_algs=SUPPORTED_ALGS,
        )
    except InvalidRegistrationResponse as e:
        raise HTTPException(400, f"registration failed: {e}")
    except Exception:
        raise HTTPException(400, "registration failed: malformed credential")

    if store.get_user(user_id) and _find_credential(store, user_id, v.credential_id):
        raise HTTPException(409, "credential already registered")
    if cer.get("enroll_mode") == "one_time" and not (store.get_user(user_id) and store.get_credentials(user_id)):
        # single use: consumed atomically only now that a valid credential exists
        if not store.consume_enrollment_token(user_id, cer.get("enroll_token")):
            raise HTTPException(403, "enrollment token already used or expired")
    transports: List[str] = []
    for t in (body.credential.get("response") or {}).get("transports") or []:
        if t in {x.value for x in AuthenticatorTransport}:
            transports.append(t)
    try:
        if store.get_user(user_id) is None:
            store.create_user(user_id, cer["display_name"])
        store.add_credential(user_id, v.credential_id, v.credential_public_key, v.sign_count, transports)
    except Exception:
        # duplicate credential id (any user) or concurrent enrollment race
        raise HTTPException(409, "could not store credential")
    sess.set_session_cookie(app, response, user_id)
    _audit(request, "authn.register", {"user_id": user_id, "credential_id": b64u_encode(v.credential_id)})
    return {"status": "registered", "user_id": user_id, "credential_id": b64u_encode(v.credential_id)}


# ----------------------------------------------------------------------------
# login (user presence on the authenticator page)
# ----------------------------------------------------------------------------
@router.post("/login/options", dependencies=[Depends(guard_post)])
def login_options(body: LoginOptionsIn, request: Request):
    app = request.app
    store = _store(request)
    creds = store.get_credentials(body.user_id) if _valid_user_id(body.user_id) and store.get_user(body.user_id) else []
    if not creds:
        # Do not reveal whether a user exists beyond what a passkey prompt would.
        raise HTTPException(404, "no passkey registered for this user")
    options = generate_authentication_options(
        rp_id=sess.rp_id(app),
        allow_credentials=[
            PublicKeyCredentialDescriptor(
                id=_as_bytes(c["credential_id"]),
                transports=[AuthenticatorTransport(t) for t in (c.get("transports") or []) if t in {x.value for x in AuthenticatorTransport}] or None,
            )
            for c in creds
        ],
        user_verification=_uv_requirement(request),
    )
    try:
        sess.ceremonies(app).put(options.challenge, "login", user_id=body.user_id)
    except OverflowError:
        raise HTTPException(429, "too many pending ceremonies")
    return _options_response(options)


def _verify_assertion(request: Request, user_id: str, credential: Dict[str, Any], challenge: bytes):
    """Verify a WebAuthn assertion by one of ``user_id``'s credentials.
    Returns (stored_credential, VerifiedAuthentication)."""
    store = _store(request)
    raw_id = _credential_raw_id(credential)
    cred = _find_credential(store, user_id, raw_id)
    if cred is None:
        raise HTTPException(400, "credential not registered to this user")
    _check_user_handle(credential, user_id)
    try:
        v = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=sess.rp_id(request.app),
            expected_origin=sess.expected_origins(request.app),
            credential_public_key=_as_bytes(cred["public_key"]),
            credential_current_sign_count=int(cred.get("sign_count") or 0),
            require_user_verification=sess.require_uv(request.app),
        )
    except InvalidAuthenticationResponse as e:
        raise HTTPException(400, f"assertion failed: {e}")
    except Exception:
        raise HTTPException(400, "assertion failed: malformed credential")
    return cred, v


@router.post("/login/verify", dependencies=[Depends(guard_post)])
def login_verify(body: CredentialIn, request: Request, response: Response):
    app = request.app
    cd = _parse_client_data(body.credential)
    _check_not_cross_origin(cd)
    try:
        challenge = b64u_decode(cd.get("challenge", ""))
    except ValueError:
        raise HTTPException(400, "malformed challenge")
    cer = sess.ceremonies(app).pop(challenge, "login")
    if cer is None:
        raise HTTPException(400, "unknown or expired login challenge")
    user_id = cer["user_id"]
    cred, v = _verify_assertion(request, user_id, body.credential, challenge)
    _cas_sign_count(_store(request), v.credential_id, v.new_sign_count)
    sess.set_session_cookie(app, response, user_id)
    _audit(request, "authn.login", {"user_id": user_id, "user_verified": v.user_verified})
    return {"status": "signed_in", "user_id": user_id, "user_verified": v.user_verified}


@router.post("/logout", dependencies=[Depends(guard_post)])
def logout(request: Request, response: Response):
    # CR-5: revoke the login server-side, not only in this browser
    sess.revoke_session_cookie(request.app, request.cookies.get(sess.SESSION_COOKIE))
    sess.clear_session_cookie(request.app, response)
    return {"status": "signed_out"}


@router.get("/me")
def me(request: Request):
    uid = require_user(request)
    return {"user_id": uid, "totp_mode": sess.approval_mode(request.app) == "totp"}


# ----------------------------------------------------------------------------
# approvals
# ----------------------------------------------------------------------------
def _approval_view(request: Request, ap: Dict[str, Any]) -> Dict[str, Any]:
    card = _render_card(request, ap)
    expl = ap.get("explanation")
    untrusted = card.pop("agent_explanation_untrusted", None)
    if isinstance(untrusted, dict) and untrusted.get("text") is not None:
        expl = untrusted["text"]
    if expl is not None:
        expl = str(expl)[:MAX_EXPLANATION_LEN]
    gr = ap.get("grant_request")
    return {
        "id": ap["id"],
        "status": ap.get("status"),
        "created_at": ap.get("created_at"),
        "expires_at": ap.get("expires_at"),
        "digest": ap.get("digest"),
        # The card is produced ONLY by the gateway's trusted renderer from the
        # descriptor; agent text is carried separately and labelled untrusted.
        "card": card,
        "explanation": expl,
        "grant_request": gr,
        "grant_digest": grant_digest(gr) if gr else None,
    }


@router.get("/pending")
def pending(request: Request):
    uid = require_user(request)
    out = []
    for ap in _store(request).list_pending(uid):
        if ap.get("user_id") != uid or ap.get("status") != "pending" or _expired(ap):
            continue
        try:
            out.append(_approval_view(request, ap))
        except HTTPException:
            # Never show an approvable card we could not render faithfully;
            # the user can still deny it.
            out.append({"id": ap["id"], "status": "pending", "error": "card unavailable",
                        "expires_at": ap.get("expires_at"), "card": None})
    return {"approvals": out}


@router.get("/approvals/{approval_id}")
def approval_detail(approval_id: str, request: Request):
    uid = require_user(request)
    ap = _load_user_approval(request, approval_id, uid)
    return _approval_view(request, ap)


@router.post("/approvals/{approval_id}/options", dependencies=[Depends(guard_post)])
def approval_options(approval_id: str, body: ApprovalOptionsIn, request: Request):
    uid = require_user(request)
    ap = _load_user_approval(request, approval_id, uid)
    _require_pending(ap)
    if body.grant and not ap.get("grant_request"):
        raise HTTPException(400, "no grant offered for this approval")
    creds = _store(request).get_credentials(uid)
    if not creds:
        raise HTTPException(400, "no passkey registered")
    if _mode(request, ap) == "unbound":
        # BASELINE `unbound` (P2/P5 deliberately violated): a fresh random
        # challenge proves user presence but does not cover the effect digest.
        challenge = secrets.token_bytes(32)
        try:
            sess.ceremonies(request.app).put(challenge, "unbound", approval_id=ap["id"], user_id=uid)
        except OverflowError:
            raise HTTPException(429, "too many pending ceremonies")
        body.grant = False
    else:
        try:
            challenge = approval_challenge(ap, with_grant=body.grant)
        except ValueError as e:
            raise HTTPException(500, f"cannot derive challenge: {e}")
    options = generate_authentication_options(
        rp_id=sess.rp_id(request.app),
        challenge=challenge,
        allow_credentials=[
            PublicKeyCredentialDescriptor(
                id=_as_bytes(c["credential_id"]),
                transports=[AuthenticatorTransport(t) for t in (c.get("transports") or []) if t in {x.value for x in AuthenticatorTransport}] or None,
            )
            for c in creds
        ],
        user_verification=_uv_requirement(request),
        timeout=120000,
    )
    return _options_response(options)


@router.post("/approvals/{approval_id}/verify", dependencies=[Depends(guard_post)])
def approval_verify(approval_id: str, body: ApprovalVerifyIn, request: Request):
    uid = require_user(request)
    store = _store(request)
    ap = _load_user_approval(request, approval_id, uid)
    _require_pending(ap)
    gr = ap.get("grant_request")
    if body.grant and not gr:
        raise HTTPException(400, "no grant offered for this approval")
    cd = _parse_client_data(body.credential)
    _check_not_cross_origin(cd)
    if _mode(request, ap) == "unbound":
        return _approval_verify_unbound(request, ap, uid, body, cd)
    challenge = approval_challenge(ap, with_grant=body.grant)
    cred, v = _verify_assertion(request, uid, body.credential, challenge)

    resp = body.credential["response"]
    pub = _as_bytes(cred["public_key"])
    ad_b64 = b64u_encode(b64u_decode(resp["authenticatorData"]))
    flags = authenticator_flags({"authenticator_data": ad_b64})
    receipt: Dict[str, Any] = {
        "v": RECEIPT_VERSION,
        "challenge": "ASU-APPROVAL-v2",
        "credential_id": b64u_encode(v.credential_id),
        "authenticator_data": ad_b64,
        "client_data_json": b64u_encode(b64u_decode(resp["clientDataJSON"])),
        "signature": b64u_encode(b64u_decode(resp["signature"])),
        "digest": ap["digest"],
        "approval_id": ap["id"],
        "nonce": ap["nonce"],
        "alg": alg_of_public_key(pub),
        "rp_id": sess.rp_id(request.app),
        "user_id": uid,
        "user_verified": bool(flags["uv"]),
        "flags": {k: flags[k] for k in ("up", "uv", "be", "bs")},
        "grant_digest": grant_digest(gr) if body.grant else None,
        "grant": gr if body.grant else None,
        "approved_at": int(time.time()),
    }
    # Defence in depth: the stored receipt must verify offline exactly as a
    # third party would verify it.
    if not verify_receipt(
        receipt,
        pub,
        ap["digest"],
        ap["id"],
        ap["nonce"],
        expected_origins=sess.expected_origins(request.app),
        expected_rp_id=sess.rp_id(request.app),
        expected_grant_digest=grant_digest(gr) if body.grant else None,
        require_user_verification=sess.require_uv(request.app),
    ):
        raise HTTPException(400, "receipt self-check failed")

    _cas_sign_count(store, v.credential_id, v.new_sign_count)
    grant = dict(gr) if body.grant else None
    if not store.mark_approved(ap["id"], receipt, grant):
        raise HTTPException(409, "approval is not pending")
    _audit(
        request,
        "authn.approve",
        {"approval_id": ap["id"], "digest": ap["digest"], "user_id": uid, "grant": bool(body.grant)},
    )
    return {"status": "approved", "approval_id": ap["id"], "receipt": receipt}


def _approval_verify_unbound(request: Request, ap: Dict[str, Any], uid: str, body: ApprovalVerifyIn, cd):
    """BASELINE `unbound`: passkey approval of the pending request that is NOT
    bound to its effect digest. The receipt is marked unverifiable."""
    try:
        challenge = b64u_decode(cd.get("challenge", ""))
    except ValueError:
        raise HTTPException(400, "malformed challenge")
    cer = sess.ceremonies(request.app).pop(challenge, "unbound")
    if cer is None or cer["approval_id"] != ap["id"] or cer["user_id"] != uid:
        raise HTTPException(400, "unknown or expired challenge")
    cred, v = _verify_assertion(request, uid, body.credential, challenge)
    store = _store(request)
    _cas_sign_count(store, v.credential_id, v.new_sign_count)
    receipt = {
        "mode": "unbound",
        "baseline": "unbound-insecure",
        "credential_id": b64u_encode(v.credential_id),
        "approval_id": ap["id"],
        "user_id": uid,
        "approved_at": int(time.time()),
        "verifiable": False,
    }
    if not store.mark_approved(ap["id"], receipt, None):
        raise HTTPException(409, "approval is not pending")
    _audit(request, "authn.approve_unbound", {"approval_id": ap["id"], "user_id": uid})
    return {"status": "approved", "approval_id": ap["id"], "baseline": "unbound-insecure"}


@router.post("/approvals/{approval_id}/deny", dependencies=[Depends(guard_post)])
def approval_deny(approval_id: str, request: Request):
    uid = require_user(request)
    ap = _load_user_approval(request, approval_id, uid)
    if ap.get("status") != "pending":
        raise HTTPException(409, "approval is not pending")
    if not _store(request).mark_denied(ap["id"]):
        raise HTTPException(409, "approval is not pending")
    _audit(request, "authn.deny", {"approval_id": ap["id"], "user_id": uid})
    return {"status": "denied", "approval_id": ap["id"]}


# ----------------------------------------------------------------------------
# TOTP — INSECURE BASELINE (SPEC section 4, --approval-mode totp)
#
# A TOTP code carries no binding to the effect digest (P2 fails), yields no
# third-party-verifiable receipt (P5 fails) and can be relayed by whoever is
# shown it, including the agent. It exists only for comparison experiments
# and is disabled unless the approval's mode (or config.approval_mode) is "totp".
# ----------------------------------------------------------------------------
_totp_lock = threading.Lock()


def _totp_state(app) -> Dict[str, Any]:
    with _totp_lock:
        st = getattr(app.state, "_asu_totp_state", None)
        if st is None:
            st = {"last_step": {}, "failures": {}}
            app.state._asu_totp_state = st
        return st


def _require_totp_mode(request: Request) -> None:
    if sess.approval_mode(request.app) != "totp":
        raise HTTPException(404, "TOTP baseline disabled")


@router.post("/totp/enroll", dependencies=[Depends(guard_post), Depends(_require_totp_mode)])
def totp_enroll(request: Request):
    """INSECURE BASELINE. Enroll a TOTP secret for the signed-in user."""
    import pyotp

    uid = require_user(request)
    secret = pyotp.random_base32()
    _store(request).set_totp_secret(uid, secret)
    uri = pyotp.TOTP(secret).provisioning_uri(name=uid, issuer_name=sess.rp_name(request.app))
    return {
        "baseline": "totp-insecure",
        "warning": "INSECURE BASELINE: TOTP codes are not bound to the action and can be relayed.",
        "secret": secret,
        "otpauth_uri": uri,
    }


@router.post("/totp/approvals/{approval_id}/verify")
def totp_verify(approval_id: str, body: TotpVerifyIn, request: Request):
    """INSECURE BASELINE. Approve with a TOTP code.

    Intentionally does not require the authenticator-page cookie: in this
    baseline possession of a current code is the whole approval, which is
    exactly why a relayed code works (modelled attack).
    """
    import pyotp

    store = _store(request)
    ap = store.get_approval(approval_id)
    if ap is None:
        raise HTTPException(404, "approval not found")
    if _mode(request, ap) != "totp":
        raise HTTPException(404, "TOTP baseline disabled")
    _require_pending(ap)
    secret = store.get_totp_secret(ap["user_id"])
    if not secret:
        raise HTTPException(400, "no TOTP enrolled")
    st = _totp_state(request.app)
    totp = pyotp.TOTP(secret)
    code = body.code.strip()
    now = time.time()
    matched_step = None
    if code.isdigit():
        for off in (-1, 0, 1):
            t = now + off * totp.interval
            if pyotp.utils.strings_equal(totp.at(t), code):
                matched_step = int(t // totp.interval)
                break
    with _totp_lock:
        if matched_step is None or matched_step <= st["last_step"].get(ap["user_id"], -1):
            n = st["failures"].get(approval_id, 0) + 1
            st["failures"][approval_id] = n
            locked = n >= TOTP_MAX_FAILURES
        else:
            locked = None
            use_step = getattr(store, "use_totp_step", None)
            if callable(use_step) and not use_step(ap["user_id"], matched_step):
                n = st["failures"].get(approval_id, 0) + 1
                st["failures"][approval_id] = n
                locked = n >= TOTP_MAX_FAILURES
            else:
                st["last_step"][ap["user_id"]] = matched_step
    if locked is not None:
        if locked:
            store.mark_denied(approval_id)
            raise HTTPException(403, "too many wrong codes; approval denied")
        raise HTTPException(400, "invalid or reused code")
    receipt = {
        "mode": "totp",
        "baseline": "totp-insecure",
        "approval_id": ap["id"],
        "digest": ap["digest"],
        "nonce": ap["nonce"],
        "totp_step": matched_step,
        "approved_at": int(now),
        "verifiable": False,
    }
    if not store.mark_approved(ap["id"], receipt, None):
        raise HTTPException(409, "approval is not pending")
    _audit(request, "authn.approve_totp", {"approval_id": ap["id"], "user_id": ap["user_id"]})
    return {"status": "approved", "approval_id": ap["id"], "baseline": "totp-insecure"}
