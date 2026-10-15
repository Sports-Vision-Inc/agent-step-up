"""Authenticator-page user session (signed cookie) and short-lived WebAuthn
ceremony state. The cookie authenticates the *human on the authenticator
page*; it is never given to the agent and never by itself approves an effect
(every approval needs a fresh passkey assertion over the approval challenge).
"""
from __future__ import annotations

import hashlib
import secrets
import threading
import time
from typing import Any, Dict, List, Optional

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

SESSION_COOKIE = "asu_authn"
_COOKIE_SALT = "asu-authn-session-v1"
DEFAULT_SESSION_TTL_S = 8 * 3600
DEFAULT_RP_ID = "localhost"
DEFAULT_RP_NAME = "Agent Step-Up"
DEFAULT_ORIGINS = ["http://localhost:8000"]


# ----------------------------------------------------------------------------
# config access (app.state.config; attributes per builder brief)
# ----------------------------------------------------------------------------
def _config(app) -> Any:
    return getattr(app.state, "config", None)


def cfg(app, name: str, default: Any = None) -> Any:
    """Read a config value: attribute first, then ``config.extra[name]``
    (the gateway's Config keeps unknown YAML keys in ``extra``)."""
    c = _config(app)
    if c is None:
        return default
    v = getattr(c, name, None)
    if v is None:
        extra = getattr(c, "extra", None)
        if isinstance(extra, dict):
            v = extra.get(name)
    return default if v is None else v


def rp_id(app) -> str:
    return cfg(app, "rp_id") or DEFAULT_RP_ID


def rp_name(app) -> str:
    return cfg(app, "rp_name") or DEFAULT_RP_NAME


def expected_origins(app) -> List[str]:
    """Single accessor (CR-10): the gateway Config's ``allowed_origins()``
    when available, so the authn routes and the gateway's receipt re-check
    always agree."""
    c = _config(app)
    fn = getattr(c, "allowed_origins", None)
    if callable(fn):
        return list(fn())
    o = cfg(app, "expected_origins") or cfg(app, "allowed_origins") or cfg(app, "origin")
    if not o:
        return list(DEFAULT_ORIGINS)
    if isinstance(o, str):
        return [o]
    return list(o)


def approval_mode(app) -> Optional[str]:
    return cfg(app, "approval_mode")


def require_uv(app) -> bool:
    """D-005 item 3: user verification is REQUIRED unless the deployment
    explicitly sets ``require_user_verification: false`` (UP-only opt-out)."""
    return bool(cfg(app, "require_user_verification", True))


def dev_mode(app) -> bool:
    return cfg(app, "dev_mode", False) is True


def session_ttl(app) -> int:
    v = cfg(app, "authn_session_ttl_s")
    return int(v) if v else DEFAULT_SESSION_TTL_S


def _secret(app) -> bytes:
    for name in ("cookie_secret", "session_secret", "secret_key"):
        v = cfg(app, name)
        if v:
            return v.encode() if isinstance(v, str) else bytes(v)
    with _INIT_LOCK:
        return _process_secret(app)


def _process_secret(app) -> bytes:
    s = getattr(app.state, "_asu_authn_secret", None)
    if s is None:
        # Per-process random secret: sessions do not survive a restart, which
        # is the safe default when no secret is configured.
        s = secrets.token_bytes(32)
        app.state._asu_authn_secret = s
    return s


def _serializer(app) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(_secret(app), salt=_COOKIE_SALT)


def _web_login_store(app):
    store = getattr(app.state, "store", None)
    if store is not None and callable(getattr(store, "create_web_login", None)) \
            and callable(getattr(store, "get_web_login", None)):
        return store
    return None


def make_session_cookie(app, user_id: str) -> str:
    """Cookie value for a passkey-authenticated authenticator-page user.

    If the gateway Store offers server-side web logins
    (``create_web_login``/``get_web_login``), the cookie is that opaque random
    token (stored hashed server-side, expiring there). Otherwise it is an
    itsdangerous-signed, timestamped payload.
    """
    st = _web_login_store(app)
    if st is not None:
        return "wl." + st.create_web_login(user_id, session_ttl(app))
    return "sg." + _serializer(app).dumps({"u": user_id, "sid": secrets.token_urlsafe(12)})


def _revoked_signed(app) -> set:
    with _INIT_LOCK:
        r = getattr(app.state, "_asu_authn_revoked", None)
        if r is None:
            r = set()
            app.state._asu_authn_revoked = r
        return r


def revoke_session_cookie(app, value: Optional[str]) -> None:
    """Server-side logout (CR-5): server-side logins are deleted from the
    Store; signed cookies are remembered as revoked until they expire."""
    if not value or len(value) > 4096:
        return
    kind, _, rest = value.partition(".")
    st = _web_login_store(app)
    if kind == "wl" and st is not None and callable(getattr(st, "revoke_web_login", None)):
        st.revoke_web_login(rest)
    elif kind == "sg":
        try:
            data = _serializer(app).loads(rest, max_age=session_ttl(app))
            if isinstance(data, dict) and isinstance(data.get("sid"), str):
                _revoked_signed(app).add(data["sid"])
        except (BadSignature, SignatureExpired):
            pass


def read_session_cookie(app, value: Optional[str]) -> Optional[str]:
    if not value or len(value) > 4096:
        return None
    kind, _, value = value.partition(".")
    st = _web_login_store(app)
    if kind == "wl":
        if st is None:
            return None
        uid = st.get_web_login(value)
        return uid if isinstance(uid, str) else None
    if kind != "sg" or st is not None:
        # When server-side logins are available, signed cookies are not accepted.
        return None
    try:
        data = _serializer(app).loads(value, max_age=session_ttl(app))
    except (BadSignature, SignatureExpired):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("u"), str):
        return None
    if data.get("sid") in _revoked_signed(app):
        return None
    return data["u"]


def current_user(request) -> Optional[str]:
    """User id of the human signed in on the authenticator page, or None.

    The gateway's ``POST /v1/sessions`` uses this to require a passkey-
    authenticated user before issuing an agent session token.
    """
    uid = read_session_cookie(request.app, request.cookies.get(SESSION_COOKIE))
    if uid is None:
        return None
    store = getattr(request.app.state, "store", None)
    if store is not None and store.get_user(uid) is None:
        return None
    return uid


def cookie_secure(app) -> bool:  # noqa: D401
    return all(o.startswith("https://") for o in expected_origins(app))


def set_session_cookie(app, response, user_id: str) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        make_session_cookie(app, user_id),
        max_age=session_ttl(app),
        httponly=True,
        samesite="strict",
        secure=cookie_secure(app),
        path="/",
    )


def clear_session_cookie(app, response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/", samesite="strict", secure=cookie_secure(app), httponly=True)


def user_handle(user_id: str) -> bytes:
    """Opaque, stable WebAuthn user.id (no PII in the handle)."""
    return hashlib.sha256(b"ASU-user-handle-v1" + user_id.encode("utf-8")).digest()


# ----------------------------------------------------------------------------
# ceremony state for registration / login (approval challenges are derived,
# not stored)
# ----------------------------------------------------------------------------
class CeremonyStore:
    """Single-use challenges for register/login ceremonies, keyed by challenge."""

    MAX_ENTRIES = 10000
    TTL_S = 300

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: Dict[bytes, Dict[str, Any]] = {}

    def put(self, challenge: bytes, kind: str, **data: Any) -> None:
        now = time.time()
        with self._lock:
            self._prune(now)
            if len(self._items) >= self.MAX_ENTRIES:
                raise OverflowError("too many pending ceremonies")
            self._items[challenge] = {"kind": kind, "exp": now + self.TTL_S, **data}

    def pop(self, challenge: bytes, kind: str) -> Optional[Dict[str, Any]]:
        now = time.time()
        with self._lock:
            item = self._items.pop(challenge, None)
        if item is None or item["kind"] != kind or item["exp"] < now:
            return None
        return item

    def _prune(self, now: float) -> None:
        dead = [k for k, v in self._items.items() if v["exp"] < now]
        for k in dead:
            del self._items[k]


_INIT_LOCK = threading.Lock()


def ceremonies(app) -> CeremonyStore:
    with _INIT_LOCK:
        cs = getattr(app.state, "_asu_authn_ceremonies", None)
        if cs is None:
            cs = CeremonyStore()
            app.state._asu_authn_ceremonies = cs
        return cs
