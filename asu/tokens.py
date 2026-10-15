"""Ed25519 authorization tokens for the ``token`` executor (SPEC section 10).

Format: ``asu1.<b64url(JCS(payload))>.<b64url(Ed25519(sig))>`` where the
signature covers the ASCII bytes ``asu1.<payload-b64>``. Payload:
``{h, aud, exp, iat, jti, iss}``. ``verify_token`` checks signature, digest,
audience (one audience PER RESOURCE: the gateway issues ``aud`` from the
tool's ``audience`` in the policy, default ``<token_audience>:<tool>``),
issuer, issued-at and expiry, then consumes the jti in a single-use store
(P3 at R). Use ``SqliteJtiStore`` at the resource: it survives restarts and
can be shared by replicas on one host (CR-8); ``JtiCache`` is in-memory only.
"""
from __future__ import annotations

import base64
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from typing import Any, Dict, Optional, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import jcs

PREFIX = "asu1"


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64u_dec(s: str) -> bytes:
    if not isinstance(s, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", s):
        raise ValueError("bad base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class JtiCache:
    """Thread-safe single-use cache of token ids, kept until token expiry."""

    def __init__(self) -> None:
        self._seen: Dict[str, int] = {}
        self._lock = threading.Lock()

    def use(self, jti: str, exp: int, now: Optional[int] = None) -> bool:
        now = int(now if now is not None else time.time())
        with self._lock:
            for k in [k for k, e in self._seen.items() if e < now - 60]:
                del self._seen[k]
            if jti in self._seen:
                return False
            self._seen[jti] = int(exp)
            return True

    def __contains__(self, jti: str) -> bool:
        with self._lock:
            return jti in self._seen


class SqliteJtiStore:
    """Persistent single-use jti store (sqlite, WAL). ``use`` is an atomic
    INSERT, so two processes sharing the file can never both accept a jti."""

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=30)
        if path != ":memory:":
            try:
                self._conn.execute("PRAGMA journal_mode=WAL")
            except sqlite3.DatabaseError:
                pass
        self._conn.execute("PRAGMA busy_timeout=30000")
        self._conn.execute("CREATE TABLE IF NOT EXISTS used_jti (jti TEXT PRIMARY KEY, exp INTEGER NOT NULL)")

    def use(self, jti: str, exp: int, now: Optional[int] = None) -> bool:
        now = int(now if now is not None else time.time())
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                self._conn.execute("DELETE FROM used_jti WHERE exp < ?", (now - 60,))
                self._conn.execute("INSERT INTO used_jti (jti, exp) VALUES (?,?)", (jti, int(exp)))
                self._conn.execute("COMMIT")
                return True
            except sqlite3.IntegrityError:
                self._conn.execute("ROLLBACK")
                return False
            except Exception:
                try:
                    self._conn.execute("ROLLBACK")
                except Exception:
                    pass
                raise

    def __contains__(self, jti: str) -> bool:
        with self._lock:
            return self._conn.execute("SELECT 1 FROM used_jti WHERE jti=?", (jti,)).fetchone() is not None

    def close(self) -> None:
        with self._lock:
            self._conn.close()


DEFAULT_JTI_CACHE = JtiCache()
DEFAULT_ISSUER = "asu-gateway"
MAX_CLOCK_SKEW_S = 60
MAX_TOKEN_LIFETIME_S = 3600


def generate_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def load_or_create_key(path: str) -> Ed25519PrivateKey:
    if os.path.exists(path):
        with open(path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("token key is not Ed25519")
        return key
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    return key


def public_key_bytes(key: Union[Ed25519PrivateKey, Ed25519PublicKey]) -> bytes:
    pub = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _load_public(public_key: Any) -> Ed25519PublicKey:
    if isinstance(public_key, Ed25519PublicKey):
        return public_key
    if isinstance(public_key, Ed25519PrivateKey):
        return public_key.public_key()
    if isinstance(public_key, str):
        public_key = public_key.encode()
    if isinstance(public_key, (bytes, bytearray)):
        b = bytes(public_key)
        if len(b) == 32:
            return Ed25519PublicKey.from_public_bytes(b)
        if b.startswith(b"-----BEGIN"):
            k = serialization.load_pem_public_key(b)
        else:
            k = serialization.load_der_public_key(b)
        if isinstance(k, Ed25519PublicKey):
            return k
    raise ValueError("unsupported public key")


def issue_token(private_key: Ed25519PrivateKey, digest: str, aud: str, ttl_s: int = 60,
                iss: str = DEFAULT_ISSUER, now: Optional[int] = None) -> str:
    now = int(now if now is not None else time.time())
    payload = {"h": digest, "aud": aud, "iat": now, "exp": now + int(ttl_s), "jti": secrets.token_urlsafe(16),
               "iss": iss}
    p64 = _b64u(jcs.canonicalize(payload))
    signing_input = f"{PREFIX}.{p64}".encode("ascii")
    sig = private_key.sign(signing_input)
    return f"{PREFIX}.{p64}.{_b64u(sig)}"


def decode_token(token: str) -> Dict[str, Any]:
    """Decode WITHOUT verifying (for inspection only)."""
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != PREFIX:
        raise ValueError("malformed token")
    return json.loads(_b64u_dec(parts[1]))


def verify_token(token: str, public_key: Any, expected_digest: str, aud: str,
                 jti_cache: Any = None, now: Optional[int] = None,
                 expected_iss: Optional[str] = DEFAULT_ISSUER) -> bool:
    """True iff the token is validly signed, for this digest and audience,
    from the expected issuer, issued not in the future and unexpired (with a
    bounded lifetime), and its jti has not been used before (it is then
    consumed in ``jti_cache``: a ``SqliteJtiStore`` for a persistent store,
    default an in-process ``JtiCache``)."""
    try:
        if not isinstance(token, str):
            return False
        parts = token.split(".")
        if len(parts) != 3 or parts[0] != PREFIX:
            return False
        pub = _load_public(public_key)
        sig = _b64u_dec(parts[2])
        pub.verify(sig, f"{PREFIX}.{parts[1]}".encode("ascii"))
        payload = json.loads(_b64u_dec(parts[1]))
        if not isinstance(payload, dict):
            return False
        now = int(now if now is not None else time.time())
        if not hmac.compare_digest(str(payload.get("h", "")), str(expected_digest).lower()):
            return False
        if not isinstance(aud, str) or payload.get("aud") != aud:
            return False
        if expected_iss is not None and payload.get("iss") != expected_iss:
            return False
        exp = payload.get("exp")
        if not isinstance(exp, int) or isinstance(exp, bool) or now >= exp:
            return False
        iat = payload.get("iat")
        if not isinstance(iat, int) or isinstance(iat, bool) or iat > now + MAX_CLOCK_SKEW_S:
            return False
        if exp - iat > MAX_TOKEN_LIFETIME_S:
            return False
        jti = payload.get("jti")
        if not isinstance(jti, str) or not jti:
            return False
        cache = jti_cache if jti_cache is not None else DEFAULT_JTI_CACHE
        return cache.use(jti, exp, now)
    except (InvalidSignature, ValueError, TypeError, json.JSONDecodeError):
        return False
