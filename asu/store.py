"""SQLite persistence (SPEC section 7 ``Store`` interface + gateway extras).

All state transitions are single conditional UPDATEs inside ``BEGIN
IMMEDIATE`` transactions, so ``mark_approved`` (pending->approved),
``mark_denied`` (pending->denied) and ``consume`` (approved->consumed) are
atomic even with concurrent callers or processes sharing the DB file.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from decimal import Decimal
from typing import Any, Dict, Iterator, List, Optional, Tuple

from . import jcs

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY, display_name TEXT NOT NULL, created_at INTEGER NOT NULL,
        totp_secret TEXT)""",
    """CREATE TABLE IF NOT EXISTS credentials (
        credential_id BLOB PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(user_id),
        public_key BLOB NOT NULL, sign_count INTEGER NOT NULL, transports TEXT NOT NULL,
        created_at INTEGER NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL, user_id TEXT NOT NULL,
        agent_id TEXT NOT NULL, scopes TEXT NOT NULL, created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL, run_approved INTEGER NOT NULL DEFAULT 0,
        revoked INTEGER NOT NULL DEFAULT 0)""",
    """CREATE TABLE IF NOT EXISTS web_logins (
        token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS approvals (
        id TEXT PRIMARY KEY, user_id TEXT NOT NULL, session_id TEXT NOT NULL, agent_id TEXT NOT NULL,
        tool TEXT NOT NULL, digest TEXT NOT NULL, effect_key TEXT NOT NULL, descriptor TEXT NOT NULL,
        raw_args TEXT NOT NULL, ctx TEXT NOT NULL, nonce TEXT NOT NULL, status TEXT NOT NULL,
        created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, decided_at INTEGER,
        consumed_at INTEGER, receipt TEXT, grant_request TEXT, grant_json TEXT, explanation TEXT,
        card TEXT, mode TEXT NOT NULL, reasons TEXT)""",
    "CREATE INDEX IF NOT EXISTS approvals_session ON approvals(session_id, status)",
    "CREATE INDEX IF NOT EXISTS approvals_user ON approvals(user_id, status)",
    """CREATE TABLE IF NOT EXISTS grants (
        id TEXT PRIMARY KEY, user_id TEXT NOT NULL, session_id TEXT NOT NULL, agent_id TEXT NOT NULL,
        approval_id TEXT NOT NULL, grant_json TEXT NOT NULL, digest TEXT NOT NULL, tool TEXT NOT NULL,
        target TEXT, uses INTEGER NOT NULL DEFAULT 0, max_uses INTEGER NOT NULL,
        not_after INTEGER NOT NULL, amount_used TEXT NOT NULL DEFAULT '0', created_at INTEGER NOT NULL,
        revoked INTEGER NOT NULL DEFAULT 0)""",
    """CREATE TABLE IF NOT EXISTS effects (
        id TEXT PRIMARY KEY, user_id TEXT NOT NULL, session_id TEXT NOT NULL, tool TEXT NOT NULL,
        effect_class TEXT NOT NULL, target TEXT, amount TEXT, currency TEXT, digest TEXT NOT NULL,
        approval_id TEXT, grant_id TEXT, via TEXT NOT NULL, executed_at INTEGER NOT NULL,
        descriptor TEXT NOT NULL, result TEXT)""",
    "CREATE INDEX IF NOT EXISTS effects_user_time ON effects(user_id, executed_at)",
    """CREATE TABLE IF NOT EXISTS known_recipients (
        user_id TEXT NOT NULL, recipient TEXT NOT NULL, first_seen INTEGER NOT NULL,
        PRIMARY KEY (user_id, recipient))""",
    """CREATE TABLE IF NOT EXISTS rate_events (
        session_id TEXT NOT NULL, ts REAL NOT NULL)""",
    "CREATE INDEX IF NOT EXISTS rate_events_s ON rate_events(session_id, ts)",
    """CREATE TABLE IF NOT EXISTS totp_used (
        user_id TEXT NOT NULL, step INTEGER NOT NULL, PRIMARY KEY (user_id, step))""",
    # one-time enrollment tokens delivered out of band (D-005 item 2)
    """CREATE TABLE IF NOT EXISTS enrollment_tokens (
        token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL, used_at INTEGER)""",
]


def _now() -> int:
    return int(time.time())


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _json_default(o: Any) -> Any:
    if isinstance(o, (bytes, bytearray)):
        return _b64u(bytes(o))
    if isinstance(o, Decimal):
        return str(o)
    raise TypeError(f"not JSON serializable: {type(o).__name__}")


def _dumps(o: Any) -> str:
    return json.dumps(o, sort_keys=True, default=_json_default)


def _loads(s: Optional[str]) -> Any:
    return None if s is None else json.loads(s)


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(18)}"


class Store:
    def __init__(self, path: str, audit_key: Optional[bytes] = None):
        self.path = path
        self.audit_key = audit_key
        self._lock = threading.RLock()
        self._depth = 0
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=30)
        self._conn.row_factory = sqlite3.Row
        if path != ":memory:":
            try:
                self._conn.execute("PRAGMA journal_mode=WAL")
            except sqlite3.DatabaseError:
                pass
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA busy_timeout=30000")
        with self.tx() as c:
            for stmt in SCHEMA:
                c.execute(stmt)
        from .audit import AuditLog

        self.audit = AuditLog(self, key=audit_key)

    # ------------------------------------------------------------------ infra
    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        """Re-entrant write transaction (BEGIN IMMEDIATE)."""
        with self._lock:
            outer = self._depth == 0
            if outer:
                self._conn.execute("BEGIN IMMEDIATE")
            self._depth += 1
            try:
                yield self._conn
            except BaseException:
                self._depth -= 1
                if outer:
                    self._conn.execute("ROLLBACK")
                raise
            else:
                self._depth -= 1
                if outer:
                    self._conn.execute("COMMIT")

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def log(self, event: str, data: Optional[Dict[str, Any]] = None) -> None:
        self.audit.append(event, data)

    # ---------------------------------------------------------- users / creds
    def create_user(self, user_id: str, display_name: str) -> None:
        with self.tx() as c:
            c.execute(
                "INSERT INTO users (user_id, display_name, created_at) VALUES (?,?,?)",
                (user_id, display_name, _now()),
            )
            self.log("user_created", {"user_id": user_id})

    def get_user(self, user_id: str) -> Optional[dict]:
        with self.tx() as c:
            r = c.execute("SELECT user_id, display_name, created_at FROM users WHERE user_id=?", (user_id,)).fetchone()
        return dict(r) if r else None

    def add_credential(self, user_id: str, credential_id: bytes, public_key: bytes, sign_count: int,
                       transports: List[str]) -> None:
        with self.tx() as c:
            c.execute(
                "INSERT INTO credentials (credential_id, user_id, public_key, sign_count, transports, created_at)"
                " VALUES (?,?,?,?,?,?)",
                (bytes(credential_id), user_id, bytes(public_key), int(sign_count), json.dumps(list(transports or [])),
                 _now()),
            )
            self.log("credential_added", {"user_id": user_id, "credential_id": _b64u(bytes(credential_id))})

    def get_credentials(self, user_id: str) -> List[dict]:
        with self.tx() as c:
            rows = c.execute(
                "SELECT credential_id, public_key, sign_count, transports FROM credentials WHERE user_id=?"
                " ORDER BY created_at", (user_id,)).fetchall()
        return [
            {"credential_id": bytes(r["credential_id"]), "public_key": bytes(r["public_key"]),
             "sign_count": r["sign_count"], "transports": json.loads(r["transports"])}
            for r in rows
        ]

    def get_credential(self, credential_id: bytes) -> Optional[dict]:
        with self.tx() as c:
            r = c.execute("SELECT credential_id, user_id, public_key, sign_count, transports FROM credentials"
                          " WHERE credential_id=?", (bytes(credential_id),)).fetchone()
        if not r:
            return None
        return {"credential_id": bytes(r["credential_id"]), "user_id": r["user_id"],
                "public_key": bytes(r["public_key"]), "sign_count": r["sign_count"],
                "transports": json.loads(r["transports"])}

    def update_sign_count(self, credential_id: bytes, sign_count: int) -> bool:
        """Compare-and-set (CR-9): the stored counter only moves forward. A
        new value that is not greater than the stored one is rejected (False),
        except 0 -> 0 for authenticators that do not implement a counter."""
        n = int(sign_count)
        with self.tx() as c:
            cur = c.execute("UPDATE credentials SET sign_count=? WHERE credential_id=? AND"
                            " (sign_count < ? OR (? = 0 AND sign_count = 0))",
                            (n, bytes(credential_id), n, n))
            ok = cur.rowcount == 1
            if not ok:
                self.log("sign_count_rejected", {"credential_id": _b64u(bytes(credential_id)), "sign_count": n})
        return ok

    def set_totp_secret(self, user_id: str, secret: str) -> None:
        with self.tx() as c:
            c.execute("UPDATE users SET totp_secret=? WHERE user_id=?", (secret, user_id))
            self.log("totp_secret_set", {"user_id": user_id})

    def get_totp_secret(self, user_id: str) -> Optional[str]:
        with self.tx() as c:
            r = c.execute("SELECT totp_secret FROM users WHERE user_id=?", (user_id,)).fetchone()
        return r[0] if r else None

    def use_totp_step(self, user_id: str, step: int) -> bool:
        """Record a TOTP time-step as used; False if it was already used (replay)."""
        with self.tx() as c:
            try:
                c.execute("INSERT INTO totp_used (user_id, step) VALUES (?,?)", (user_id, int(step)))
            except sqlite3.IntegrityError:
                return False
        return True

    # --------------------------------------------------------------- sessions
    def create_session(self, user_id: str, agent_id: str, scopes: Optional[List[str]] = None,
                       ttl_s: int = 3600) -> Tuple[str, dict]:
        token = "asu_st_" + secrets.token_urlsafe(32)
        sid = new_id("ses")
        now = _now()
        with self.tx() as c:
            c.execute(
                "INSERT INTO sessions (session_id, token_hash, user_id, agent_id, scopes, created_at, expires_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (sid, _hash_token(token), user_id, agent_id, json.dumps(scopes or ["*"]), now, now + int(ttl_s)),
            )
            self.log("session_created", {"session_id": sid, "user_id": user_id, "agent_id": agent_id,
                                         "scopes": scopes or ["*"], "expires_at": now + int(ttl_s)})
        return token, self.get_session(sid)  # type: ignore[return-value]

    def _session_row(self, r: sqlite3.Row) -> dict:
        d = dict(r)
        d["scopes"] = json.loads(d["scopes"])
        d.pop("token_hash", None)
        return d

    def get_session(self, session_id: str) -> Optional[dict]:
        with self.tx() as c:
            r = c.execute("SELECT * FROM sessions WHERE session_id=?", (session_id,)).fetchone()
        return self._session_row(r) if r else None

    def get_session_by_token(self, token: str) -> Optional[dict]:
        if not isinstance(token, str) or not token:
            return None
        th = _hash_token(token)
        with self.tx() as c:
            r = c.execute("SELECT * FROM sessions WHERE token_hash=?", (th,)).fetchone()
        if not r or not hmac.compare_digest(r["token_hash"], th):
            return None
        if r["revoked"] or r["expires_at"] <= _now():
            return None
        return self._session_row(r)

    def set_session_run_approved(self, session_id: str) -> None:
        with self.tx() as c:
            c.execute("UPDATE sessions SET run_approved=1 WHERE session_id=?", (session_id,))

    def revoke_session(self, session_id: str) -> None:
        with self.tx() as c:
            c.execute("UPDATE sessions SET revoked=1 WHERE session_id=?", (session_id,))
            self.log("session_revoked", {"session_id": session_id})

    # user-authenticated browser logins (authenticator page cookie)
    def create_web_login(self, user_id: str, ttl_s: int = 3600) -> str:
        token = secrets.token_urlsafe(32)
        now = _now()
        with self.tx() as c:
            c.execute("INSERT INTO web_logins (token_hash, user_id, created_at, expires_at) VALUES (?,?,?,?)",
                      (_hash_token(token), user_id, now, now + int(ttl_s)))
            self.log("web_login", {"user_id": user_id})
        return token

    def revoke_web_login(self, token: Optional[str]) -> bool:
        """Server-side logout (CR-5): the cookie value stops authenticating."""
        if not token:
            return False
        with self.tx() as c:
            r = c.execute("SELECT user_id FROM web_logins WHERE token_hash=?", (_hash_token(token),)).fetchone()
            cur = c.execute("DELETE FROM web_logins WHERE token_hash=?", (_hash_token(token),))
            ok = cur.rowcount == 1
            if ok:
                self.log("web_logout", {"user_id": r["user_id"] if r else None})
        return ok

    # one-time enrollment tokens (D-005 item 2)
    def create_enrollment_token(self, user_id: str, ttl_s: int = 900) -> str:
        token = "asu_en_" + secrets.token_urlsafe(24)
        now = _now()
        with self.tx() as c:
            c.execute("INSERT INTO enrollment_tokens (token_hash, user_id, created_at, expires_at) VALUES (?,?,?,?)",
                      (_hash_token(token), user_id, now, now + int(ttl_s)))
            self.log("enrollment_token_issued", {"user_id": user_id, "expires_at": now + int(ttl_s)})
        return token

    def check_enrollment_token(self, user_id: str, token: Optional[str]) -> bool:
        if not isinstance(token, str) or not token:
            return False
        with self.tx() as c:
            r = c.execute("SELECT user_id, expires_at, used_at FROM enrollment_tokens WHERE token_hash=?",
                          (_hash_token(token),)).fetchone()
        return bool(r and r["used_at"] is None and r["expires_at"] > _now()
                    and hmac.compare_digest(r["user_id"].encode(), user_id.encode()))

    def consume_enrollment_token(self, user_id: str, token: Optional[str]) -> bool:
        """Atomically mark a valid, unexpired, unused token for ``user_id`` used."""
        if not isinstance(token, str) or not token:
            return False
        now = _now()
        with self.tx() as c:
            cur = c.execute("UPDATE enrollment_tokens SET used_at=? WHERE token_hash=? AND user_id=? AND"
                            " used_at IS NULL AND expires_at>?", (now, _hash_token(token), user_id, now))
            ok = cur.rowcount == 1
            if ok:
                self.log("enrollment_token_used", {"user_id": user_id})
        return ok

    def get_web_login(self, token: Optional[str]) -> Optional[str]:
        if not token:
            return None
        with self.tx() as c:
            r = c.execute("SELECT user_id, expires_at FROM web_logins WHERE token_hash=?",
                          (_hash_token(token),)).fetchone()
        if not r or r["expires_at"] <= _now():
            return None
        return r["user_id"]

    # -------------------------------------------------------------- approvals
    def create_approval(self, *, user_id: str, session_id: str, agent_id: str, descriptor: dict, digest: str,
                        effect_key: str, raw_args: Any, ctx: dict, mode: str, card: dict,
                        explanation: Optional[str], grant_request: Optional[dict], reasons: List[str]) -> dict:
        aid = new_id("apr")
        nonce = secrets.token_urlsafe(24)
        with self.tx() as c:
            c.execute(
                "INSERT INTO approvals (id, user_id, session_id, agent_id, tool, digest, effect_key, descriptor,"
                " raw_args, ctx, nonce, status, created_at, expires_at, grant_request, explanation, card, mode,"
                " reasons) VALUES (?,?,?,?,?,?,?,?,?,?,?, 'pending', ?,?,?,?,?,?,?)",
                (aid, user_id, session_id, agent_id, descriptor["tool"], digest, effect_key, _dumps(descriptor),
                 _dumps(raw_args), _dumps(ctx), nonce, int(descriptor["issued_at"]), int(descriptor["expires_at"]),
                 _dumps(grant_request) if grant_request is not None else None, explanation, _dumps(card), mode,
                 _dumps(reasons)),
            )
            self.log("approval_created", {"approval_id": aid, "session_id": session_id, "digest": digest,
                                          "mode": mode, "reasons": reasons,
                                          "grant_request": grant_request is not None})
        return self.get_approval(aid)  # type: ignore[return-value]

    def _approval_row(self, r: sqlite3.Row) -> dict:
        status = r["status"]
        if status in ("pending", "approved") and r["expires_at"] <= _now():
            status = "expired"
        return {
            "id": r["id"], "user_id": r["user_id"], "session_id": r["session_id"], "agent_id": r["agent_id"],
            "tool": r["tool"], "digest": r["digest"], "effect_key": r["effect_key"],
            "descriptor": json.loads(r["descriptor"]), "raw_args": json.loads(r["raw_args"]),
            "ctx": json.loads(r["ctx"]), "nonce": r["nonce"], "status": status,
            "created_at": r["created_at"], "expires_at": r["expires_at"], "decided_at": r["decided_at"],
            "consumed_at": r["consumed_at"], "receipt": _loads(r["receipt"]),
            "grant_request": _loads(r["grant_request"]), "grant": _loads(r["grant_json"]),
            "explanation": r["explanation"], "card": _loads(r["card"]), "mode": r["mode"],
            "reasons": _loads(r["reasons"]) or [],
        }

    def get_approval(self, approval_id: str) -> Optional[dict]:
        with self.tx() as c:
            r = c.execute("SELECT * FROM approvals WHERE id=?", (approval_id,)).fetchone()
        return self._approval_row(r) if r else None

    def list_pending(self, user_id: str) -> List[dict]:
        with self.tx() as c:
            rows = c.execute("SELECT * FROM approvals WHERE user_id=? AND status='pending' AND expires_at>?"
                             " ORDER BY created_at", (user_id, _now())).fetchall()
        return [self._approval_row(r) for r in rows]

    def find_pending_by_effect(self, session_id: str, effect_key: str) -> Optional[dict]:
        with self.tx() as c:
            r = c.execute("SELECT * FROM approvals WHERE session_id=? AND effect_key=? AND status='pending'"
                          " AND expires_at>? ORDER BY created_at LIMIT 1", (session_id, effect_key, _now())).fetchone()
        return self._approval_row(r) if r else None

    def count_pending(self, session_id: str) -> int:
        with self.tx() as c:
            return c.execute("SELECT COUNT(*) FROM approvals WHERE session_id=? AND status='pending' AND expires_at>?",
                             (session_id, _now())).fetchone()[0]

    def count_pending_user(self, user_id: str) -> int:
        with self.tx() as c:
            return c.execute("SELECT COUNT(*) FROM approvals WHERE user_id=? AND status='pending' AND expires_at>?",
                             (user_id, _now())).fetchone()[0]

    def count_denied_user(self, user_id: str, since: int) -> int:
        with self.tx() as c:
            return c.execute("SELECT COUNT(*) FROM approvals WHERE user_id=? AND status='denied' AND decided_at>=?",
                             (user_id, int(since))).fetchone()[0]

    def count_denied(self, session_id: str) -> int:
        with self.tx() as c:
            return c.execute("SELECT COUNT(*) FROM approvals WHERE session_id=? AND status='denied'",
                             (session_id,)).fetchone()[0]

    def mark_approved(self, approval_id: str, receipt: dict, grant: Optional[dict] = None) -> bool:
        """pending -> approved (only if unexpired). If ``grant`` is given it must
        be exactly the approval's ``grant_request`` (same JCS digest) — the
        constraints the user signed — otherwise nothing changes and False is
        returned. Receipt fields that name a digest/approval/nonce must match."""
        if not isinstance(receipt, dict):
            return False
        with self.tx() as c:
            r = c.execute("SELECT * FROM approvals WHERE id=?", (approval_id,)).fetchone()
            if not r or r["status"] != "pending" or r["expires_at"] <= _now():
                return False
            if "digest" in receipt and str(receipt["digest"]).lower() != r["digest"]:
                return False
            if "approval_id" in receipt and receipt["approval_id"] != approval_id:
                return False
            if "nonce" in receipt and receipt["nonce"] != r["nonce"]:
                return False
            grant_digest = None
            if grant is not None:
                gr = _loads(r["grant_request"])
                if gr is None:
                    return False
                try:
                    grant_digest = hashlib.sha256(jcs.canonicalize(grant)).hexdigest()
                    want = hashlib.sha256(jcs.canonicalize(gr)).hexdigest()
                except Exception:
                    return False
                if not hmac.compare_digest(grant_digest, want):
                    return False
                if "grant_digest" in receipt and str(receipt["grant_digest"]).lower() != want:
                    return False
            now = _now()
            cur = c.execute(
                "UPDATE approvals SET status='approved', receipt=?, grant_json=?, decided_at=?"
                " WHERE id=? AND status='pending' AND expires_at>?",
                (_dumps(receipt), _dumps(grant) if grant is not None else None, now, approval_id, now),
            )
            if cur.rowcount != 1:
                return False
            if grant is not None:
                gid = new_id("grt")
                c.execute(
                    "INSERT INTO grants (id, user_id, session_id, agent_id, approval_id, grant_json, digest, tool,"
                    " target, max_uses, not_after, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (gid, r["user_id"], r["session_id"], r["agent_id"], approval_id, _dumps(grant), grant_digest,
                     grant.get("tool"), grant.get("target"), int(grant.get("max_uses", 0)),
                     int(grant.get("not_after", 0)), now),
                )
            receipt_hash = hashlib.sha256(_dumps(receipt).encode()).hexdigest()
            self.log("approval_approved", {"approval_id": approval_id, "digest": r["digest"],
                                           "receipt_sha256": receipt_hash, "grant_digest": grant_digest})
        return True

    def mark_denied(self, approval_id: str) -> bool:
        with self.tx() as c:
            now = _now()
            cur = c.execute("UPDATE approvals SET status='denied', decided_at=? WHERE id=? AND status='pending'",
                            (now, approval_id))
            ok = cur.rowcount == 1
            if ok:
                self.log("approval_denied", {"approval_id": approval_id})
        return ok

    def consume(self, approval_id: str) -> bool:
        with self.tx() as c:
            now = _now()
            cur = c.execute("UPDATE approvals SET status='consumed', consumed_at=? WHERE id=? AND status='approved'"
                            " AND expires_at>?", (now, approval_id, now))
            ok = cur.rowcount == 1
            if ok:
                self.log("approval_consumed", {"approval_id": approval_id})
        return ok

    # ----------------------------------------------------------------- grants
    def active_grants(self, session_id: str, tool: str) -> List[dict]:
        with self.tx() as c:
            rows = c.execute("SELECT * FROM grants WHERE session_id=? AND tool=? AND revoked=0 AND not_after>?"
                             " AND uses<max_uses ORDER BY created_at", (session_id, tool, _now())).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["grant"] = json.loads(d.pop("grant_json"))
            out.append(d)
        return out

    def get_grant(self, grant_id: str) -> Optional[dict]:
        with self.tx() as c:
            r = c.execute("SELECT * FROM grants WHERE id=?", (grant_id,)).fetchone()
        if not r:
            return None
        d = dict(r)
        d["grant"] = json.loads(d.pop("grant_json"))
        return d

    def revoke_grant(self, grant_id: str) -> None:
        with self.tx() as c:
            c.execute("UPDATE grants SET revoked=1 WHERE id=?", (grant_id,))
            self.log("grant_revoked", {"grant_id": grant_id})

    # ---------------------------------------------------------------- effects
    def record_effect(self, *, user_id: str, session_id: str, descriptor: dict, digest: str, via: str,
                      approval_id: Optional[str] = None, grant_id: Optional[str] = None,
                      amount: Optional[str] = None, currency: Optional[str] = None,
                      recipients: Optional[List[str]] = None, result: Any = None) -> str:
        eid = new_id("eff")
        now = _now()
        with self.tx() as c:
            c.execute(
                "INSERT INTO effects (id, user_id, session_id, tool, effect_class, target, amount, currency, digest,"
                " approval_id, grant_id, via, executed_at, descriptor, result) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (eid, user_id, session_id, descriptor["tool"], descriptor["effect_class"], descriptor.get("target"),
                 amount, currency, digest, approval_id, grant_id, via, now, _dumps(descriptor), _dumps(result)),
            )
            for rcp in recipients or []:
                c.execute("INSERT OR IGNORE INTO known_recipients (user_id, recipient, first_seen) VALUES (?,?,?)",
                          (user_id, rcp, now))
            self.log("effect_executed", {"effect_id": eid, "session_id": session_id, "digest": digest, "via": via,
                                         "approval_id": approval_id, "grant_id": grant_id,
                                         "tool": descriptor["tool"], "target": descriptor.get("target")})
        return eid

    def get_effect(self, effect_id: str) -> Optional[dict]:
        with self.tx() as c:
            r = c.execute("SELECT * FROM effects WHERE id=?", (effect_id,)).fetchone()
        if not r:
            return None
        d = dict(r)
        d["descriptor"] = json.loads(d["descriptor"])
        d["result"] = _loads(d["result"])
        return d

    def recent_effects(self, user_id: str, since: int) -> List[dict]:
        with self.tx() as c:
            rows = c.execute("SELECT id, session_id, tool, effect_class, target, amount, currency, executed_at"
                             " FROM effects WHERE user_id=? AND executed_at>=? ORDER BY executed_at",
                             (user_id, int(since))).fetchall()
        return [dict(r) for r in rows]

    def is_known_recipient(self, user_id: str, recipient: str) -> bool:
        with self.tx() as c:
            return c.execute("SELECT 1 FROM known_recipients WHERE user_id=? AND recipient=?",
                             (user_id, recipient)).fetchone() is not None

    def add_known_recipient(self, user_id: str, recipient: str) -> None:
        with self.tx() as c:
            c.execute("INSERT OR IGNORE INTO known_recipients (user_id, recipient, first_seen) VALUES (?,?,?)",
                      (user_id, recipient, _now()))

    # ------------------------------------------------------------ rate events
    def add_rate_event(self, session_id: str, ts: Optional[float] = None) -> None:
        with self.tx() as c:
            c.execute("INSERT INTO rate_events (session_id, ts) VALUES (?,?)", (session_id, ts or time.time()))

    def count_rate_events(self, session_id: str, since: float) -> int:
        with self.tx() as c:
            c.execute("DELETE FROM rate_events WHERE ts < ?", (time.time() - 3600,))
            return c.execute("SELECT COUNT(*) FROM rate_events WHERE session_id=? AND ts>=?",
                             (session_id, since)).fetchone()[0]
