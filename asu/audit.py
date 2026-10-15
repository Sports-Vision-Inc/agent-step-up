"""SHA-256 hash-chained audit log (SPEC section 4 step 9).

Each entry ``e_i = {seq, ts, event, data, prev}`` is stored with
``hash_i = SHA-256(JCS(e_i))`` and ``prev = hash_{i-1}`` (genesis prev is 64
zeros). ``verify_chain`` recomputes every hash and link. Truncation of the tail
is only detectable against an externally anchored head (``head()``); see
docs/notes/gateway.md.

Keyed chain (CR-12 / RT-10): when the store is opened with an audit key (the
gateway always passes one, kept in a 0600 file next to the database), every
entry also carries ``mac = HMAC-SHA256(key, hash)``. Rewriting and rehashing
the chain then requires the key, and ``verify_*(..., key=...)`` reports any
entry whose MAC is missing or wrong. Anyone holding the key (the gateway host)
can still rewrite it; an externally anchored head remains the stronger check.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import jcs

GENESIS = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
    seq INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    event TEXT NOT NULL,
    data TEXT NOT NULL,
    prev TEXT NOT NULL,
    hash TEXT NOT NULL
);
"""


def _jsonable(obj: Any) -> Any:
    """Make data JCS-safe: bytes -> hex, floats kept, unknown -> str."""
    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(v) for v in obj]
    if isinstance(obj, (bytes, bytearray)):
        return bytes(obj).hex()
    if obj is None or isinstance(obj, (bool, str)):
        return obj
    if isinstance(obj, int):
        return obj if abs(obj) <= jcs.MAX_SAFE_INT else str(obj)
    if isinstance(obj, float):
        return obj if obj == obj and obj not in (float("inf"), float("-inf")) else str(obj)
    return str(obj)


def entry_hash(seq: int, ts: int, event: str, data: Any, prev: str) -> str:
    body = {"seq": seq, "ts": ts, "event": event, "data": data, "prev": prev}
    return hashlib.sha256(jcs.canonicalize(body)).hexdigest()


def entry_mac(key: bytes, h: str) -> str:
    return hmac.new(key, b"ASU-AUDIT-v1" + bytes.fromhex(h), hashlib.sha256).hexdigest()


def load_or_create_audit_key(path: str) -> bytes:
    """32-byte random key in a 0600 file (created with O_EXCL)."""
    if os.path.exists(path):
        with open(path, "rb") as f:
            k = f.read().strip()
        try:
            key = bytes.fromhex(k.decode("ascii"))
        except Exception:
            raise ValueError(f"audit key file {path} is not hex")
        if len(key) < 32:
            raise ValueError("audit key too short")
        return key
    import secrets

    key = secrets.token_bytes(32)
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:  # concurrent creation
        return load_or_create_audit_key(path)
    with os.fdopen(fd, "wb") as f:
        f.write(key.hex().encode("ascii"))
    return key


class AuditLog:
    """Audit log living in the Store's sqlite database. All appends happen
    inside the store's transaction lock so the chain is linear."""

    def __init__(self, store: Any, key: Optional[bytes] = None):
        self.store = store
        self.key = key
        with store.tx() as c:
            c.execute(SCHEMA)
            cols = [r[1] for r in c.execute("PRAGMA table_info(audit)").fetchall()]
            if "mac" not in cols:
                c.execute("ALTER TABLE audit ADD COLUMN mac TEXT")

    def append(self, event: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        data = _jsonable(data or {})
        with self.store.tx() as c:
            row = c.execute("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            seq = (row[0] + 1) if row else 1
            prev = row[1] if row else GENESIS
            ts = int(time.time() * 1000)
            h = entry_hash(seq, ts, event, data, prev)
            mac = entry_mac(self.key, h) if self.key else None
            c.execute(
                "INSERT INTO audit (seq, ts, event, data, prev, hash, mac) VALUES (?,?,?,?,?,?,?)",
                (seq, ts, event, jcs.canonicalize(data).decode("utf-8"), prev, h, mac),
            )
        out = {"seq": seq, "ts": ts, "event": event, "data": data, "prev": prev, "hash": h}
        if mac:
            out["mac"] = mac
        return out

    def entries(self) -> List[Dict[str, Any]]:
        with self.store.tx() as c:
            rows = c.execute("SELECT seq, ts, event, data, prev, hash, mac FROM audit ORDER BY seq").fetchall()
        out = []
        for r in rows:
            e = {"seq": r[0], "ts": r[1], "event": r[2], "data": json.loads(r[3]), "prev": r[4], "hash": r[5]}
            if r[6]:
                e["mac"] = r[6]
            out.append(e)
        return out

    def head(self) -> Tuple[int, str]:
        with self.store.tx() as c:
            row = c.execute("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        return (row[0], row[1]) if row else (0, GENESIS)

    def verify(self, expected_head: Optional[str] = None) -> Tuple[bool, Optional[int], str]:
        return verify_entries(self.entries(), expected_head, self.key)

    def export_jsonl(self, path: str) -> int:
        es = self.entries()
        with open(path, "w", encoding="utf-8") as f:
            for e in es:
                f.write(json.dumps(e, sort_keys=True) + "\n")
        return len(es)


def verify_entries(entries: Iterable[Dict[str, Any]], expected_head: Optional[str] = None,
                   key: Optional[bytes] = None) -> Tuple[bool, Optional[int], str]:
    """Return (ok, first_bad_seq, message). With ``key`` every entry must carry
    a valid HMAC (detects a rewrite by anyone without the key)."""
    prev = GENESIS
    expected_seq = 1
    last_hash = GENESIS
    for e in entries:
        seq = e.get("seq")
        if seq != expected_seq:
            return False, seq, f"sequence gap: expected {expected_seq}, got {seq}"
        if e.get("prev") != prev:
            return False, seq, "prev link does not match previous entry hash"
        try:
            h = entry_hash(seq, e["ts"], e["event"], e["data"], e["prev"])
        except Exception as ex:  # malformed entry
            return False, seq, f"malformed entry: {ex}"
        if h != e.get("hash"):
            return False, seq, "entry hash mismatch (content modified)"
        if key is not None and not hmac.compare_digest(str(e.get("mac") or ""), entry_mac(key, h)):
            return False, seq, "entry MAC missing or wrong (chain rewritten without the audit key)"
        prev = h
        last_hash = h
        expected_seq += 1
    if expected_head is not None and expected_head != last_hash:
        return False, expected_seq, "chain head differs from anchored head (truncated or rewritten)"
    return True, None, f"ok ({expected_seq - 1} entries)"


def verify_db(path: str, expected_head: Optional[str] = None, key: Optional[bytes] = None
              ) -> Tuple[bool, Optional[int], str]:
    conn = sqlite3.connect(path)
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info(audit)").fetchall()]
        sel = "SELECT seq, ts, event, data, prev, hash" + (", mac" if "mac" in cols else ", NULL") + \
            " FROM audit ORDER BY seq"
        rows = conn.execute(sel).fetchall()
    finally:
        conn.close()
    es = []
    for r in rows:
        try:
            data = json.loads(r[3])
        except Exception:
            return False, r[0], "audit data is not valid JSON"
        es.append({"seq": r[0], "ts": r[1], "event": r[2], "data": data, "prev": r[4], "hash": r[5], "mac": r[6]})
    return verify_entries(es, expected_head, key)


def verify_jsonl(path: str, expected_head: Optional[str] = None, key: Optional[bytes] = None
                 ) -> Tuple[bool, Optional[int], str]:
    with open(path, "r", encoding="utf-8") as f:
        es = [json.loads(line) for line in f if line.strip()]
    return verify_entries(es, expected_head, key)
