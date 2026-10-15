"""RED TEAM (crypto lens): a lone UTF-16 surrogate in an argument *name*
(valid JSON: {"\\ud800": 1}) makes ``jcs._utf16_key`` raise
UnicodeEncodeError, which is not a CanonicalizationError. ``Gateway.call``
only catches CanonicalizationError, so the request escapes as an unhandled
exception (HTTP 500 on /v1/tools/call) instead of a clean 403 invalid_args
denial with an audit entry. A lone surrogate in a *value* is handled.

Secure behaviour asserted: the call is rejected with 403 and does not raise.
"""
from __future__ import annotations

import json

from asu.config import Config
from asu.gateway import Gateway


def test_lone_surrogate_key_is_cleanly_denied(tmp_path):
    cfg = Config(db_path=str(tmp_path / "asu.db"), ledger_path=str(tmp_path / "l.jsonl"),
                 workspace_root=str(tmp_path),
                 policy={"tools": {"send_email": {"class": "send", "default": "challenge"}}})
    gw = Gateway(cfg)
    tok, sess = gw.store.create_session("alice", "agent-1", ["*"], 600)
    args = json.loads('{"to": "bob@example.com", "\\ud800": 1}')
    try:
        code, body = gw.call(sess, {"tool": "send_email", "args": args})
    except Exception as e:  # noqa: BLE001
        raise AssertionError(f"canonicalization error escaped as {type(e).__name__}: {e}")
    assert code == 403 and body["status"] == "denied"
