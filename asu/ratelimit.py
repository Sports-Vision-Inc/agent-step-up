"""Flood controls (P7): per-session request rate, one pending approval per
session (configurable), lockout after repeated denials, de-duplication of
identical pending approvals -- plus per-USER caps across all of a user's
sessions (RT-9: an agent that holds several session tokens must not get N
concurrent prompts or N x lockout denials)."""
from __future__ import annotations

import time
from typing import Any, Dict, Optional, Tuple


class FloodControl:
    def __init__(self, store: Any, policy: Dict[str, Any]):
        self.store = store
        fl = policy.get("flood", {}) or {}
        self.max_pending = int(fl.get("max_pending_per_session", 1))
        self.per_min = int(fl.get("max_requests_per_min", 6))
        self.lockout = int(fl.get("deny_lockout", 3))
        self.max_pending_user = fl.get("max_pending_per_user")
        self.lockout_user = fl.get("deny_lockout_per_user")
        self.lockout_window = int(fl.get("lockout_window_s") or 3600)

    def locked_out(self, session_id: str, user_id: Optional[str] = None, now: Optional[float] = None) -> bool:
        if self.store.count_denied(session_id) >= self.lockout:
            return True
        if user_id is not None and self.lockout_user and hasattr(self.store, "count_denied_user"):
            now = time.time() if now is None else now
            if self.store.count_denied_user(user_id, int(now - self.lockout_window)) >= int(self.lockout_user):
                return True
        return False

    def check_call(self, session_id: str, now: Optional[float] = None, user_id: Optional[str] = None) -> Optional[str]:
        """Count a new tool call; return a reason string if it must be refused."""
        now = time.time() if now is None else now
        with self.store.tx():
            if self.store.count_denied(session_id) >= self.lockout:
                return "deny_lockout"
            if user_id is not None and self.locked_out(session_id, user_id, now):
                return "deny_lockout_user"
            n = self.store.count_rate_events(session_id, now - 60)
            if n >= self.per_min:
                return "rate_limit_per_min"
            self.store.add_rate_event(session_id, now)
        return None

    def check_new_approval(self, session_id: str, effect_key: str,
                           user_id: Optional[str] = None) -> Tuple[str, Optional[dict]]:
        """Return ("dedupe", existing) | ("limit", None) | ("limit_user", None) |
        ("ok", None). Must be called inside the store transaction that then
        creates the approval."""
        existing = self.store.find_pending_by_effect(session_id, effect_key)
        if existing is not None:
            return "dedupe", existing
        if self.store.count_pending(session_id) >= self.max_pending:
            return "limit", None
        if user_id is not None and self.max_pending_user and hasattr(self.store, "count_pending_user"):
            if self.store.count_pending_user(user_id) >= int(self.max_pending_user):
                return "limit_user", None
        return "ok", None
