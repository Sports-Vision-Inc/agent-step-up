"""Gateway core: decide / challenge / execute (SPEC section 4 steps 3-9).

Transport-independent; ``app.py`` (REST) and ``mcp.py`` (JSON-RPC) both call
``Gateway.call``. Every response returned to the agent contains only what the
SPEC allows (status, approval_id, reasons for denials, executor result).
"""
from __future__ import annotations

import base64
import hmac
import inspect
import json
import logging
import os
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import descriptor as D
from .config import Config
from .executors import Executor, build_executor
from .grants import build_grant_request, try_use_grant
from .jcs import CanonicalizationError
from .policy import Decision, decide, tool_class
from .ratelimit import FloodControl
from .store import Store

log = logging.getLogger("asu.gateway")

Response = Tuple[int, Dict[str, Any]]

BINDING_MODES = ("asu", "narrated-card", "chat-confirm")  # approval bound to h at execution
UNBOUND_MODES = ("unbound", "totp")                       # baselines: approval not bound to h
MAX_EXPLANATION = 4000
_TOOL_RE = re.compile(r"[A-Za-z0-9_.:\-/]{1,128}")


def open_store(config: Config) -> Store:
    """The gateway's Store, with the audit-chain HMAC key (CR-12)."""
    from .audit import load_or_create_audit_key

    if config.db_path == ":memory:":
        import secrets

        key = secrets.token_bytes(32)
    else:
        key = load_or_create_audit_key(config.audit_key_path or (config.db_path + ".auditkey"))
    return Store(config.db_path, audit_key=key)


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class Gateway:
    def __init__(self, config: Config, store: Optional[Store] = None):
        self.config = config
        self.store = store or open_store(config)
        self.policy = config.policy or {}
        self.flood = FloodControl(self.store, self.policy)
        self._executors: Dict[str, Executor] = {}
        self._token_key = None
        # Optional override (tests / experiments): fn(approval, store) -> bool
        self.receipt_verifier: Optional[Callable[[Dict[str, Any], Store], bool]] = None

    # ------------------------------------------------------------- utilities
    @property
    def token_key(self):
        if self._token_key is None:
            from .tokens import load_or_create_key

            self._token_key = load_or_create_key(self.config.token_key_path)
        return self._token_key

    def token_public_key(self) -> bytes:
        from .tokens import public_key_bytes

        return public_key_bytes(self.token_key)

    def executor_for(self, tool: str) -> Executor:
        spec = self.config.tool_spec(tool) or {}
        name = spec.get("executor") or self.config.executor
        if name not in self._executors:
            key = self.token_key if name == "token" else None
            self._executors[name] = build_executor(name, self.config, key)
        return self._executors[name]

    def authenticate(self, token: Optional[str]) -> Optional[Dict[str, Any]]:
        return self.store.get_session_by_token(token) if token else None

    def _ctx(self, session: Dict[str, Any], tool: str, origin: str, now: int) -> Dict[str, Any]:
        spec = self.config.tool_spec(tool) or {}
        return {
            "principal": session["user_id"],
            "session_id": session["session_id"],
            "agent_id": session["agent_id"],
            "origin": origin,
            "issued_at": now,
            "expires_at": now + int(self.config.approval_ttl_s),
            "effect_class": tool_class(self.policy, tool),
            "workspace_root": self.config.workspace_root,
            "resolve_symlinks": self.config.resolve_symlinks,
            "arg_types": spec.get("args") or {},
            # D-005 item 4: a declared schema is closed
            "arg_schema_closed": "args" in spec,
        }

    @staticmethod
    def _origin(v: Any) -> str:
        # Agent-asserted origin is untrusted: anything but an explicit
        # "user_turn" is treated as autonomous (fail closed).
        return "user_turn" if v == "user_turn" else "autonomous"

    def _audit(self, event: str, **data: Any) -> None:
        self.store.log(event, data)

    # ----------------------------------------------------------------- calls
    def call(self, session: Dict[str, Any], body: Dict[str, Any]) -> Response:
        if not isinstance(body, dict):
            return 400, {"status": "invalid", "error": "body must be an object"}
        if body.get("approval_id") is not None:
            if not isinstance(body["approval_id"], str):
                return 400, {"status": "invalid", "error": "approval_id must be a string"}
            if not re.fullmatch(r"[A-Za-z0-9_\-]{1,128}", body["approval_id"]):
                return 404, {"status": "not_found"}
            return self._execute_approved(session, body)

        sid = session["session_id"]
        reason = self.flood.check_call(sid, user_id=session["user_id"])
        if reason:
            self._audit("rate_limited", session_id=sid, reason=reason)
            return 429, {"status": "rate_limited", "reason": reason}

        tool = body.get("tool")
        args = body.get("args") if body.get("args") is not None else {}
        explanation = body.get("explanation")
        if not isinstance(tool, str) or not isinstance(args, dict):
            return 400, {"status": "invalid", "error": "tool must be a string and args an object"}
        if not _TOOL_RE.fullmatch(tool):
            self._audit("denied", session_id=sid, tool=D.display(tool)[:200], reasons=["bad_tool_name"])
            return 403, {"status": "denied", "reasons": ["bad_tool_name"]}
        if explanation is not None and not isinstance(explanation, str):
            return 400, {"status": "invalid", "error": "explanation must be a string"}
        if explanation:
            # lone surrogates cannot be stored or rendered: replace them
            explanation = "".join("\ufffd" if 0xD800 <= ord(ch) <= 0xDFFF else ch
                                  for ch in explanation[:MAX_EXPLANATION])
        scopes = session.get("scopes") or []
        if "*" not in scopes and tool not in scopes:
            self._audit("denied", session_id=sid, tool=tool, reasons=["out_of_session_scope"])
            return 403, {"status": "denied", "reasons": ["out_of_session_scope"]}
        try:
            raw_size = len(json.dumps(args, default=str))
        except Exception:
            raw_size = self.config.max_args_bytes + 1
        if raw_size > self.config.max_args_bytes:
            return 403, {"status": "denied", "reasons": ["args_too_large"]}

        now = int(time.time())
        ctx = self._ctx(session, tool, self._origin(body.get("origin")), now)
        try:
            desc = D.canonicalize(tool, args, ctx)
            h = D.digest(desc)
        except D.UnknownArgumentError as e:
            # D-005 item 4: closed schema. Names are agent-chosen: escape them.
            reasons = [f"unknown_argument:{D.display(n)[:128]}" for n in e.names]
            self._audit("denied", session_id=sid, tool=tool, reasons=reasons)
            return 403, {"status": "denied", "reasons": reasons}
        except Exception as e:  # CanonicalizationError, or anything unexpected: deny, never 500 (CR-6)
            msg = D.display(str(e))[:300]
            self._audit("denied", session_id=sid, tool=tool, reasons=[f"invalid_args:{msg}"])
            return 403, {"status": "denied", "reasons": [f"invalid_args: {msg}"]}

        decision = decide(desc, self.policy, self.store, session["user_id"], now, self.config.workspace_root)
        self._audit("decision", session_id=sid, tool=tool, digest=h, decision=decision.to_dict(),
                    mode=self.config.approval_mode)
        if decision.outcome == "deny":
            return 403, {"status": "denied", "reasons": decision.reasons}
        if decision.outcome == "allow":
            return self._run(session, desc, h, via="policy_allow")
        return self._challenge(session, desc, h, decision, args, ctx, explanation, body)

    # -------------------------------------------------------------- challenge
    def _challenge(self, session, desc, h, decision: Decision, raw_args, ctx, explanation, body) -> Response:
        mode = self.config.approval_mode
        sid = session["session_id"]
        if mode == "none":
            return self._run(session, desc, h, via="mode_none")
        if mode == "unbound":
            fresh = self.store.get_session(sid)
            if fresh and fresh.get("run_approved"):
                return self._run(session, desc, h, via="unbound_session")
        if mode == "totp" and body.get("totp_code") is not None:
            if self._check_totp(session["user_id"], body.get("totp_code")):
                return self._run(session, desc, h, via="totp_code")
            self._audit("totp_rejected", session_id=sid)
            return 403, {"status": "denied", "reasons": ["totp_invalid"]}
        if mode == "asu" and decision.grantable:
            gid = try_use_grant(self.store, desc)
            if gid:
                return self._run(session, desc, h, via="grant", grant_id=gid)

        ek = D.effect_key(desc)
        with self.store.tx():
            kind, existing = self.flood.check_new_approval(sid, ek, user_id=session["user_id"])
            if kind == "dedupe":
                self._audit("approval_deduplicated", session_id=sid, approval_id=existing["id"])
                return 202, {"status": "approval_required", "approval_id": existing["id"]}
            if kind in ("limit", "limit_user"):
                why = "max_pending_per_session" if kind == "limit" else "max_pending_per_user"
                self._audit("rate_limited", session_id=sid, reason=why)
                return 429, {"status": "rate_limited", "reason": why}
            if mode == "narrated-card":
                card = D.render_narrated_card(desc, explanation)
            else:
                card = D.render_card(desc, decision.reasons, explanation, self.config.workspace_root)
            grant_request = build_grant_request(desc, self.policy, decision) if mode == "asu" else None
            ap = self.store.create_approval(
                user_id=session["user_id"], session_id=sid, agent_id=session["agent_id"], descriptor=desc,
                digest=h, effect_key=ek, raw_args=raw_args, ctx=ctx, mode=mode, card=card,
                explanation=explanation, grant_request=grant_request, reasons=decision.reasons)
        return 202, {"status": "approval_required", "approval_id": ap["id"]}

    def _check_totp(self, user_id: str, code: Any) -> bool:
        import pyotp

        secret = self.store.get_totp_secret(user_id)
        if not secret or not isinstance(code, str) or not code.isdigit():
            return False
        totp = pyotp.TOTP(secret)
        now = time.time()
        step_now = int(now // totp.interval)
        for off in (-1, 0, 1):
            step = step_now + off
            if hmac.compare_digest(totp.at(step * totp.interval), code):
                return self.store.use_totp_step(user_id, step)
        return False

    # ---------------------------------------------------------------- execute
    def _execute_approved(self, session: Dict[str, Any], body: Dict[str, Any]) -> Response:
        aid = body["approval_id"]
        sid = session["session_id"]
        ap = self.store.get_approval(aid)
        if not ap or ap["session_id"] != sid or ap["user_id"] != session["user_id"]:
            self._audit("approval_lookup_rejected", session_id=sid, approval_id=aid,
                        reason="not_found" if not ap else "cross_session")
            return 404, {"status": "not_found"}
        status = ap["status"]
        if status == "pending":
            return 202, {"status": "approval_required", "approval_id": aid}
        if status == "denied":
            return 403, {"status": "denied", "reasons": ["approval_denied"]}
        if status == "expired":
            return 403, {"status": "denied", "reasons": ["approval_expired"]}
        if status == "consumed":
            self._audit("replay_rejected", session_id=sid, approval_id=aid)
            return 403, {"status": "denied", "reasons": ["approval_already_used"]}
        if status != "approved":
            return 403, {"status": "denied", "reasons": [f"approval_{status}"]}

        mode = ap["mode"]
        if mode in UNBOUND_MODES:
            return self._execute_unbound(session, ap, body)

        # --- effect binding (P2) ---
        if body.get("tool") is not None and body.get("tool") != ap["tool"]:
            self._audit("effect_mismatch", session_id=sid, approval_id=aid, reason="tool")
            return 409, {"status": "effect_mismatch"}
        if D.digest(ap["descriptor"]) != ap["digest"]:
            self._audit("effect_mismatch", session_id=sid, approval_id=aid, reason="stored_descriptor_corrupt")
            return 409, {"status": "effect_mismatch"}
        if body.get("args") is not None:
            try:
                h2 = D.digest(D.canonicalize(ap["tool"], body["args"], ap["ctx"]))
            except Exception as e:  # noqa: BLE001 - any failure is a mismatch
                h2 = f"error:{type(e).__name__}"
            if not hmac.compare_digest(h2, ap["digest"]):
                self._audit("effect_mismatch", session_id=sid, approval_id=aid, reason="resubmitted_args",
                            resubmitted_digest=h2)
                return 409, {"status": "effect_mismatch"}
        # Re-resolve the stored call now (detects symlink swaps after approval).
        try:
            h3 = D.digest(D.canonicalize(ap["tool"], ap["raw_args"], ap["ctx"]))
        except Exception as e:  # noqa: BLE001
            h3 = f"error:{type(e).__name__}"
        if not hmac.compare_digest(h3, ap["digest"]):
            self._audit("effect_mismatch", session_id=sid, approval_id=aid, reason="resolution_changed")
            return 409, {"status": "effect_mismatch"}

        if mode == "asu" and self.config.reverify_receipts and not self._verify_receipt(ap):
            self._audit("receipt_rejected", session_id=sid, approval_id=aid)
            return 403, {"status": "denied", "reasons": ["receipt_invalid"]}

        if not self.store.consume(aid):
            self._audit("replay_rejected", session_id=sid, approval_id=aid, reason="consume_failed")
            return 403, {"status": "denied", "reasons": ["approval_already_used"]}
        return self._run(session, ap["descriptor"], ap["digest"], via="approval", approval_id=aid)

    def _execute_unbound(self, session, ap, body) -> Response:
        """BASELINES `unbound` / `totp`: the approval does not cover h, so the
        gateway has nothing to bind against and runs whatever the agent
        (re)submits. Hard deny rules still apply."""
        aid = ap["id"]
        if body.get("args") is not None or body.get("tool") is not None:
            tool = body.get("tool") or ap["tool"]
            args = body.get("args") if body.get("args") is not None else ap["raw_args"]
            now = int(time.time())
            ctx = self._ctx(session, tool, self._origin(body.get("origin", ap["descriptor"]["origin"])), now)
            if not isinstance(tool, str) or not _TOOL_RE.fullmatch(tool) or not isinstance(args, dict):
                return 403, {"status": "denied", "reasons": ["invalid_args"]}
            try:
                desc = D.canonicalize(tool, args, ctx)
            except Exception as e:  # noqa: BLE001
                return 403, {"status": "denied", "reasons": [f"invalid_args: {D.display(str(e))[:300]}"]}
            dec = decide(desc, self.policy, self.store, session["user_id"], now, self.config.workspace_root)
            if dec.outcome == "deny":
                return 403, {"status": "denied", "reasons": dec.reasons}
        else:
            desc = ap["descriptor"]
        if not self.store.consume(aid):
            return 403, {"status": "denied", "reasons": ["approval_already_used"]}
        if ap["mode"] == "unbound":
            self.store.set_session_run_approved(session["session_id"])
        return self._run(session, desc, D.digest(desc), via=f"{ap['mode']}_approval", approval_id=aid)

    def _verify_receipt(self, ap: Dict[str, Any]) -> bool:
        if self.receipt_verifier is not None:
            try:
                return bool(self.receipt_verifier(ap, self.store))
            except Exception:
                return False
        receipt = ap.get("receipt")
        if not isinstance(receipt, dict):
            return False
        try:
            from asu.authn import verify_receipt  # type: ignore
        except Exception:
            log.error("asu.authn.verify_receipt unavailable; refusing to execute (fail closed)")
            return False
        cid = receipt.get("credential_id")
        if isinstance(cid, (bytes, bytearray)):
            cid_b = bytes(cid)
        elif isinstance(cid, str):
            try:
                cid_b = _b64u_dec(cid)
            except Exception:
                return False
        else:
            return False
        pub = None
        for cred in self.store.get_credentials(ap["user_id"]):
            if hmac.compare_digest(cred["credential_id"], cid_b):
                pub = cred["public_key"]
        if pub is None:
            return False
        kwargs: Dict[str, Any] = {}
        try:
            params = inspect.signature(verify_receipt).parameters
        except (TypeError, ValueError):
            params = {}
        origins = self.config.allowed_origins()
        if "expected_rp_id" in params:
            kwargs["expected_rp_id"] = self.config.rp_id
        if "expected_origins" in params:
            kwargs["expected_origins"] = list(origins)
        if "require_user_verification" in params:
            kwargs["require_user_verification"] = self.config.require_user_verification
        if ap.get("grant") is not None:
            if "expected_grant_digest" not in params:
                return False
            from .descriptor import canonical_bytes
            import hashlib

            kwargs["expected_grant_digest"] = hashlib.sha256(canonical_bytes(ap["grant"])).hexdigest()
        try:
            return bool(verify_receipt(receipt, pub, ap["digest"], ap["id"], ap["nonce"], **kwargs))
        except Exception:
            return False

    # -------------------------------------------------------------------- run
    def _run(self, session, desc, h, via: str, approval_id: Optional[str] = None,
             grant_id: Optional[str] = None) -> Response:
        meta = {"via": via, "approval_id": approval_id, "grant_id": grant_id, "mode": self.config.approval_mode,
                "session_id": session["session_id"]}
        try:
            result = self.executor_for(desc["tool"])(desc, h, meta)
        except Exception as e:  # executor failure: nothing recorded as executed
            log.exception("executor failed")
            self._audit("execution_failed", session_id=session["session_id"], digest=h, error=str(e)[:500])
            return 500, {"status": "error", "error": "execution_failed"}
        amount, currency = D.amount_of(desc)
        eid = self.store.record_effect(
            user_id=session["user_id"], session_id=session["session_id"], descriptor=desc, digest=h, via=via,
            approval_id=approval_id, grant_id=grant_id, amount=str(abs(amount)) if amount is not None else None,
            currency=currency, recipients=D.recipients(desc), result=result)
        return 200, {"status": "executed", "result": result, "receipt_id": eid}

    # --------------------------------------------------- agent-facing helpers
    def approval_status(self, session: Dict[str, Any], approval_id: str) -> Response:
        ap = self.store.get_approval(approval_id)
        if not ap or ap["session_id"] != session["session_id"] or ap["user_id"] != session["user_id"]:
            return 404, {"status": "not_found"}
        return 200, {"status": ap["status"]}

    def chat_confirm(self, session: Dict[str, Any], approval_id: str, answer: Any) -> Response:
        """BASELINE `chat-confirm`: a 'yes' typed in the agent's own channel
        approves (P1 deliberately violated: the agent can produce it)."""
        if self.config.approval_mode != "chat-confirm":
            return 404, {"status": "not_found"}
        ap = self.store.get_approval(approval_id)
        if not ap or ap["session_id"] != session["session_id"] or ap["mode"] != "chat-confirm":
            return 404, {"status": "not_found"}
        text = answer if isinstance(answer, str) else ""
        if text.strip().lower() in ("y", "yes", "approve", "ok", "confirm"):
            ok = self.store.mark_approved(approval_id, {"type": "chat-confirm", "text": text[:200]})
        else:
            ok = self.store.mark_denied(approval_id)
        ap = self.store.get_approval(approval_id)
        return (200 if ok else 409), {"status": ap["status"] if ap else "not_found"}

    def export_receipt(self, approval_id: str) -> Optional[Dict[str, Any]]:
        """Offline-verifiable bundle (P5): descriptor, digest, approval id,
        nonce, receipt, and the user's credential public keys."""
        ap = self.store.get_approval(approval_id)
        if not ap or ap.get("receipt") is None:
            return None
        creds = self.store.get_credentials(ap["user_id"])
        return export_bundle(ap, creds)


def export_bundle(ap: Dict[str, Any], creds: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Offline bundle. ``public_keys`` are included only as a convenience: a
    third party must verify against a key it obtained independently
    (``asu verify-receipt --public-key``), never against these (CR-7)."""
    return {
        "format": "asu-receipt-bundle-v2",
        "approval_id": ap["id"],
        "nonce": ap["nonce"],
        "digest": ap["digest"],
        "descriptor": ap["descriptor"],
        "grant": ap.get("grant"),
        "receipt": ap["receipt"],
        "user_id": ap["user_id"],
        "public_keys": [{"credential_id": _b64u(c["credential_id"]), "public_key": _b64u(c["public_key"])}
                        for c in creds],
    }
