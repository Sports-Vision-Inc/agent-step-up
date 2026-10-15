"""Gateway configuration (YAML file or dict) and policy loading."""
from __future__ import annotations

import copy
import os
from dataclasses import dataclass, field, fields
from typing import Any, Dict, List, Optional

import yaml

APPROVAL_MODES = ("none", "chat-confirm", "narrated-card", "unbound", "totp", "asu")

PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_POLICY_PATH = os.path.join(PACKAGE_DIR, "policies", "default.yaml")
SCHEMA_LIBRARY_PATH = os.path.join(PACKAGE_DIR, "policies", "schemas.yaml")
REPO_ROOT = os.path.dirname(PACKAGE_DIR)

DEFAULT_POLICY: Dict[str, Any] = {
    "tools": {},
    "unknown_tool": "deny",
    # D-005 item 4: tools listed in the policy get their argument schema from
    # asu/policies/schemas.yaml unless the policy declares it; a declared
    # schema is closed (unknown arguments -> deny).
    "schema_library": True,
    # tools with no schema at all: their non-read calls are always stepped up
    "untyped_tools": "challenge",
    "step_up": {
        "first_time_recipient": True,
        "amount_over": 100,
        "autonomous_origin": True,
        "destructive_classes": ["delete", "pay", "admin", "exec"],
        "outside_workspace": True,
        "aggregate": {"window_s": 600, "max_effects": 5, "max_amount": 200},
    },
    "deny": {"path_globs": ["/etc/**", "**/.ssh/**"], "hosts": []},
    "grants": {"max_ttl_s": 3600, "max_uses": 10, "max_text_len": 4000},
    # per-session limits (SPEC P7). Per-user limits across all of a user's
    # sessions (RT-9: an agent holding several session tokens) are set by the
    # packaged default.yaml; a policy dict that omits them does not get them
    # (so existing experiment policies keep their measured behaviour).
    "flood": {"max_pending_per_session": 1, "max_requests_per_min": 6, "deny_lockout": 3,
              "max_pending_per_user": None, "deny_lockout_per_user": None, "lockout_window_s": 3600},
}


def load_schema_library() -> Dict[str, Any]:
    with open(SCHEMA_LIBRARY_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def apply_schema_library(pol: Dict[str, Any]) -> None:
    """Fill ``tools.<name>.args`` from the packaged schema library (an explicit
    per-argument entry in the policy wins)."""
    if not pol.get("schema_library", True):
        return
    lib = load_schema_library()
    for name, spec in (pol.get("tools") or {}).items():
        if isinstance(spec, dict) and name in lib:
            merged = dict(lib[name] or {})
            merged.update(spec.get("args") or {})
            spec["args"] = merged


def _deep_merge(base: Dict[str, Any], over: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict) and k != "tools":
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def load_policy(source: Any = None) -> Dict[str, Any]:
    """Load a policy from a YAML path, a dict, or None (packaged default).
    Missing sections are filled from DEFAULT_POLICY; ``tools`` is never merged
    with defaults (an explicit tool list is authoritative)."""
    if source is None:
        with open(DEFAULT_POLICY_PATH, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    elif isinstance(source, dict):
        data = source
    else:
        with open(source, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    pol = _deep_merge(DEFAULT_POLICY, data)
    apply_schema_library(pol)
    validate_policy(pol)
    return pol


def validate_policy(pol: Dict[str, Any]) -> None:
    from .descriptor import EFFECT_CLASSES

    if not isinstance(pol.get("tools"), dict):
        raise ValueError("policy.tools must be a mapping")
    for name, spec in pol["tools"].items():
        if not isinstance(spec, dict):
            raise ValueError(f"policy.tools.{name} must be a mapping")
        if spec.get("class") not in EFFECT_CLASSES:
            raise ValueError(f"policy.tools.{name}.class must be one of {EFFECT_CLASSES}")
        if spec.get("default", "challenge") not in ("allow", "deny", "challenge"):
            raise ValueError(f"policy.tools.{name}.default must be allow|deny|challenge")
        if "args" in spec:
            from .descriptor import normalize_schema
            from .jcs import CanonicalizationError

            if not isinstance(spec["args"], dict):
                raise ValueError(f"policy.tools.{name}.args must be a mapping")
            try:
                normalize_schema(spec["args"])
            except CanonicalizationError as e:
                raise ValueError(f"policy.tools.{name}.args: {e}")
    if pol.get("untyped_tools", "challenge") not in ("challenge", "deny", "allow"):
        raise ValueError("policy.untyped_tools must be challenge|deny|allow")
    if pol.get("unknown_tool", "deny") not in ("deny", "challenge"):
        raise ValueError("policy.unknown_tool must be deny|challenge")
    fl = pol["flood"]
    for k in ("max_pending_per_session", "max_requests_per_min", "deny_lockout"):
        if not isinstance(fl.get(k), int) or fl[k] < 1:
            raise ValueError(f"policy.flood.{k} must be a positive integer")
    for k in ("max_pending_per_user", "deny_lockout_per_user", "lockout_window_s"):
        if fl.get(k) is not None and (not isinstance(fl[k], int) or fl[k] < 1):
            raise ValueError(f"policy.flood.{k} must be a positive integer or null")
    g = pol["grants"]
    for k in ("max_ttl_s", "max_uses"):
        if not isinstance(g.get(k), int) or g[k] < 0:
            raise ValueError(f"policy.grants.{k} must be a non-negative integer")


@dataclass
class Config:
    db_path: str = "asu.db"
    approval_mode: str = "asu"
    workspace_root: str = "."
    policy_path: Optional[str] = None
    policy: Optional[Dict[str, Any]] = None
    executor: str = "mock_ledger"
    ledger_path: str = "ledger.jsonl"
    http_forward_url: Optional[str] = None
    http_forward_headers_env: Dict[str, str] = field(default_factory=dict)  # header -> env var name
    token_key_path: str = "gateway_ed25519.pem"
    token_audience: str = "asu-resource"
    token_ttl_s: int = 60
    token_issuer: str = "asu-gateway"
    rp_id: str = "localhost"
    rp_name: str = "ASU Gateway"
    origin: str = "http://localhost:8000"
    # every origin the authenticator page may be served from (default: [origin])
    expected_origins: Optional[List[str]] = None
    session_ttl_s: int = 3600
    approval_ttl_s: int = 300
    resolve_symlinks: bool = True
    reverify_receipts: bool = True
    # D-005 item 3: UV (PIN / biometric) required for every ceremony by default
    require_user_verification: bool = True
    web_dir: Optional[str] = None
    mount_authn: bool = True
    max_args_bytes: int = 65536
    # D-005 item 2: first enrollment needs a one-time enrollment token
    # (``asu enroll-link``). dev_mode=True relaxes this (loud startup warning).
    dev_mode: bool = False
    enrollment_token: Optional[str] = None      # legacy static operator secret (prefer one-time links)
    enrollment_ttl_s: int = 900
    # per-entry HMAC key for the audit chain (CR-12); None -> "<db_path>.auditkey"
    audit_key_path: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.approval_mode not in APPROVAL_MODES:
            raise ValueError(f"approval_mode must be one of {APPROVAL_MODES}")
        if self.policy is None:
            self.policy = load_policy(self.policy_path)
        else:
            self.policy = load_policy(self.policy)
        if self.web_dir is None:
            self.web_dir = os.path.join(REPO_ROOT, "web")
        if self.enrollment_token is None and self.extra.get("enrollment_token"):
            self.enrollment_token = str(self.extra["enrollment_token"])

    def allowed_origins(self) -> List[str]:
        """The ONE place origins are read from (CR-10): ``expected_origins``,
        else legacy ``extra.expected_origins`` / ``extra.allowed_origins``,
        else ``[origin]``."""
        o = self.expected_origins or self.extra.get("expected_origins") or self.extra.get("allowed_origins") \
            or self.origin
        return [o] if isinstance(o, str) else list(o)

    @classmethod
    def from_dict(cls, data: Dict[str, Any], base_dir: Optional[str] = None) -> "Config":
        known = {f.name for f in fields(cls)}
        kwargs = {k: v for k, v in (data or {}).items() if k in known}
        extra = {k: v for k, v in (data or {}).items() if k not in known}
        if extra:
            kwargs.setdefault("extra", {}).update(extra)
        if base_dir:
            for k in ("db_path", "workspace_root", "policy_path", "ledger_path", "token_key_path", "web_dir",
                      "audit_key_path"):
                v = kwargs.get(k)
                if isinstance(v, str) and v and not os.path.isabs(v):
                    kwargs[k] = os.path.join(base_dir, v)
        return cls(**kwargs)

    @classmethod
    def from_file(cls, path: str) -> "Config":
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls.from_dict(data, base_dir=os.path.dirname(os.path.abspath(path)))

    def tool_spec(self, tool: str) -> Optional[Dict[str, Any]]:
        return (self.policy or {}).get("tools", {}).get(tool)
