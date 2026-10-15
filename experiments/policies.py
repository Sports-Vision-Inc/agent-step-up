"""Gateway policies used by the experiments (SPEC section 9 format).

Every policy actually used in a run is copied verbatim into the results JSON,
so numbers can always be traced back to the exact policy that produced them.
"""
from __future__ import annotations

import copy
from typing import Any, Dict

# Tool catalogue for the scripted scenarios (A1-A13). Effect classes follow
# SPEC section 5; defaults follow asu/policies/default.yaml where the tool exists.
SCENARIO_TOOLS: Dict[str, Dict[str, Any]] = {
    "read_file": {"class": "read", "default": "allow"},
    "list_dir": {"class": "read", "default": "allow"},
    "read_inbox": {"class": "read", "default": "allow"},
    "write_file": {"class": "write", "default": "allow"},
    "delete_file": {"class": "delete", "default": "challenge"},
    "send_email": {"class": "send", "default": "challenge"},
    "send_message": {"class": "send", "default": "allow"},
    "transfer_money": {"class": "pay", "default": "challenge"},
    "http_request": {"class": "net", "default": "allow"},
    "http_post": {"class": "net", "default": "challenge"},
    "run_shell": {"class": "exec", "default": "challenge"},
    "change_settings": {"class": "admin", "default": "challenge"},
    "remove_member": {"class": "admin", "default": "challenge", "args": {"member": "account"}},
}

SCENARIO_POLICY: Dict[str, Any] = {
    "tools": SCENARIO_TOOLS,
    "unknown_tool": "deny",
    "step_up": {
        "first_time_recipient": True,
        "amount_over": 100,
        "autonomous_origin": True,
        "destructive_classes": ["delete", "pay", "admin", "exec"],
        "outside_workspace": True,
        "aggregate": {"window_s": 600, "max_effects": 5, "max_amount": 200},
    },
    "deny": {"path_globs": ["/etc/**", "/private/etc/**", "**/.ssh/**"], "hosts": []},
    "grants": {"max_ttl_s": 3600, "max_uses": 3},
    # max_requests_per_min raised from the default 6 to 30 so that ordinary
    # multi-call tasks are not throttled by the in-process harness (which runs
    # far faster than a real agent); A6 additionally runs the default 6.
    # Per-user caps across all of a user's sessions (RT-9) as in asu/policies/default.yaml.
    "flood": {"max_pending_per_session": 1, "max_requests_per_min": 30, "deny_lockout": 3,
              "max_pending_per_user": 3, "deny_lockout_per_user": 10, "lockout_window_s": 3600},
}


def scenario_policy(**over: Any) -> Dict[str, Any]:
    p = copy.deepcopy(SCENARIO_POLICY)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(p.get(k), dict) and k != "tools":
            p[k].update(copy.deepcopy(v))
        else:
            p[k] = copy.deepcopy(v)
    return p


def flood_default_policy() -> Dict[str, Any]:
    """SPEC section 9 flood settings exactly (6 requests/min)."""
    return scenario_policy(flood={"max_pending_per_session": 1, "max_requests_per_min": 6, "deny_lockout": 3,
                                  "max_pending_per_user": 3, "deny_lockout_per_user": 10})


def flood_off_policy() -> Dict[str, Any]:
    """Ablation: P7 controls effectively disabled (large limits)."""
    return scenario_policy(flood={"max_pending_per_session": 1000, "max_requests_per_min": 100000,
                                  "deny_lockout": 100000, "max_pending_per_user": 100000,
                                  "deny_lockout_per_user": 100000})


def payments_relaxed_policy(aggregate: bool = True) -> Dict[str, Any]:
    """A7 (laundering): payments to known payees under amount_over are allowed
    without a prompt; only the amount threshold, first-time payee and the
    aggregate budget can trigger step-up."""
    tools = copy.deepcopy(SCENARIO_TOOLS)
    tools["transfer_money"] = {"class": "pay", "default": "allow"}
    su = copy.deepcopy(SCENARIO_POLICY["step_up"])
    su["destructive_classes"] = ["delete", "admin", "exec"]
    if not aggregate:
        # None (not {}): asu.config deep-merges policies with defaults, so an
        # empty mapping would silently re-enable the default aggregate budget.
        su["aggregate"] = {"window_s": 600, "max_effects": None, "max_amount": None}
    return scenario_policy(tools=tools, step_up=su)
