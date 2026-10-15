"""Executors (SPEC section 10). An executor receives the STORED canonical
descriptor (never the agent's copy) and its digest, and returns a
JSON-serialisable result.

- ``mock_ledger``: append ``{descriptor, digest, ...}`` as one JSON line to the
  ledger file (ground truth for experiment scoring).
- ``http_forward``: POST ``{descriptor, digest}`` to a URL; credentials are
  resolved from environment variables on the gateway host (never seen by A).
- ``python:<module>:<fn>``: call ``fn(descriptor)`` (or ``fn(descriptor, digest)``).
- ``token``: return a short-lived Ed25519 authorization token for R.
"""
from __future__ import annotations

import importlib
import inspect
import json
import os
import threading
import time
from typing import Any, Callable, Dict, Optional

Executor = Callable[[Dict[str, Any], str, Dict[str, Any]], Any]

_ledger_lock = threading.Lock()


class ExecutorError(RuntimeError):
    pass


def mock_ledger(path: str) -> Executor:
    def run(desc: Dict[str, Any], digest: str, meta: Dict[str, Any]) -> Dict[str, Any]:
        rec = {"executed_at": time.time(), "digest": digest, "descriptor": desc,
               "via": meta.get("via"), "approval_id": meta.get("approval_id"), "grant_id": meta.get("grant_id"),
               "mode": meta.get("mode")}
        line = json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n"
        d = os.path.dirname(os.path.abspath(path))
        os.makedirs(d, exist_ok=True)
        with _ledger_lock:
            with open(path, "a", encoding="utf-8") as f:
                try:
                    import fcntl

                    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                except (ImportError, OSError):  # pragma: no cover - non-POSIX
                    pass
                f.write(line)
                f.flush()
                os.fsync(f.fileno())
        return {"ledger": "appended", "digest": digest}

    return run


def http_forward(url: str, headers_env: Optional[Dict[str, str]] = None, timeout: float = 10.0) -> Executor:
    def run(desc: Dict[str, Any], digest: str, meta: Dict[str, Any]) -> Dict[str, Any]:
        import httpx

        headers = {"Content-Type": "application/json", "X-ASU-Digest": digest}
        for header, env in (headers_env or {}).items():
            val = os.environ.get(env)
            if val is None:
                raise ExecutorError(f"credential env var {env} not set on gateway")
            headers[header] = val
        r = httpx.post(url, json={"descriptor": desc, "digest": digest}, headers=headers, timeout=timeout)
        try:
            body = r.json()
        except ValueError:
            body = r.text[:2000]
        return {"http_status": r.status_code, "body": body}

    return run


def python_callable(spec: str) -> Executor:
    if ":" not in spec:
        raise ExecutorError("python executor spec must be 'module:function'")
    mod_name, fn_name = spec.rsplit(":", 1)
    fn = getattr(importlib.import_module(mod_name), fn_name)
    try:
        nparams = 0
        for p in inspect.signature(fn).parameters.values():
            if p.kind == p.VAR_POSITIONAL:
                nparams = 3
                break
            if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD):
                nparams += 1
    except (TypeError, ValueError):
        nparams = 1

    def run(desc: Dict[str, Any], digest: str, meta: Dict[str, Any]) -> Any:
        if nparams >= 3:
            return fn(desc, digest, meta)
        if nparams == 2:
            return fn(desc, digest)
        return fn(desc)

    return run


def token_executor(private_key: Any, aud: Any, ttl_s: int = 60, iss: str = "asu-gateway") -> Executor:
    """``aud`` is a string or a callable ``tool -> audience`` (one audience per
    resource, CR-8)."""
    from .tokens import issue_token

    def run(desc: Dict[str, Any], digest: str, meta: Dict[str, Any]) -> Dict[str, Any]:
        a = aud(desc["tool"]) if callable(aud) else aud
        tok = issue_token(private_key, digest, a, ttl_s, iss=iss)
        return {"token": tok, "aud": a, "iss": iss, "ttl_s": ttl_s, "digest": digest}

    return run


def token_audience_for(config: Any, tool: str) -> str:
    """Per-resource audience: ``tools.<tool>.audience`` from the policy, else
    ``<token_audience>:<tool>``."""
    spec = config.tool_spec(tool) or {}
    return spec.get("audience") or f"{config.token_audience}:{tool}"


def build_executor(name: str, config: Any, token_key: Any = None) -> Executor:
    if name == "mock_ledger":
        return mock_ledger(config.ledger_path)
    if name == "http_forward":
        if not config.http_forward_url:
            raise ExecutorError("http_forward requires http_forward_url")
        return http_forward(config.http_forward_url, config.http_forward_headers_env)
    if name.startswith("python:"):
        return python_callable(name[len("python:"):])
    if name == "token":
        if token_key is None:
            raise ExecutorError("token executor requires the gateway signing key")
        return token_executor(token_key, lambda tool: token_audience_for(config, tool), config.token_ttl_s,
                              getattr(config, "token_issuer", "asu-gateway"))
    raise ExecutorError(f"unknown executor {name!r}")
