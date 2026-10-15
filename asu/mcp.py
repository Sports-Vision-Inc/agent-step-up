"""MCP (JSON-RPC 2.0 over streamable HTTP) front-end for the gateway.

``POST /mcp`` supports ``initialize``, ``ping``, ``tools/list``, ``tools/call``
(single messages and batches; notifications get no response). Responses are
plain JSON, or a ``text/event-stream`` body when the client accepts only SSE
(or explicitly prefers it with ``Accept: text/event-stream`` first).

Gateway outcomes map to JSON-RPC errors:
  approval required -> -32010 {"approval_id"}   (SPEC section 8)
  denied            -> -32011 {"reasons"}
  effect mismatch   -> -32012
  rate limited      -> -32013 {"reason"}
  not found         -> -32014
  unauthenticated   -> -32001 (HTTP 401)
Retry after approval: ``tools/call`` with ``params.approval_id`` (or
``params._meta.approval_id``) — never inside ``arguments``, which are part of
the effect.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from starlette.concurrency import run_in_threadpool

PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
SERVER_INFO = {"name": "asu-gateway", "version": "0.1.0"}

APPROVAL_REQUIRED = -32010
DENIED = -32011
EFFECT_MISMATCH = -32012
RATE_LIMITED = -32013
NOT_FOUND = -32014
UNAUTHENTICATED = -32001


def _err(id_: Any, code: int, message: str, data: Any = None) -> Dict[str, Any]:
    e: Dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        e["data"] = data
    return {"jsonrpc": "2.0", "id": id_, "error": e}


def _ok(id_: Any, result: Any) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": id_, "result": result}


_JSON_TYPES = {
    "recipient": {"anyOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}}]},
    "account": {"anyOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}}]},
    "path": {"anyOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}}]},
    "url": {"anyOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}}]},
    "amount": {"anyOf": [{"type": "string"}, {"type": "number"}]},
    "currency": {"type": "string", "pattern": "^[A-Za-z]{3}$"},
    "argv": {"anyOf": [{"type": "array", "items": {"type": "string"}}, {"type": "string"}]},
    "text": {"type": "string"},
    "flag": {"type": "boolean"},
    "int": {"type": "integer"},
    "env": {"type": "object", "additionalProperties": {"type": "string"}},
    "json": {},
}


def input_schema_for(spec: Dict[str, Any]) -> Dict[str, Any]:
    """JSON Schema advertised to MCP clients: closed for typed tools (D-005)."""
    if spec.get("input_schema"):
        return spec["input_schema"]
    if "args" not in spec:
        return {"type": "object", "additionalProperties": True}
    from .descriptor import normalize_schema

    props: Dict[str, Any] = {}
    for name, e in normalize_schema(spec.get("args") or {}).items():
        if e["type"] == "enum":
            props[name] = {"enum": list(e["values"])}
        else:
            props[name] = dict(_JSON_TYPES.get(e["type"], {}))
        props[name]["description"] = f"ASU type: {e['type']}"
    return {"type": "object", "properties": props, "additionalProperties": False}


def _tools_for(gw: Any, session: Dict[str, Any]) -> List[Dict[str, Any]]:
    scopes = session.get("scopes") or []
    out = []
    for name, spec in sorted((gw.policy.get("tools") or {}).items()):
        if "*" not in scopes and name not in scopes:
            continue
        schema = input_schema_for(spec)
        out.append({
            "name": name,
            "description": spec.get("description") or f"{spec['class']} action (ASU-mediated; may require approval)",
            "inputSchema": schema,
        })
    return out


def map_gateway_result(id_: Any, code: int, payload: Dict[str, Any]) -> Dict[str, Any]:
    if code == 200:
        return _ok(id_, {
            "content": [{"type": "text", "text": json.dumps(payload.get("result"), sort_keys=True, default=str)}],
            "structuredContent": payload,
            "isError": False,
        })
    if code == 202:
        return _err(id_, APPROVAL_REQUIRED, "approval_required", {"approval_id": payload.get("approval_id")})
    if code == 403:
        return _err(id_, DENIED, "denied", {"reasons": payload.get("reasons", [])})
    if code == 409:
        return _err(id_, EFFECT_MISMATCH, "effect_mismatch")
    if code == 429:
        return _err(id_, RATE_LIMITED, "rate_limited", {"reason": payload.get("reason")})
    if code == 404:
        return _err(id_, NOT_FOUND, "not_found")
    if code == 400:
        return _err(id_, -32602, "invalid_params", {"error": payload.get("error")})
    return _err(id_, -32603, "internal_error", {"error": payload.get("error")})


def handle_message(gw: Any, session: Dict[str, Any], msg: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
        return _err(msg.get("id") if isinstance(msg, dict) else None, -32600, "invalid_request")
    is_notification = "id" not in msg
    id_ = msg.get("id")
    method = msg["method"]
    params = msg.get("params") or {}
    if not isinstance(params, dict):
        return None if is_notification else _err(id_, -32602, "invalid_params")
    if is_notification:
        return None  # notifications/initialized, notifications/cancelled, ...

    if method == "initialize":
        pv = params.get("protocolVersion")
        return _ok(id_, {
            "protocolVersion": pv if pv in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0],
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": SERVER_INFO,
            "instructions": "Tool calls are mediated by an ASU gateway. On error -32010 the human must approve "
                            "out of band; retry tools/call with params.approval_id.",
        })
    if method == "ping":
        return _ok(id_, {})
    if method == "tools/list":
        return _ok(id_, {"tools": _tools_for(gw, session)})
    if method == "tools/call":
        meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
        body: Dict[str, Any] = {"tool": params.get("name"), "args": params.get("arguments")}
        for k in ("approval_id", "origin", "explanation", "totp_code"):
            v = params.get(k, meta.get(k, meta.get(f"asu/{k}")))
            if v is not None:
                body[k] = v
        if body.get("approval_id") is not None and params.get("arguments") is None:
            body.pop("args")
        if body.get("approval_id") is not None and params.get("name") is None:
            body.pop("tool")
        code, payload = gw.call(session, body)
        return map_gateway_result(id_, code, payload)
    return _err(id_, -32601, "method_not_found")


def _wants_sse(request: Request) -> bool:
    accept = (request.headers.get("accept") or "").lower()
    if "text/event-stream" not in accept:
        return False
    if "application/json" not in accept:
        return True
    return accept.index("text/event-stream") < accept.index("application/json")


def _sse(messages: List[Dict[str, Any]]) -> Response:
    body = "".join(f"event: message\ndata: {json.dumps(m, separators=(',', ':'))}\n\n" for m in messages)
    return Response(body, media_type="text/event-stream", headers={"Cache-Control": "no-store"})


def register_mcp(app: FastAPI, gw: Any) -> None:
    from .app import _bearer  # local import to avoid a cycle at module load

    @app.post("/mcp")
    async def mcp_endpoint(request: Request):
        raw = await request.body()
        try:
            data = json.loads(raw)
        except Exception:
            out = _err(None, -32700, "parse_error")
            return _sse([out]) if _wants_sse(request) else JSONResponse(out, status_code=400)
        session = gw.authenticate(_bearer(request))
        if not session:
            out = _err(data.get("id") if isinstance(data, dict) else None, UNAUTHENTICATED, "unauthenticated")
            return JSONResponse(out, status_code=401, headers={"WWW-Authenticate": 'Bearer realm="asu"'})
        batch = isinstance(data, list)
        msgs = data if batch else [data]
        if batch and not msgs:
            out = _err(None, -32600, "invalid_request")
            return JSONResponse(out, status_code=400)
        responses = []
        for m in msgs:
            r = await run_in_threadpool(handle_message, gw, session, m)
            if r is not None:
                responses.append(r)
        if not responses:
            return Response(status_code=202)
        if _wants_sse(request):
            return _sse(responses)
        return JSONResponse(responses if batch else responses[0])

    @app.get("/mcp")
    def mcp_get():
        return Response(status_code=405, headers={"Allow": "POST"})
