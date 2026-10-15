"""FastAPI application factory (SPEC sections 7 and 8)."""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.concurrency import run_in_threadpool

from .config import Config
from .gateway import Gateway, open_store
from .store import Store

log = logging.getLogger("asu.app")

LOGIN_COOKIE_FALLBACK = "asu_login"


def _bearer(request: Request) -> Optional[str]:
    h = request.headers.get("authorization") or ""
    if h[:7].lower() == "bearer ":
        return h[7:].strip() or None
    return None


def _unauth() -> JSONResponse:
    return JSONResponse({"status": "unauthenticated"}, status_code=401,
                        headers={"WWW-Authenticate": 'Bearer realm="asu"'})


async def _json_body(request: Request) -> Any:
    try:
        return await request.json()
    except Exception:
        return None


def authenticated_user(request: Request) -> Optional[str]:
    """The passkey-authenticated human on the authenticator page (cookie).
    Prefers ``asu.authn.current_user``; falls back to the Store web-login
    cookie when AUTHN is not installed."""
    try:
        from asu.authn import current_user  # type: ignore
    except Exception:
        current_user = None
    if current_user is not None:
        try:
            return current_user(request)
        except Exception:
            return None
    store: Store = request.app.state.store
    return store.get_web_login(request.cookies.get(LOGIN_COOKIE_FALLBACK))


DEV_MODE_BANNER = (
    "\n" + "!" * 78 + "\n"
    "!! ASU GATEWAY RUNNING WITH dev_mode: true -- INSECURE, FOR LOCAL TESTS ONLY.\n"
    "!! First passkey enrollment needs NO out-of-band token: anything that can reach\n"
    "!! this port (including the agent) can enroll a passkey for a NEW user id and\n"
    "!! then approve that user's effects. Never use dev_mode for a real principal.\n"
    + "!" * 78 + "\n"
)

SECURITY_HEADERS = {
    # anti-framing on every response (RT-11); the PWA also refuses to run framed
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


def create_app(config: Optional[Config] = None, store: Optional[Store] = None) -> FastAPI:
    config = config or Config()
    store = store or open_store(config)
    gw = Gateway(config, store)
    if config.dev_mode:
        import sys

        log.warning("dev_mode is ON: open first enrollment (insecure)")
        print(DEV_MODE_BANNER, file=sys.stderr)
        store.log("dev_mode_enabled", {"warning": "open first enrollment for new user ids"})
    app = FastAPI(title="ASU Gateway", version="0.2.0")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            if k == "Content-Security-Policy" and k in response.headers:
                continue
            response.headers.setdefault(k, v)
        if request.url.path.startswith("/v1/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    app.state.config = config
    app.state.store = store
    app.state.gateway = gw
    app.state.audit = store.audit

    def session_of(request: Request) -> Optional[Dict[str, Any]]:
        return gw.authenticate(_bearer(request))

    # ------------------------------------------------------------ agent API
    @app.post("/v1/sessions")
    async def create_session(request: Request):
        origin = request.headers.get("origin")
        allowed = config.allowed_origins()
        if origin is not None and origin not in allowed:
            return JSONResponse({"status": "forbidden", "error": "bad origin"}, status_code=403)
        # cookie-authenticated: require a JSON content type (cross-site forms /
        # no-cors fetches cannot set it) as a CSRF defence
        ctype = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            return JSONResponse({"status": "invalid", "error": "application/json required"}, status_code=415)
        uid = authenticated_user(request)
        if not uid:
            return _unauth()
        body = await _json_body(request) or {}
        if not isinstance(body, dict):
            return JSONResponse({"status": "invalid"}, status_code=400)
        agent_id = body.get("agent_id") or "agent"
        scopes = body.get("scopes") or ["*"]
        if not isinstance(agent_id, str) or not isinstance(scopes, list) or \
                not all(isinstance(s, str) for s in scopes):
            return JSONResponse({"status": "invalid"}, status_code=400)
        ttl = body.get("ttl_s") or config.session_ttl_s
        try:
            ttl = max(1, min(int(ttl), int(config.session_ttl_s)))
        except (TypeError, ValueError):
            return JSONResponse({"status": "invalid"}, status_code=400)
        token, sess = store.create_session(uid, agent_id[:128], scopes, ttl)
        return {"session_token": token, "expires_at": sess["expires_at"], "session_id": sess["session_id"]}

    @app.post("/v1/tools/call")
    async def tools_call(request: Request):
        sess = session_of(request)
        if not sess:
            return _unauth()
        body = await _json_body(request)
        if not isinstance(body, dict):
            return JSONResponse({"status": "invalid", "error": "JSON object body required"}, status_code=400)
        code, payload = await run_in_threadpool(gw.call, sess, body)
        return JSONResponse(payload, status_code=code)

    @app.get("/v1/approvals/{approval_id}")
    def approval_status(approval_id: str, request: Request):
        sess = session_of(request)
        if not sess:
            return _unauth()
        code, payload = gw.approval_status(sess, approval_id)
        return JSONResponse(payload, status_code=code)

    @app.post("/v1/approvals/{approval_id}/chat-confirm")
    async def chat_confirm(approval_id: str, request: Request):
        """BASELINE chat-confirm only (404 in every other mode)."""
        sess = session_of(request)
        if not sess:
            return _unauth()
        body = await _json_body(request) or {}
        code, payload = gw.chat_confirm(sess, approval_id, body.get("answer") if isinstance(body, dict) else None)
        return JSONResponse(payload, status_code=code)

    @app.get("/v1/gateway/token-key")
    def token_key():
        """Public Ed25519 key resources use to verify authz tokens."""
        import base64

        return {"alg": "Ed25519", "public_key_b64": base64.b64encode(gw.token_public_key()).decode(),
                "iss": config.token_issuer, "aud": config.token_audience,
                "aud_format": config.token_audience + ":<tool> (or tools.<tool>.audience)"}

    @app.get("/healthz")
    def healthz():
        return {"ok": True, "approval_mode": config.approval_mode}

    from .mcp import register_mcp

    register_mcp(app, gw)

    # ----------------------------------------------------- user-facing parts
    if config.mount_authn:
        try:
            from asu.authn import router as authn_router  # lazy: AUTHN may be absent
        except ImportError as e:
            log.warning("asu.authn not available (%s); authenticator routes not mounted", e)
        else:
            prefix = getattr(authn_router, "prefix", "") or ""
            if prefix.startswith("/v1/authn"):
                app.include_router(authn_router)
            else:
                app.include_router(authn_router, prefix="/v1/authn")

    if config.web_dir and os.path.isdir(config.web_dir):
        from fastapi.staticfiles import StaticFiles

        app.mount("/app", StaticFiles(directory=config.web_dir, html=True), name="web")

        @app.get("/")
        def root():
            return RedirectResponse("/app/")

    return app
