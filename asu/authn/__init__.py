"""WebAuthn passkey step-up for ASU (SPEC sections 4 and 7).

Exports (SPEC section 7):
    router                -- FastAPI APIRouter; its routes already carry the
                             prefix /v1/authn, so mount with
                             ``app.include_router(router)`` (no extra prefix).
    approval_challenge    -- WebAuthn challenge bytes for an approval.
    verify_receipt        -- pure offline receipt verification.
Extra helpers (used by the gateway):
    current_user(request) -- user id of the passkey-signed-in human, or None.
    SESSION_COOKIE, grant_digest
"""
from .receipt import approval_challenge, grant_digest, verify_receipt
from .session import SESSION_COOKIE, current_user
from .routes import router

__all__ = [
    "router",
    "approval_challenge",
    "verify_receipt",
    "current_user",
    "grant_digest",
    "SESSION_COOKIE",
]
