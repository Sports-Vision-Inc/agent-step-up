"""``asu`` command line: serve, enroll-link, dev-session, verify-chain,
export-receipt, verify-receipt."""
from __future__ import annotations

import argparse
import base64
import json
import sys
from typing import Any, List, Optional

from .config import APPROVAL_MODES, Config


def _load_config(args: argparse.Namespace) -> Config:
    overrides = {}
    if getattr(args, "approval_mode", None):
        overrides["approval_mode"] = args.approval_mode
    if getattr(args, "db", None):
        overrides["db_path"] = args.db
    if getattr(args, "config", None):
        cfg = Config.from_file(args.config)
        for k, v in overrides.items():
            setattr(cfg, k, v)
        if "approval_mode" in overrides and overrides["approval_mode"] not in APPROVAL_MODES:
            raise SystemExit(f"bad approval mode {overrides['approval_mode']}")
        return cfg
    return Config(**overrides)


def _b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from .app import create_app

    cfg = _load_config(args)
    app = create_app(cfg)
    uvicorn.run(app, host=args.host, port=args.port, log_level=args.log_level)
    return 0


def _enroll_url(cfg: Config, user: str, token: str) -> str:
    from urllib.parse import quote

    base = cfg.allowed_origins()[0].rstrip("/")
    return f"{base}/app/#enroll={quote(token, safe='')}&user={quote(user, safe='')}"


def cmd_enroll_link(args: argparse.Namespace) -> int:
    """Print a ONE-TIME enrollment URL for a user (D-005 item 2). Deliver it
    to the human out of band (never through the agent)."""
    from .gateway import open_store

    cfg = _load_config(args)
    store = open_store(cfg)
    if store.get_credentials(args.user):
        print(json.dumps({"error": f"user {args.user!r} already has a passkey; sign in and use 'Add passkey'"}))
        return 1
    token = store.create_enrollment_token(args.user, args.ttl or cfg.enrollment_ttl_s)
    out = {"user_id": args.user, "enrollment_url": _enroll_url(cfg, args.user, token),
           "enrollment_token": token, "expires_in_s": args.ttl or cfg.enrollment_ttl_s,
           "note": "one-time; open it on the device that will hold the passkey. Do not give it to the agent."}
    print(json.dumps(out, indent=2))
    return 0


def cmd_dev_session(args: argparse.Namespace) -> int:
    from .gateway import open_store

    cfg = _load_config(args)
    store = open_store(cfg)
    if not store.get_credentials(args.user) and not args.force_insecure:
        # D-005 item 2 / CR-1: an agent token for a principal with no passkey
        # is exactly the state in which an agent could enroll its own key.
        if store.get_user(args.user) is None:
            store.create_user(args.user, args.display_name or args.user)
        token = store.create_enrollment_token(args.user, cfg.enrollment_ttl_s)
        print(json.dumps({
            "error": f"user {args.user!r} has no registered passkey; refusing to mint an agent session token",
            "enroll_first": _enroll_url(cfg, args.user, token),
            "hint": "open the one-time enrollment URL on the passkey device, then re-run; "
                    "or pass --force-insecure for throwaway test setups",
        }, indent=2))
        return 2
    if args.force_insecure and not store.get_credentials(args.user):
        print("WARNING: --force-insecure: minting an agent token for a principal with NO passkey. "
              "Do not use for a real principal.", file=sys.stderr)
    if store.get_user(args.user) is None:
        store.create_user(args.user, args.display_name or args.user)
    scopes = args.scopes.split(",") if args.scopes else ["*"]
    token, sess = store.create_session(args.user, args.agent, scopes, args.ttl or cfg.session_ttl_s)
    out = {"session_token": token, "expires_at": sess["expires_at"], "session_id": sess["session_id"],
           "user_id": args.user, "agent_id": args.agent}
    if args.login_cookie:
        try:
            from asu.authn import SESSION_COOKIE as cookie_name  # type: ignore
        except Exception:
            from .app import LOGIN_COOKIE_FALLBACK as cookie_name
        value = store.create_web_login(args.user, 3600)
        if cookie_name != "asu_login":
            value = "wl." + value  # AUTHN's server-side login cookie format
        out["login_cookie"] = {"name": cookie_name, "value": value}
    print(json.dumps(out, indent=2))
    return 0


def cmd_verify_chain(args: argparse.Namespace) -> int:
    import os

    from .audit import load_or_create_audit_key, verify_db, verify_jsonl

    key = None
    key_path = args.audit_key
    if key_path is None and not args.jsonl:
        cfg = _load_config(args)
        cand = cfg.audit_key_path or ((args.db or cfg.db_path) + ".auditkey")
        key_path = cand if os.path.exists(cand) else None
    if key_path:
        key = load_or_create_audit_key(key_path) if os.path.exists(key_path) else None
        if key is None:
            print(json.dumps({"ok": False, "first_bad_seq": None, "message": f"audit key {key_path} not found"}))
            return 1
    if args.jsonl:
        ok, seq, msg = verify_jsonl(args.jsonl, args.head, key)
    else:
        db = args.db or _load_config(args).db_path
        ok, seq, msg = verify_db(db, args.head, key)
    print(json.dumps({"ok": ok, "first_bad_seq": seq, "message": msg}))
    return 0 if ok else 1


def cmd_export_receipt(args: argparse.Namespace) -> int:
    from .gateway import export_bundle
    from .store import Store

    cfg = _load_config(args)
    store = Store(cfg.db_path)
    ap = store.get_approval(args.approval_id)
    if not ap or ap.get("receipt") is None:
        print(json.dumps({"error": "no receipt for that approval"}))
        return 1
    bundle = export_bundle(ap, store.get_credentials(ap["user_id"]))
    text = json.dumps(bundle, indent=2, sort_keys=True)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    else:
        print(text)
    return 0


def verify_bundle(bundle: dict, public_keys: List[bytes], rp_id: Optional[str] = None,
                  origins: Optional[List[str]] = None, require_uv: bool = False) -> dict:
    """Offline check of an exported receipt bundle against independently
    obtained keys (P5 as restated by D-005 item 7: a third party with pk_U can
    verify that U's authenticator signed digest h for approval id). Reports the
    signed flag bits and the grant digest; fails if the signature covers a
    grant that the bundle does not disclose (CR-7)."""
    from .descriptor import digest, recipients, targets_of

    try:
        from asu.authn import verify_receipt  # type: ignore
        from asu.authn.receipt import authenticator_flags, grant_digest  # type: ignore
    except ImportError:
        return {"ok": False, "error": "asu.authn.verify_receipt not installed"}
    if not rp_id:
        return {"ok": False, "error": "an expected RP ID is required (--rp-id)"}
    if not public_keys:
        return {"ok": False, "error": "an independently obtained public key is required (--public-key)"}
    try:
        if digest(bundle["descriptor"]) != bundle["digest"]:
            return {"ok": False, "error": "descriptor does not hash to the approved digest"}
    except Exception as e:
        return {"ok": False, "error": f"bad descriptor: {e}"}
    receipt = bundle.get("receipt") or {}
    signed_g = receipt.get("grant_digest")
    g = None
    if bundle.get("grant") is not None:
        try:
            g = grant_digest(bundle["grant"])
        except Exception as e:
            return {"ok": False, "error": f"bad grant: {e}"}
        if signed_g is None or str(signed_g).lower() != g:
            return {"ok": False, "error": "bundle grant does not match the signed grant digest"}
    elif signed_g is not None:
        return {"ok": False, "error": "the approval also signed a delegated grant that the bundle does not "
                                     "disclose (grant_digest %s)" % signed_g}
    kwargs: dict = {"expected_rp_id": rp_id, "require_user_verification": require_uv}
    if origins:
        kwargs["expected_origins"] = list(origins)
    if g is not None:
        kwargs["expected_grant_digest"] = g
    for pk in public_keys:
        try:
            if verify_receipt(receipt, pk, bundle["digest"], bundle["approval_id"], bundle["nonce"], **kwargs):
                flags = authenticator_flags(receipt)
                desc = bundle["descriptor"]
                return {"ok": True, "claim": "the holder of the given public key signed this digest for this "
                                             "approval id (key-level; see docs: consent-level needs an honest "
                                             "rendering origin)",
                        "digest": bundle["digest"], "approval_id": bundle["approval_id"],
                        "tool": desc.get("tool"), "target": desc.get("target"), "targets": targets_of(desc),
                        "recipients": recipients(desc), "rp_id": rp_id,
                        "flags": {k: flags[k] for k in ("up", "uv", "be", "bs")},
                        "user_verified": flags["uv"], "sign_count": flags["sign_count"],
                        "grant_digest": signed_g, "grant": bundle.get("grant")}
        except TypeError:
            continue
    return {"ok": False, "error": "signature does not verify under any supplied public key"}


def cmd_verify_receipt(args: argparse.Namespace) -> int:
    with open(args.bundle, "r", encoding="utf-8") as f:
        bundle = json.load(f)
    keys: List[bytes] = []
    for path in args.public_key:
        with open(path, "rb") as f:
            raw = f.read()
        if raw.startswith(b"-----BEGIN"):
            keys.append(raw)
        else:
            keys.append(_b64u_dec(raw.decode().strip()))
    res = verify_bundle(bundle, keys, rp_id=args.rp_id, origins=args.origin or None, require_uv=args.require_uv)
    print(json.dumps(res, sort_keys=True))
    return 0 if res.get("ok") else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="asu", description="Agent Step-Up gateway")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--config", help="gateway YAML config")
        sp.add_argument("--db", help="override sqlite db path")

    sp = sub.add_parser("serve", help="run the gateway")
    common(sp)
    sp.add_argument("--host", default="127.0.0.1")
    sp.add_argument("--port", type=int, default=8000)
    sp.add_argument("--approval-mode", choices=APPROVAL_MODES)
    sp.add_argument("--log-level", default="info")
    sp.set_defaults(fn=cmd_serve)

    sp = sub.add_parser("enroll-link", help="print a one-time passkey enrollment URL for a user (out of band)")
    common(sp)
    sp.add_argument("--user", required=True)
    sp.add_argument("--ttl", type=int, help="seconds the link stays valid (default enrollment_ttl_s)")
    sp.set_defaults(fn=cmd_enroll_link)

    sp = sub.add_parser("dev-session", help="(dev/tests) create a user + agent session token directly")
    common(sp)
    sp.add_argument("--user", default="alice")
    sp.add_argument("--display-name")
    sp.add_argument("--agent", default="agent-1")
    sp.add_argument("--scopes", help="comma-separated tool names (default: all)")
    sp.add_argument("--ttl", type=int)
    sp.add_argument("--login-cookie", action="store_true", help="also mint an authenticator-page login cookie")
    sp.add_argument("--force-insecure", action="store_true",
                    help="mint a token even though the principal has no passkey (throwaway tests only)")
    sp.set_defaults(fn=cmd_dev_session)

    sp = sub.add_parser("verify-chain", help="verify the audit hash chain")
    common(sp)
    sp.add_argument("--jsonl", help="verify an exported JSONL audit log instead of the db")
    sp.add_argument("--head", help="externally anchored head hash (detects truncation)")
    sp.add_argument("--audit-key", help="audit HMAC key file (default: <db>.auditkey if present)")
    sp.set_defaults(fn=cmd_verify_chain)

    sp = sub.add_parser("export-receipt", help="export an offline-verifiable receipt bundle")
    common(sp)
    sp.add_argument("approval_id")
    sp.add_argument("--out")
    sp.set_defaults(fn=cmd_export_receipt)

    sp = sub.add_parser("verify-receipt", help="verify an exported receipt bundle offline")
    sp.add_argument("bundle")
    sp.add_argument("--public-key", action="append", required=True,
                    help="file with the user's public key obtained independently of the gateway "
                         "(PEM, or base64url COSE/DER); repeatable")
    sp.add_argument("--rp-id", required=True, help="expected WebAuthn RP ID (e.g. gateway.example.com)")
    sp.add_argument("--origin", action="append", help="expected origin(s) (default: any origin valid for the RP ID)")
    sp.add_argument("--require-uv", action="store_true", help="fail unless the UV flag is set")
    sp.set_defaults(fn=cmd_verify_receipt)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.fn(args) or 0)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
