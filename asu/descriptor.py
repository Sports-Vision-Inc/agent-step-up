"""Canonical effect descriptor (SPEC section 5, revised by D-005) and trusted
card rendering.

``canonicalize(tool, args, ctx)`` turns an agent's tool call into the
descriptor Delta; ``digest(desc)`` is ``SHA-256(JCS(Delta))`` as hex;
``render_card(desc)`` derives the human-visible card from Delta only (P4).

Descriptor v2 (D-005 item 4): every argument carries a TYPE, taken from the
tool's declared schema in the policy (``tools.<name>.args``) or, for tools
without a schema, inferred from the argument name (legacy heuristics; such
tools are flagged and always stepped up). The types are part of Delta
(``arg_types``) so the policy, grants, the card and an offline verifier all
read the same typing:

    recipient | account | amount | currency | path | url | argv | text |
    flag | int | enum   (D-005)   + env (exec environment) and json (verbatim
    structured value; alias of the legacy ``raw``). ``email`` is a legacy
    alias of ``recipient``.

At most one ``amount`` and one ``currency`` argument per call (amounts are
never summed). ``targets`` is the UNION of every recipient / account / url
host / path argument; ``target`` is that union joined by ",".

Normalisation is strict: anything ambiguous is rejected with
``CanonicalizationError`` rather than guessed (e.g. URL userinfo, display-name
email forms, ``~`` paths, locale-formatted amounts).
"""
from __future__ import annotations

import copy
import datetime as _dt
import hashlib
import ipaddress
import os
import posixpath
import re
import shlex
import socket
import unicodedata
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlsplit

from . import jcs
from .jcs import CanonicalizationError

DESCRIPTOR_VERSION = 2
EFFECT_CLASSES = ("read", "write", "delete", "send", "pay", "exec", "net", "admin")
ORIGINS = ("user_turn", "autonomous")

# D-005 item 4 types (+ env, json). Aliases are accepted in policies.
ARG_TYPES = ("recipient", "account", "amount", "currency", "path", "url", "argv", "text", "flag", "int",
             "enum", "env", "json")
TYPE_ALIASES = {"email": "recipient", "raw": "json"}
TARGET_TYPES = ("recipient", "account", "url", "path")
LIST_TYPES = ("recipient", "account", "path", "url")


class UnknownArgumentError(CanonicalizationError):
    """An argument that the tool's declared (closed) schema does not list."""

    def __init__(self, names: List[str]):
        self.names = list(names)
        super().__init__("unknown argument(s) for a typed tool: " + ", ".join(display(n) for n in names))


# Argument-name heuristics (matched case-insensitively), used ONLY for tools
# without a declared schema (flagged on the card and stepped up by policy).
PATH_KEYS = {
    "path", "paths", "file", "files", "file_path", "filepath", "filename",
    "src", "source", "dst", "dest", "destination", "dir", "directory",
    "target_path", "cwd", "workdir", "output", "output_path", "input_path",
}
URL_KEYS = {"url", "uri", "urls", "endpoint", "href", "webhook", "link", "callback_url"}
EMAIL_KEYS = {"to", "cc", "bcc", "recipient", "recipients", "email", "reply_to", "from", "sender"}
AMOUNT_KEYS = {"amount", "total", "price", "sum"}
CURRENCY_KEYS = {"currency"}
ARGV_KEYS = {"command", "cmd", "argv"}
ENV_KEYS = {"env", "environment"}
ACCOUNT_KEYS = {"payee", "account", "to_account", "iban", "account_id", "beneficiary", "recipient_account"}

_BIDI_AND_INVISIBLE = set(
    [0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2060, 0xFEFF, 0x00AD]
    + list(range(0x202A, 0x202F))
    + list(range(0x2066, 0x206A))
)
# Graphic characters that render as blank space (Lies-in-the-Loop padding,
# RT-5) or are invisible although their category is "printable".
_BLANK_GLYPHS = set(
    [0x2800, 0x3164, 0x115F, 0x1160, 0xFFA0, 0x17B4, 0x17B5, 0x034F, 0x1D159, 0x180E, 0x2062, 0x2063, 0x2064]
    + list(range(0xFE00, 0xFE10))          # variation selectors
    + list(range(0xE0100, 0xE01F0))        # variation selectors supplement
    + list(range(0x180B, 0x1810))          # Mongolian free variation selectors
)


def schema_entry(entry: Any) -> Dict[str, Any]:
    """Normalise one policy schema entry to ``{"type": t, ...options}``."""
    if isinstance(entry, str):
        entry = {"type": entry}
    if not isinstance(entry, dict) or not isinstance(entry.get("type"), str):
        raise CanonicalizationError("schema entries must be a type name or {type: ...}")
    out = dict(entry)
    t = TYPE_ALIASES.get(out["type"], out["type"])
    if t not in ARG_TYPES:
        raise CanonicalizationError(f"unknown arg type {entry['type']!r} in policy schema")
    out["type"] = t
    if t == "enum":
        vals = out.get("values")
        if not isinstance(vals, list) or not vals:
            raise CanonicalizationError("enum arguments need a non-empty 'values' list")
    return out


def normalize_schema(schema: Optional[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    out = {}
    for k, v in (schema or {}).items():
        if not isinstance(k, str) or not k:
            raise CanonicalizationError("schema argument names must be non-empty strings")
        out[k] = schema_entry(v)
    n_amount = sum(1 for e in out.values() if e["type"] == "amount")
    n_cur = sum(1 for e in out.values() if e["type"] == "currency")
    if n_amount > 1 or n_cur > 1:
        raise CanonicalizationError("a tool schema may declare at most one amount and one currency argument")
    return out


# ---------------------------------------------------------------------------
# primitive normalisers
# ---------------------------------------------------------------------------
def _require_str(v: Any, what: str) -> str:
    if not isinstance(v, str):
        raise CanonicalizationError(f"{what} must be a string")
    if "\x00" in v:
        raise CanonicalizationError(f"{what} contains NUL")
    return v


def normalize_path(value: Any, workspace_root: str, resolve_symlinks: bool = True) -> Dict[str, str]:
    """Return ``{"path": abs-normpath, "resolved_path": realpath}``.

    Relative paths are resolved against the (realpath of the) workspace root.
    ``path`` is the lexical normalisation (what a naive reader expects);
    ``resolved_path`` follows symlinks the way the kernel will (``..`` after a
    symlink is applied to the link target, not lexically).
    """
    s = _require_str(value, "path")
    if s == "":
        raise CanonicalizationError("empty path")
    if s.startswith("~"):
        raise CanonicalizationError("'~' paths are ambiguous; use an explicit path")
    root = os.path.realpath(workspace_root)
    joined = s if os.path.isabs(s) else os.path.join(root, s)
    norm = os.path.normpath(joined)
    if norm.startswith("//"):
        norm = "/" + norm.lstrip("/")
    if resolve_symlinks:
        resolved = os.path.realpath(joined)
    else:
        resolved = norm
    return {"path": norm, "resolved_path": resolved}


_UNRESERVED = re.compile(r"[A-Za-z0-9\-._~]")
_LEGACY_IPV4 = re.compile(r"^(0x[0-9a-f]+|[0-9]+)(\.(0x[0-9a-f]+|[0-9]+)){0,3}$")


def _normalize_pct(s: str) -> str:
    def repl(m: "re.Match[str]") -> str:
        ch = chr(int(m.group(1), 16))
        return ch if _UNRESERVED.fullmatch(ch) else "%" + m.group(1).upper()

    return re.sub(r"%([0-9A-Fa-f]{2})", repl, s)


def _remove_dot_segments(path: str) -> str:
    if path == "":
        return "/"
    trailing = path.endswith("/") or path.endswith("/.") or path.endswith("/..")
    p = posixpath.normpath(path)
    if p.startswith("//"):
        p = "/" + p.lstrip("/")
    if p == ".":
        p = "/"
    if not p.startswith("/"):
        p = "/" + p
    if trailing and not p.endswith("/"):
        p += "/"
    return p


def normalize_host(host: str) -> str:
    host = host.rstrip(".")
    if not host:
        raise CanonicalizationError("empty host")
    if "%" in host:
        raise CanonicalizationError("percent-encoded or zoned host not allowed")
    if ":" in host:  # IPv6 literal (urlsplit removed the brackets)
        try:
            return "[" + ipaddress.IPv6Address(host).compressed + "]"
        except ValueError as e:
            raise CanonicalizationError(f"bad IPv6 host: {e}")
    low = host.lower()
    if _LEGACY_IPV4.match(low):
        # decimal / hex / octal / short forms (http://2130706433/ == 127.0.0.1)
        try:
            return socket.inet_ntoa(socket.inet_aton(low))
        except OSError:
            raise CanonicalizationError(f"bad numeric host {host!r}")
    try:
        import idna

        return idna.encode(host, uts46=True).decode("ascii").lower()
    except Exception as e:  # idna.IDNAError, UnicodeError
        raise CanonicalizationError(f"bad host {host!r}: {e}")


_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}


def normalize_url(value: Any) -> str:
    """scheme://host:port/path[?query]; userinfo rejected; fragment dropped."""
    s = _require_str(value, "url")
    if any(ord(c) <= 0x20 or ord(c) == 0x7F for c in s) or "\\" in s:
        raise CanonicalizationError("url contains whitespace, control characters or backslashes")
    try:
        parts = urlsplit(s)
    except ValueError as e:
        raise CanonicalizationError(f"bad url: {e}")
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise CanonicalizationError(f"unsupported url scheme {parts.scheme!r}")
    if "@" in parts.netloc or parts.username is not None or parts.password is not None:
        raise CanonicalizationError("userinfo in url is not allowed")
    if parts.hostname is None:
        raise CanonicalizationError("url has no host")
    try:
        port = parts.port
    except ValueError as e:
        raise CanonicalizationError(f"bad port: {e}")
    # parts.hostname is lowercased already; idna for unicode
    raw_host = parts.netloc
    if raw_host.startswith("["):
        raw_host = raw_host[1:raw_host.index("]")]
    else:
        raw_host = raw_host.rsplit(":", 1)[0] if ":" in raw_host else raw_host
    host = normalize_host(raw_host)
    if port is None:
        port = _DEFAULT_PORTS[scheme]
    path = _remove_dot_segments(_normalize_pct(parts.path))
    out = f"{scheme}://{host}:{port}{path}"
    if parts.query:
        out += "?" + _normalize_pct(parts.query)
    return out


_LOCAL_OK = re.compile(r"^[a-z0-9!#$%&'*+/=?^_`{|}~.\-]+$")


def normalize_email(value: Any) -> str:
    s = _require_str(value, "email")
    if s != s.strip() or any(c.isspace() for c in s):
        raise CanonicalizationError("email contains whitespace")
    if any(c in s for c in '<>"(),;:[]\\'):
        raise CanonicalizationError("display-name / quoted / list email forms are not allowed")
    if s.count("@") != 1:
        raise CanonicalizationError("email must contain exactly one '@'")
    local, domain = s.split("@")
    local = local.lower()
    if not local or not _LOCAL_OK.match(local) or local.startswith(".") or local.endswith(".") or ".." in local:
        raise CanonicalizationError(f"bad email local part {local!r}")
    try:
        import idna

        dom = idna.encode(domain.rstrip("."), uts46=True).decode("ascii").lower()
    except Exception as e:
        raise CanonicalizationError(f"bad email domain {domain!r}: {e}")
    return f"{local}@{dom}"


_AMOUNT_RE = re.compile(r"^[+-]?(\d+(\.\d*)?|\.\d+)$")


def normalize_amount(value: Any) -> str:
    if isinstance(value, bool):
        raise CanonicalizationError("amount must be a number or decimal string")
    if isinstance(value, int):
        d = Decimal(value)
    elif isinstance(value, float):
        d = Decimal(repr(value))
    elif isinstance(value, str):
        if not _AMOUNT_RE.match(value):
            raise CanonicalizationError(f"amount {value!r} is not a plain decimal")
        d = Decimal(value)
    elif isinstance(value, Decimal):
        d = value
    else:
        raise CanonicalizationError("amount must be a number or decimal string")
    try:
        if not d.is_finite():
            raise CanonicalizationError("amount must be finite")
        d = d.normalize()
    except InvalidOperation as e:
        raise CanonicalizationError(f"bad amount: {e}")
    out = format(d, "f")
    if out in ("-0", "+0"):
        out = "0"
    return out


def normalize_currency(value: Any) -> str:
    s = _require_str(value, "currency")
    if not re.fullmatch(r"[A-Za-z]{3}", s):
        raise CanonicalizationError("currency must be a 3-letter ISO 4217 code")
    return s.upper()


def normalize_argv(value: Any) -> List[str]:
    if isinstance(value, str):
        _require_str(value, "command")
        # A string command is what a shell will interpret; record that honestly.
        return ["/bin/sh", "-c", value]
    if not isinstance(value, list) or not value:
        raise CanonicalizationError("command must be a non-empty argv list or string")
    return [_require_str(a, "argv element") for a in value]


def normalize_env(value: Any) -> Dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise CanonicalizationError("env must be an object")
    out = {}
    for k, v in value.items():
        _require_str(k, "env name")
        if not isinstance(v, (str, int, float)) or isinstance(v, bool):
            raise CanonicalizationError("env values must be strings")
        out[k] = v if isinstance(v, str) else str(v)
    return out


def _account(value: Any) -> str:
    s = _require_str(value, "account")
    s = unicodedata.normalize("NFC", s).strip()
    if not s:
        raise CanonicalizationError("empty account")
    return s




def normalize_recipient(value: Any) -> str:
    """A message/payment recipient: an email address if it contains '@'
    (normalised strictly), otherwise an opaque account / user id."""
    s = _require_str(value, "recipient")
    if "@" in s:
        return normalize_email(s)
    return _account(s)


# ---------------------------------------------------------------------------
# descriptor
# ---------------------------------------------------------------------------
def heuristic_type(key: str, value: Any, effect_class: str) -> str:
    """Legacy name-based typing, used only for tools without a declared schema."""
    k = key.lower()
    if k in PATH_KEYS:
        return "path"
    if k in URL_KEYS:
        return "url"
    if k in EMAIL_KEYS:
        return "recipient"
    if k in AMOUNT_KEYS:
        return "amount"
    if k in CURRENCY_KEYS:
        return "currency"
    if k in ACCOUNT_KEYS:
        return "account"
    if effect_class == "exec" and k in ARGV_KEYS:
        return "argv"
    if effect_class == "exec" and k in ENV_KEYS:
        return "env"
    return "json"


def _normalize_value(t: str, value: Any, ctx: Dict[str, Any], opts: Dict[str, Any]):
    many = isinstance(value, list) and t in LIST_TYPES
    vals = value if many else [value]

    def one(v):
        if t == "path":
            return normalize_path(v, ctx.get("workspace_root") or os.getcwd(), ctx.get("resolve_symlinks", True))
        if t == "url":
            return normalize_url(v)
        if t == "recipient":
            return normalize_recipient(v)
        if t == "account":
            return _account(v)
        if t == "amount":
            return normalize_amount(v)
        if t == "currency":
            return normalize_currency(v)
        if t == "argv":
            return normalize_argv(v)
        if t == "env":
            return normalize_env(v)
        if t == "text":
            s = _require_str(v, "text argument")
            ml = opts.get("max_len")
            if isinstance(ml, int) and len(s) > ml:
                raise CanonicalizationError(f"text argument longer than {ml} characters")
            return s
        if t == "flag":
            if not isinstance(v, bool):
                raise CanonicalizationError("flag argument must be true or false")
            return v
        if t == "int":
            if isinstance(v, bool) or not isinstance(v, int):
                raise CanonicalizationError("int argument must be an integer")
            return v
        if t == "enum":
            allowed = opts.get("values") or []
            if not any(jcs.canonicalize(v) == jcs.canonicalize(a) for a in allowed):
                raise CanonicalizationError("enum argument not one of the declared values")
            return copy.deepcopy(v)
        return copy.deepcopy(v)  # json

    out = [one(v) for v in vals]
    return out if many else out[0]


def _check_keys(args: Dict[str, Any]) -> None:
    seen: Dict[str, str] = {}
    for k in args:
        if not isinstance(k, str) or not k:
            raise CanonicalizationError("argument names must be non-empty strings")
        jcs._encode_string(k)  # lone surrogates -> CanonicalizationError (CR-6)
        if "\x00" in k:
            raise CanonicalizationError("argument name contains NUL")
        low = unicodedata.normalize("NFKC", k).lower()
        if low in seen:
            raise CanonicalizationError(f"ambiguous argument names {display(seen[low])!r} and {display(k)!r}")
        seen[low] = k


def _targets(args: Dict[str, Any], types: Dict[str, str]) -> List[str]:
    """UNION of every recipient / account / url-host / path argument (D-005
    item 4). ``cwd`` and argv[0] are used only when nothing else addresses
    the effect."""
    out: Set[str] = set()
    cwd: Set[str] = set()
    argv0: Set[str] = set()
    for k in sorted(args):
        t = types.get(k)
        v = args[k]
        vals = v if isinstance(v, list) and t in LIST_TYPES else [v]
        for x in vals:
            if t in ("recipient", "account") and isinstance(x, str):
                out.add(x)
            elif t == "url" and isinstance(x, str):
                out.add(urlsplit(x).netloc)
            elif t == "path" and isinstance(x, dict):
                (cwd if k.lower() in ("cwd", "workdir") else out).add(x["resolved_path"])
            elif t == "argv" and isinstance(x, list) and x:
                argv0.add(x[0])
    if not out:
        out = argv0 or cwd
    return sorted(out)


def canonicalize(tool: str, args: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    """Build the canonical effect descriptor Delta (SPEC section 5, v2).

    ``ctx`` keys: principal, session_id, agent_id, origin, issued_at,
    expires_at, effect_class, workspace_root, resolve_symlinks (default True),
    arg_types (the tool's schema ``{argname: type | {type, ...}}``) and
    arg_schema_closed (True when the policy declares the tool's schema: any
    argument outside it is rejected with ``UnknownArgumentError``).
    """
    _require_str(tool, "tool")
    if not re.fullmatch(r"[A-Za-z0-9_.:\-/]{1,128}", tool):
        raise CanonicalizationError("bad tool name")
    if args is None:
        args = {}
    if not isinstance(args, dict):
        raise CanonicalizationError("args must be an object")
    _check_keys(args)
    effect_class = ctx.get("effect_class") or "admin"
    if effect_class not in EFFECT_CLASSES:
        raise CanonicalizationError(f"unknown effect class {effect_class!r}")
    origin = ctx.get("origin", "autonomous")
    if origin not in ORIGINS:
        raise CanonicalizationError(f"bad origin {origin!r}")
    schema = normalize_schema(ctx.get("arg_types") or {})
    closed = bool(ctx.get("arg_schema_closed"))
    if closed:
        unknown = sorted(k for k in args if k not in schema)
        if unknown:
            raise UnknownArgumentError(unknown)
    types: Dict[str, str] = {}
    opts: Dict[str, Dict[str, Any]] = {}
    for k, v in args.items():
        if k in schema:
            types[k], opts[k] = schema[k]["type"], schema[k]
        else:
            types[k] = heuristic_type(k, v, effect_class)
            opts[k] = {"type": types[k]}
    if sum(1 for t in types.values() if t == "amount") > 1:
        raise CanonicalizationError("more than one amount argument (amounts are never summed)")
    if sum(1 for t in types.values() if t == "currency") > 1:
        raise CanonicalizationError("more than one currency argument")
    norm = {k: _normalize_value(types[k], v, ctx, opts[k]) for k, v in args.items()}
    tg = _targets(norm, types)
    desc = {
        "v": DESCRIPTOR_VERSION,
        "tool": tool,
        "effect_class": effect_class,
        "args": norm,
        "arg_types": {k: types[k] for k in sorted(types)},
        "schema": "declared" if closed else "inferred",
        "target": ",".join(tg) if tg else None,
        "targets": tg,
        "principal": ctx["principal"],
        "session_id": ctx["session_id"],
        "agent_id": ctx["agent_id"],
        "origin": origin,
        "issued_at": int(ctx["issued_at"]),
        "expires_at": int(ctx["expires_at"]),
    }
    jcs.canonicalize(desc)  # validates JSON-ability / I-JSON ranges
    return desc


def canonical_bytes(desc: Dict[str, Any]) -> bytes:
    return jcs.canonicalize(desc)


def digest(desc: Dict[str, Any]) -> str:
    """h = SHA-256(JCS(desc)) as lowercase hex."""
    return hashlib.sha256(jcs.canonicalize(desc)).hexdigest()


def effect_key(desc: Dict[str, Any]) -> str:
    """Digest of the descriptor without its timestamps: identifies 'the same
    effect' for de-duplication of pending approvals (P7)."""
    d = {k: v for k, v in desc.items() if k not in ("issued_at", "expires_at")}
    return hashlib.sha256(jcs.canonicalize(d)).hexdigest()


# ---------------------------------------------------------------------------
# typed views used by policy / grants / rendering
# ---------------------------------------------------------------------------
def _is_path_item(x: Any) -> bool:
    return isinstance(x, dict) and set(x) == {"path", "resolved_path"}


def types_of(desc: Dict[str, Any]) -> Dict[str, str]:
    """Argument types of a descriptor (``arg_types``; inferred for legacy v1
    descriptors that predate typed descriptors)."""
    args = desc.get("args", {}) or {}
    t = desc.get("arg_types")
    if isinstance(t, dict):
        return {k: t.get(k, "json") for k in args}
    out = {}
    for k, v in args.items():
        if _is_path_item(v) or (isinstance(v, list) and v and all(_is_path_item(x) for x in v)):
            out[k] = "path"
        else:
            ht = heuristic_type(k, v, desc.get("effect_class", "admin"))
            out[k] = "json" if ht == "path" else ht
    return out


def targets_of(desc: Dict[str, Any]) -> List[str]:
    tg = desc.get("targets")
    if isinstance(tg, list):
        return [x for x in tg if isinstance(x, str)]
    t = desc.get("target")
    return [x for x in t.split(",") if x] if isinstance(t, str) and t else []


def _values(desc: Dict[str, Any], wanted: Tuple[str, ...]) -> Iterable[Tuple[str, Any]]:
    args = desc.get("args", {}) or {}
    for k, t in sorted(types_of(desc).items()):
        if t in wanted and k in args:
            v = args[k]
            for x in (v if isinstance(v, list) and t in LIST_TYPES else [v]):
                yield k, x


def iter_paths(desc: Dict[str, Any]) -> Iterable[Dict[str, str]]:
    for _k, x in _values(desc, ("path",)):
        if _is_path_item(x):
            yield x


def iter_urls(desc: Dict[str, Any]) -> Iterable[str]:
    for _k, x in _values(desc, ("url",)):
        if isinstance(x, str):
            yield x


def recipients(desc: Dict[str, Any]) -> List[str]:
    """Every recipient / payee of a send or pay effect: the UNION of all
    recipient- and account-typed arguments (D-005 item 4)."""
    if desc.get("effect_class") not in ("send", "pay"):
        return []
    out = sorted({x for _k, x in _values(desc, ("recipient", "account")) if isinstance(x, str)})
    if not out and "arg_types" not in desc:
        out = targets_of(desc)
    return out


def amount_of(desc: Dict[str, Any]) -> Tuple[Optional[Decimal], Optional[str]]:
    """The call's single amount argument and its currency. Never sums several
    amount-like arguments (RT-1); canonicalize() rejects more than one."""
    amounts: List[Decimal] = []
    currency = None
    for _k, x in _values(desc, ("amount",)):
        if isinstance(x, str) and _AMOUNT_RE.match(x):
            amounts.append(Decimal(x))
    for _k, x in _values(desc, ("currency",)):
        if isinstance(x, str):
            currency = x
    if not amounts:
        return None, currency
    # Legacy descriptors only: several amount keys -> the largest magnitude
    # (conservative), never their sum.
    return max(amounts, key=abs), currency


def argv_of(desc: Dict[str, Any]) -> Optional[List[str]]:
    for _k, x in _values(desc, ("argv",)):
        if isinstance(x, list) and all(isinstance(a, str) for a in x):
            return x
    return None


INTERPRETERS = {
    "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish", "csh", "tcsh", "busybox", "python", "pypy",
    "node", "nodejs", "deno", "bun", "perl", "ruby", "pwsh", "powershell", "php", "lua", "osascript", "cmd",
    "tclsh", "awk", "gawk",
}
_WRAPPERS = {"env", "sudo", "doas", "nice", "nohup", "exec", "command", "time", "timeout", "stdbuf", "xargs",
             "ionice", "chroot", "setsid"}
_CODE_FLAGS = {"-c", "-e", "-E", "-p", "-r", "--eval", "--command", "-command", "-encodedcommand", "-enc",
               "-ec", "/c", "/k", "--exec", "-x"}


def interpreter_use(argv: List[str]) -> Optional[Tuple[str, str]]:
    """``(interpreter, flag)`` if argv runs inline code through a shell or
    interpreter (``bash -c``, ``python -c``, ``node -e``, ``pwsh -Command``...)."""
    # skip wrappers (env, sudo, timeout ...) with their options, option
    # values and VAR=value assignments
    i = 0
    if i < len(argv) and posixpath.basename(argv[i]).lower() in _WRAPPERS:
        while i < len(argv):
            a = argv[i]
            b = posixpath.basename(a).lower()
            if b in _WRAPPERS or "=" in a or a.isdigit() or re.fullmatch(r"\d+[smhd]?", a):
                i += 1
            elif a.startswith("-"):
                i += 1
                # an option followed by a separate value (sudo -u root)
                if i < len(argv) and not argv[i].startswith("-") and len(a) == 2 and a[1] in "ugCDhprtTU":
                    i += 1
            else:
                break
    if i >= len(argv):
        return None
    base = posixpath.basename(argv[i].replace("\\", "/")).lower()
    if base.endswith(".exe"):
        base = base[:-4]
    name = re.sub(r"[0-9.\-]+$", "", base)
    if name not in INTERPRETERS:
        return None
    for a in argv[i + 1:]:
        al = a.lower()
        if al in _CODE_FLAGS or (re.fullmatch(r"-[a-z]{0,3}[ce][a-z]{0,3}", al) and len(a) <= 5):
            return name, a
        if name in ("awk", "gawk") and not a.startswith("-"):
            return name, a  # awk's first operand is a program
    return None


# ---------------------------------------------------------------------------
# trusted rendering (P4, D-005 item 6)
# ---------------------------------------------------------------------------
TITLE_MAX = 140
FIELD_MAX = 240
LABEL_MAX = 64
RUN_MIN_BLANK = 4    # runs of whitespace / blank glyphs at least this long are collapsed
RUN_MIN_OTHER = 16   # runs of any other repeated character


def _printable(ch: str, marks_before: int) -> bool:
    cp = ord(ch)
    if cp in _BLANK_GLYPHS or cp in _BIDI_AND_INVISIBLE:
        return False
    cat = unicodedata.category(ch)
    if cat[0] in "LNPS":
        return True
    if cat[0] == "M":
        return marks_before < 2  # stacked combining marks ("zalgo") are escaped
    return False


def _blankish(ch: str) -> bool:
    cp = ord(ch)
    return (ch.isspace() or cp in _BLANK_GLYPHS or cp in _BIDI_AND_INVISIBLE
            or unicodedata.category(ch) in ("Cf", "Zs", "Zl", "Zp"))


def _tokens(s: str, quote: bool = True) -> List[Tuple[str, str]]:
    toks: List[Tuple[str, str]] = []
    marks = 0
    for ch in s:
        if ch == "\\" and quote:
            tok = ("\\\\", "plain")
        elif ch == '"' and quote:
            tok = ('\\"', "plain")
        elif ch == "\n":
            tok = ("\\n", "ws")
        elif ch == "\t":
            tok = ("\\t", "ws")
        elif ch == " ":
            tok = (" ", "ws")
        elif _printable(ch, marks):
            tok = (ch, "plain")
        else:
            tok = ("\\u{%04X}" % ord(ch), "blank" if _blankish(ch) else "hidden")
        marks = marks + 1 if unicodedata.category(ch)[0] == "M" else 0
        toks.append(tok)
    return toks


def _tok_name(tok: str) -> str:
    if tok == " ":
        return "space"
    if tok.startswith("\\u{"):
        return "U+" + tok[3:-1]
    return '"' + tok + '"'


def _esc(s: str, info: Optional[Set[str]] = None, quote: bool = True) -> str:
    """Injective human rendering of a string (without the surrounding quotes):

    * ``\\`` and ``"`` are escaped; newline / tab render as ``\\n`` / ``\\t``;
    * every character outside a printable allow-list (controls, format and
      bidi characters, unassigned / private code points, whitespace other
      than the ASCII space, blank-rendering glyphs such as U+2800 or U+3164,
      stacked combining marks) is shown as ``\\u{XXXX}``;
    * a run of N >= 4 identical whitespace / blank tokens (or N >= 16 of any
      other token) is shown as ``\\[N× name]``.
    The output can be decoded back to the input, so distinct strings never
    render the same."""
    info = info if info is not None else set()
    toks = _tokens(s, quote)
    out: List[str] = []
    i = 0
    while i < len(toks):
        j = i
        while j < len(toks) and toks[j][0] == toks[i][0]:
            j += 1
        tok, kind = toks[i]
        n = j - i
        thr = RUN_MIN_BLANK if kind in ("ws", "blank") else RUN_MIN_OTHER
        if n >= thr:
            out.append("\\[%d\u00d7 %s]" % (n, _tok_name(tok)))
            info.add("collapsed")
        else:
            out.append(tok * n)
        if kind in ("hidden", "blank"):
            info.add("escaped")
        i = j
    return "".join(out)


def display(s: Any) -> str:
    """Escaped rendering of a value for humans (strings without quotes;
    ``\\`` and ``"`` are left as they are -- use the card's typed fields for
    an injective rendering)."""
    if not isinstance(s, str):
        s = jcs.canonicalize(s).decode("utf-8")
    return _esc(s, quote=False)


def _lit(v: Any, info: Set[str], t: Optional[str] = None) -> str:
    """Typed literal: strings are quoted, numbers / booleans / null are bare
    JSON literals, lists and objects keep their structure, so values of
    different JSON types never render alike (D-005 item 6)."""
    if t == "path":
        if isinstance(v, list):
            return "[" + ", ".join(_lit(x, info, "path") for x in v) + "]"
        if _is_path_item(v):
            s = '"%s"' % _esc(v["path"], info)
            if v["resolved_path"] != v["path"]:
                s += ' \u2192 resolves to "%s"' % _esc(v["resolved_path"], info)
            return s
    if isinstance(v, str):
        return '"%s"' % _esc(v, info)
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, (int, float)):
        return jcs.canonicalize(v).decode("ascii")
    if isinstance(v, (list, tuple)):
        return "[" + ", ".join(_lit(x, info, t if t in LIST_TYPES else None) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ", ".join('"%s": %s' % (_esc(k, info), _lit(v[k], info)) for k in sorted(v)) + "}"
    return '"%s"' % _esc(str(v), info)


def _capped(text: str, limit: int, info: Set[str]) -> Dict[str, Any]:
    if len(text) <= limit:
        return {"value": text}
    info.add("truncated")
    return {"value": text[:limit] + " \u2026 [+%d more characters \u2014 expand to read all]" % (len(text) - limit),
            "truncated": True, "full": text, "length": len(text)}


def _unicode_of_idn(host: str) -> Optional[str]:
    if "xn--" not in host:
        return None
    try:
        import idna

        return idna.decode(host)
    except Exception:
        return None


def _quoted_targets(desc: Dict[str, Any], info: Set[str]) -> str:
    tg = targets_of(desc)
    return ", ".join('"%s"' % _esc(t, info) for t in tg) if tg else "(no target)"


def _title(desc: Dict[str, Any], info: Set[str]) -> str:
    cls = desc.get("effect_class")
    tool = _esc(str(desc.get("tool")), info)
    t = _quoted_targets(desc, info)
    if cls == "pay":
        amount, cur = amount_of(desc)
        amt = f"{amount} {cur or ''}".strip() if amount is not None else "(no amount)"
        return f"PAY {_esc(amt, info)} to {t} [{tool}]"
    if cls == "send":
        return f"SEND to {t} [{tool}]"
    if cls == "delete":
        return f"DELETE {t} [{tool}]"
    if cls == "exec":
        argv = argv_of(desc)
        cmd = _esc(shlex.join(argv), info) if argv else t
        return f"RUN {cmd} [{tool}]"
    if cls == "net":
        return f"NETWORK request to {t} [{tool}]"
    if cls == "write":
        return f"WRITE {t} [{tool}]"
    if cls == "admin":
        return f"ADMIN {tool} on {t}"
    return f"READ {t} [{tool}]"


def risk_lines_for(desc: Dict[str, Any], workspace_root: Optional[str] = None) -> List[str]:
    lines: List[str] = []
    info: Set[str] = set()
    cls = desc.get("effect_class")
    if cls in ("delete", "pay", "admin", "exec"):
        lines.append(f"Destructive/high-impact action class: {cls}")
    if desc.get("origin") == "autonomous":
        lines.append("No user turn: the agent started this on its own (autonomous origin)")
    if desc.get("schema") == "inferred" or "arg_types" not in desc:
        lines.append("This tool has no declared argument schema: argument meanings were guessed from their names")
    amount, cur = amount_of(desc)
    if amount is not None:
        lines.append(f"Moves money: {_esc(str(amount), info)} {cur or '(no currency)'}")
    rc = recipients(desc)
    if len(rc) > 1:
        lines.append(f"{len(rc)} recipients/payees: " + ", ".join('"%s"' % _esc(r, info) for r in rc))
    root = os.path.realpath(workspace_root) if workspace_root else None
    for p in iter_paths(desc):
        if p["path"] != p["resolved_path"]:
            lines.append(f"Path \"{_esc(p['path'], info)}\" actually resolves to \"{_esc(p['resolved_path'], info)}\"")
        if root and not (p["resolved_path"] == root or p["resolved_path"].startswith(root.rstrip("/") + "/")):
            lines.append(f"Outside the workspace: \"{_esc(p['resolved_path'], info)}\"")
    for u in iter_urls(desc):
        sp = urlsplit(u)
        host = sp.hostname or ""
        uni = _unicode_of_idn(host)
        if uni:
            lines.append(f"Internationalised domain {host} is displayed by browsers as '{_esc(uni, info)}'")
        try:
            ipaddress.ip_address(host.strip("[]"))
            lines.append(f"Destination is a raw IP address: {host}")
        except ValueError:
            pass
        if sp.port not in (80, 443):
            lines.append(f"Non-standard port {sp.port}")
    for r in rc:
        if "@" in r:
            uni = _unicode_of_idn(r.split("@", 1)[1])
            if uni:
                lines.append(f"Recipient domain {r.split('@', 1)[1]} is displayed as '{_esc(uni, info)}'")
    for k, x in _values(desc, ("argv",)):
        if isinstance(x, list):
            iu = interpreter_use(x)
            if iu:
                lines.append(f"Runs inline code through a shell/interpreter ({_esc(iu[0], info)} "
                             f"{_esc(iu[1], info)}): the argument after it is a program - read it in full")
    for k, x in _values(desc, ("env",)):
        if isinstance(x, dict) and x:
            lines.append("Sets environment variables: " + ", ".join(_esc(n, info) for n in sorted(x)))
    return lines


def _fmt_time(ts: int) -> str:
    return _dt.datetime.fromtimestamp(int(ts), tz=_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


INFO_LINES = {
    "escaped": "Arguments contain invisible, blank, bidi or control characters (shown escaped as \\u{...})",
    "collapsed": "Arguments contain long runs of blank or repeated characters (padding; shown collapsed as \\[N\u00d7 ...])",
    "truncated": "Some values are long and are shortened on this card; expand them to read them in full",
}


def render_card(desc: Dict[str, Any], reasons: Optional[List[str]] = None,
                explanation: Optional[str] = None, workspace_root: Optional[str] = None) -> Dict[str, Any]:
    """Card for the authenticator page, derived ONLY from the descriptor
    (plus gateway policy reasons). Gateway labels ("Tool", "Target", ...) are
    fixed strings; agent-chosen argument NAMES appear only in the separate
    ``arguments`` section with the fixed prefix ``arg.``. Agent text, if
    given, is placed in a separately labelled, collapsed-by-default untrusted
    box and never in title/fields/risk_lines."""
    info: Set[str] = set()
    types = types_of(desc)

    def row(label: str, text: str, section: str = "effect", **extra: Any) -> Dict[str, Any]:
        r = {"label": label, "section": section}
        r.update(_capped(text, FIELD_MAX, info))
        r.update(extra)
        return r

    fields = [row("Tool", _esc(str(desc.get("tool")), info)),
              row("Effect class", str(desc.get("effect_class"))),
              row("Target", _quoted_targets(desc, info) if targets_of(desc) else "(none)")]
    arguments = []
    for k in sorted(desc.get("args", {})):
        t = types.get(k, "json")
        name = _esc(k, info)
        lab = _capped("arg." + name, LABEL_MAX, info)
        r = row(lab["value"], _lit(desc["args"][k], info, t), "arguments", type=t)
        if lab.get("truncated"):
            r["label_full"] = lab["full"]
        arguments.append(r)
    fields += arguments
    fields += [
        row("On behalf of", _esc(str(desc.get("principal")), info)),
        row("Agent", _esc(str(desc.get("agent_id")), info)),
        row("Session", _esc(str(desc.get("session_id")), info)),
        row("Origin", f"{desc.get('origin')} (asserted by the agent, not verified)"),
        row("Expires", f"{_fmt_time(desc.get('expires_at', 0))} (requested {_fmt_time(desc.get('issued_at', 0))})"),
    ]
    title = _title(desc, info)
    title_cut = len(title) > TITLE_MAX
    if title_cut:
        title = title[:TITLE_MAX] + " \u2026"
    risk = risk_lines_for(desc, workspace_root)
    for k in ("escaped", "collapsed", "truncated"):
        if k in info:
            risk.append(INFO_LINES[k])
    if title_cut:
        risk.append("The title is shortened; the full effect is in the fields below")
    for r in reasons or []:
        line = f"Policy: {_esc(str(r), quote=False)}"
        if line not in risk:
            risk.append(line)
    card = {
        "card_version": 2,
        "title": title,
        "effect_class": desc.get("effect_class"),
        "risk_lines": risk,
        "fields": fields,
        "digest": digest(desc),
        "trusted": True,
    }
    if explanation:
        card["agent_explanation_untrusted"] = {
            "label": "Agent's explanation (UNTRUSTED - written by the agent, may be false)",
            "text": _esc(explanation, quote=False),
            "collapsed": True,
        }
    return card


def render_narrated_card(desc: Dict[str, Any], explanation: Optional[str]) -> Dict[str, Any]:
    """BASELINE `narrated-card` (P4 deliberately violated): the card text is the
    agent's own narration; the descriptor is not shown."""
    text = explanation or "(the agent did not describe this action)"
    return {
        "title": text[:200],
        "effect_class": desc.get("effect_class"),
        "risk_lines": [],
        "fields": [{"label": "Description", "value": text}],
        "digest": digest(desc),
        "trusted": False,
    }
