"""RFC 8785 JSON Canonicalization Scheme (JCS), implemented from the RFC.

Self-contained (no third-party dependency) so the gateway's digest does not
depend on an external package's behaviour. Tests cross-check the output
byte-for-byte against the ``rfc8785`` PyPI package when it is installed.

Rules implemented:
- objects: members sorted by the UTF-16 code units of their names;
- strings: shortest JSON escaping (only ``"``, ``\\``, and control characters
  < 0x20 are escaped; \\b \\t \\n \\f \\r use their short forms, others \\u00xx
  lowercase hex); everything else emitted as UTF-8;
- numbers: ECMAScript Number.prototype.toString serialisation of IEEE-754
  doubles; non-finite numbers are rejected; integers outside the I-JSON safe
  range (|n| > 2**53 - 1) are rejected rather than silently rounded;
- literals: true / false / null.
"""
from __future__ import annotations

import math
from typing import Any

MAX_SAFE_INT = 2**53 - 1


class CanonicalizationError(ValueError):
    """Raised when a value cannot be canonicalized (strictly)."""


_SHORT_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


def _encode_string(s: str) -> str:
    out = ['"']
    for ch in s:
        cp = ord(ch)
        if cp in _SHORT_ESCAPES:
            out.append(_SHORT_ESCAPES[cp])
        elif cp < 0x20:
            out.append("\\u%04x" % cp)
        elif 0xD800 <= cp <= 0xDFFF:
            # Lone surrogates cannot be encoded as UTF-8 (I-JSON forbids them).
            raise CanonicalizationError("lone surrogate in string")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _encode_number(x: Any) -> str:
    if isinstance(x, bool):  # pragma: no cover - guarded by caller
        raise CanonicalizationError("bool is not a number")
    if isinstance(x, int):
        if abs(x) > MAX_SAFE_INT:
            raise CanonicalizationError(f"integer {x} outside I-JSON safe range")
        return str(x)
    if not isinstance(x, float):
        raise CanonicalizationError(f"unsupported number type {type(x).__name__}")
    if not math.isfinite(x):
        raise CanonicalizationError("non-finite number")
    if x == 0:
        return "0"  # also covers -0.0
    # Python's repr gives the shortest round-tripping digits (same as ES).
    r = repr(x)
    sign = ""
    if r[0] == "-":
        sign, r = "-", r[1:]
    if "e" in r or "E" in r:
        mant, exp_s = r.lower().split("e")
        exp = int(exp_s)
    else:
        mant, exp = r, 0
    if "." in mant:
        int_part, frac_part = mant.split(".")
    else:
        int_part, frac_part = mant, ""
    if frac_part == "0":
        frac_part = ""
    digits = (int_part + frac_part).lstrip("0")
    # decimal exponent n such that value = 0.d1d2...dk * 10^n  (ES "n")
    lead_zeros = len(int_part + frac_part) - len((int_part + frac_part).lstrip("0"))
    n = len(int_part) + exp - lead_zeros
    digits = digits.rstrip("0")
    k = len(digits)
    if k <= n <= 21:
        s = digits + "0" * (n - k)
    elif 0 < n <= 21:
        s = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        s = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        es = ("+" if e >= 0 else "-") + str(abs(e))
        if k == 1:
            s = digits + "e" + es
        else:
            s = digits[0] + "." + digits[1:] + "e" + es
    return sign + s


def _utf16_key(s: str):
    try:
        return s.encode("utf-16-be")
    except UnicodeEncodeError:  # lone surrogate in an object key (CR-6)
        raise CanonicalizationError("lone surrogate in object key")


def _encode(value: Any, out: list) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, str):
        out.append(_encode_string(value))
    elif isinstance(value, (int, float)):
        out.append(_encode_number(value))
    elif isinstance(value, dict):
        for k in value:
            if not isinstance(k, str):
                raise CanonicalizationError("object keys must be strings")
            _encode_string(k)  # rejects lone surrogates before sorting (CR-6)
        out.append("{")
        first = True
        for k in sorted(value, key=_utf16_key):
            if not first:
                out.append(",")
            first = False
            out.append(_encode_string(k))
            out.append(":")
            _encode(value[k], out)
        out.append("}")
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _encode(item, out)
        out.append("]")
    else:
        raise CanonicalizationError(f"unsupported JSON type {type(value).__name__}")


def canonicalize(value: Any) -> bytes:
    """Return the RFC 8785 canonical UTF-8 encoding of ``value``."""
    out: list = []
    _encode(value, out)
    return "".join(out).encode("utf-8")


dumps = canonicalize
