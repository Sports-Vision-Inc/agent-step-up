"""RED TEAM (crypto lens): differential test of asu.jcs against the rfc8785
reference package on randomized JSON (random IEEE-754 bit patterns, astral /
BMP-high keys to exercise UTF-16 code-unit ordering, nesting). This PASSES
today; it is kept as a regression guard."""
from __future__ import annotations

import math
import random
import struct

import pytest

rfc8785 = pytest.importorskip("rfc8785")
from asu import jcs  # noqa: E402


def _gen(R):
    def rfloat():
        c = R.random()
        if c < 0.5:
            while True:
                x = struct.unpack("<d", struct.pack("<Q", R.getrandbits(64)))[0]
                if math.isfinite(x):
                    return x
        if c < 0.75:
            return R.uniform(-1e6, 1e6)
        return R.choice([1e21, 1e-7, 1e-6, 9.999999999999999e20, 5e-324, 1.7976931348623157e308,
                         0.1, 100.0, -0.0, 1e22, 4.35, float(2**53), float(2**60)])

    def rstr():
        out = []
        for _ in range(R.randint(0, 6)):
            c = R.random()
            if c < 0.3:
                out.append(chr(R.randint(0, 0x7F)))
            elif c < 0.5:
                out.append(chr(R.randint(0x80, 0xD7FF)))
            elif c < 0.7:
                out.append(chr(R.randint(0xE000, 0xFFFF)))
            else:
                out.append(chr(R.randint(0x10000, 0x10FFFF)))
        return "".join(out)

    def rval(d=0):
        c = R.random()
        if d > 3 or c < 0.15:
            return R.choice([None, True, False])
        if c < 0.35:
            return rfloat()
        if c < 0.45:
            return R.randint(-(2**53) + 1, 2**53 - 1)
        if c < 0.65:
            return rstr()
        if c < 0.8:
            return [rval(d + 1) for _ in range(R.randint(0, 4))]
        return {rstr(): rval(d + 1) for _ in range(R.randint(0, 5))}

    return rval


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_jcs_matches_rfc8785_reference(seed):
    rval = _gen(random.Random(seed))
    for _ in range(5000):
        v = rval()
        assert jcs.canonicalize(v) == rfc8785.dumps(v), repr(v)[:200]


@pytest.mark.parametrize("bad", [{"a": "\ud800"}, 2**53, -(2**53), {"a": float("nan")}, {"a": float("inf")}])
def test_jcs_rejects_like_reference(bad):
    with pytest.raises(ValueError):
        jcs.canonicalize(bad)
    with pytest.raises(Exception):
        rfc8785.dumps(bad)
