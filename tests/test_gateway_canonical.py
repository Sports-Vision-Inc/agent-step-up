"""JCS (RFC 8785) and descriptor normalisation, incl. A10 canonicalization tricks."""
from __future__ import annotations

import json
import math
import os
import random
import struct

import pytest

from asu import jcs
from asu.descriptor import (canonicalize, digest, effect_key, normalize_amount, normalize_email, normalize_path,
                            normalize_url, render_card, render_narrated_card)
from asu.jcs import CanonicalizationError


# --------------------------------------------------------------------- JCS
def test_jcs_rfc8785_example():
    # RFC 8785 section 3.2.2 / 3.2.3 sample
    data = json.loads('{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],'
                      '"string": "\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/",'
                      '"literals": [null, true, false]}')
    out = jcs.canonicalize(data)
    assert out == ('{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
                   '"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}').encode("utf-8")


def test_jcs_key_order_is_utf16():
    # U+1F600 (surrogates D83D..) sorts before U+FB01 in UTF-16, after in code points
    out = jcs.canonicalize({"ﬁ": 1, "\U0001F600": 2, "a": 3, "B": 4})
    assert out.decode() == '{"B":4,"a":3,"\U0001F600":2,"ﬁ":1}'


@pytest.mark.parametrize("v,s", [(1e21, "1e+21"), (1e-7, "1e-7"), (1e20, "100000000000000000000"),
                                 (1.5e-6, "0.0000015"), (-0.0, "0"), (0.1, "0.1"), (5e-324, "5e-324"),
                                 (123456789012345680000.0, "123456789012345680000"), (100.0, "100"), (-1, "-1")])
def test_jcs_numbers(v, s):
    assert jcs.canonicalize(v).decode() == s


def test_jcs_rejects_bad_values():
    for bad in (float("nan"), float("inf"), 2**53, -(2**53), {1: "x"}, "\ud800", object()):
        with pytest.raises(CanonicalizationError):
            jcs.canonicalize(bad)
    assert jcs.canonicalize(2**53 - 1) == b"9007199254740991"


def test_jcs_matches_rfc8785_package():
    rfc8785 = pytest.importorskip("rfc8785")
    rng = random.Random(1234)
    vals = []
    for _ in range(20000):
        v = struct.unpack("<d", rng.getrandbits(64).to_bytes(8, "little"))[0]
        if math.isfinite(v):
            vals.append(v)
        vals.append(rng.random() * 10 ** rng.randint(-25, 25) * rng.choice([1, -1]))
    for v in vals:
        assert jcs.canonicalize(v) == rfc8785.dumps(v), v
    obj = {"z": [1, 2.5, None, True, {"y": "\u0007 \"\\"}], "a": "é", "\U0001F600": {}}
    assert jcs.canonicalize(obj) == rfc8785.dumps(obj)


# --------------------------------------------------------------- descriptor
def ctx(ws, **kw):
    c = {"principal": "alice", "session_id": "ses_1", "agent_id": "agent-1", "origin": "user_turn",
         "issued_at": 1000, "expires_at": 1300, "effect_class": "write", "workspace_root": ws}
    c.update(kw)
    return c


def test_descriptor_shape_and_explanation_excluded(tmp_path):
    d = canonicalize("write_file", {"path": "a.txt", "content": "hi"}, ctx(str(tmp_path)))
    # descriptor v2 (D-005 item 4): typed arguments + union of targets
    assert set(d) == {"v", "tool", "effect_class", "args", "arg_types", "schema", "target", "targets", "principal",
                      "session_id", "agent_id", "origin", "issued_at", "expires_at"}
    assert d["v"] == 2
    assert d["arg_types"] == {"content": "json", "path": "path"} and d["schema"] == "inferred"
    assert "explanation" not in json.dumps(d)
    assert len(digest(d)) == 64


def test_path_relative_dotdot_and_symlink(tmp_path):
    ws = tmp_path / "ws"
    (ws / "sub").mkdir(parents=True)
    root = os.path.realpath(str(ws))
    p = normalize_path("sub/../x.txt", str(ws))
    assert p == {"path": root + "/x.txt", "resolved_path": root + "/x.txt"}
    # equivalent spellings produce the same descriptor digest
    d1 = canonicalize("write_file", {"path": "x.txt"}, ctx(str(ws)))
    d2 = canonicalize("write_file", {"path": "./sub/../x.txt"}, ctx(str(ws)))
    d3 = canonicalize("write_file", {"path": root + "//x.txt"}, ctx(str(ws)))
    assert digest(d1) == digest(d2) == digest(d3)
    # symlink: lexical path inside workspace, resolved path outside (GhostApproval-style)
    secret = tmp_path / "secret.txt"
    secret.write_text("s")
    os.symlink(str(secret), str(ws / "innocent.txt"))
    p = normalize_path("innocent.txt", str(ws))
    assert p["path"] == root + "/innocent.txt"
    assert p["resolved_path"] == os.path.realpath(str(secret))
    d = canonicalize("write_file", {"path": "innocent.txt"}, ctx(str(ws)))
    assert d["target"] == os.path.realpath(str(secret))
    card = render_card(d, workspace_root=str(ws))
    assert any("actually resolves to" in r for r in card["risk_lines"])
    assert any("Outside the workspace" in r for r in card["risk_lines"])


def test_symlink_then_dotdot_follows_kernel_semantics(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    deep = tmp_path / "a" / "b"
    deep.mkdir(parents=True)
    os.symlink(str(deep), str(ws / "link"))
    p = normalize_path("link/../target", str(ws))
    assert p["path"] == os.path.realpath(str(ws)) + "/target"          # lexical
    assert p["resolved_path"] == os.path.realpath(str(tmp_path / "a")) + "/target"  # kernel


def test_path_rejections(tmp_path):
    for bad in ("~/x", "", "a\x00b", 5):
        with pytest.raises(CanonicalizationError):
            normalize_path(bad, str(tmp_path))


@pytest.mark.parametrize("raw,canon", [
    ("https://Example.COM/a/./b/../c", "https://example.com:443/a/c"),
    ("https://example.com", "https://example.com:443/"),
    ("https://example.com:443/x#frag", "https://example.com:443/x"),
    ("HTTP://example.com.:80/%7Euser/%2e%2e/x", "http://example.com:80/x"),
    ("https://example.com/p?b=2&a=1", "https://example.com:443/p?b=2&a=1"),
    ("http://2130706433/", "http://127.0.0.1:80/"),
    ("http://0x7f.1/", "http://127.0.0.1:80/"),
    ("http://[::FFFF:7f00:1]:8080/x", "http://[::ffff:127.0.0.1]:8080/x"),
    ("https://bücher.example/", "https://xn--bcher-kva.example:443/"),
])
def test_url_normalization(raw, canon):
    assert normalize_url(raw) == canon


@pytest.mark.parametrize("bad", [
    "https://user:pw@example.com/", "https://trusted.com@evil.com/", "https://trusted.com\\@evil.com/",
    "file:///etc/passwd", "javascript:alert(1)", "https:///nohost", " https://example.com", "https://ex ample.com",
    "https://example.com:99999/", "https://exa%6dple.com/",
])
def test_url_rejections(bad):
    with pytest.raises(CanonicalizationError):
        normalize_url(bad)


def test_host_suffix_and_homograph_are_distinct(tmp_path):
    c = ctx(str(tmp_path), effect_class="net")
    a = canonicalize("http_request", {"url": "https://apple.com/"}, c)
    h = canonicalize("http_request", {"url": "https://аpple.com/"}, c)  # Cyrillic a
    s = canonicalize("http_request", {"url": "https://apple.com.evil.example/"}, c)
    assert len({digest(a), digest(h), digest(s)}) == 3
    assert h["target"].startswith("xn--")
    assert s["target"] == "apple.com.evil.example:443"
    card = render_card(h)
    assert any("displayed by browsers" in r for r in card["risk_lines"])


def test_email_normalization():
    assert normalize_email("Bob@Example.COM") == "bob@example.com"
    assert normalize_email("bob@bücher.example") == "bob@xn--bcher-kva.example"
    for bad in ("Bob <bob@x.com>", "a@b@c.com", "bob", " bob@x.com", '"a@b"@x.com', "a..b@x.com", "bob@x.com,eve@y.com"):
        with pytest.raises(CanonicalizationError):
            normalize_email(bad)


def test_amounts_and_currency(tmp_path):
    assert normalize_amount("100.00") == "100"
    assert normalize_amount(100) == "100"
    assert normalize_amount(0.1) == "0.1"
    assert normalize_amount("-0.00") == "0"
    assert normalize_amount("0.50") == "0.5"
    for bad in ("1,000", "$100", "1e3", "NaN", "Infinity", True, None, float("nan"), " 1"):
        with pytest.raises(CanonicalizationError):
            normalize_amount(bad)
    c = ctx(str(tmp_path), effect_class="pay")
    d1 = canonicalize("transfer_money", {"amount": "100.00", "currency": "usd", "payee": "ACME"}, c)
    d2 = canonicalize("transfer_money", {"amount": 100, "currency": "USD", "payee": "ACME"}, c)
    assert digest(d1) == digest(d2)
    assert d1["args"]["currency"] == "USD" and d1["target"] == "ACME"
    with pytest.raises(CanonicalizationError):
        canonicalize("transfer_money", {"amount": 1, "currency": "US"}, c)


def test_shell_argv_env_cwd(tmp_path):
    c = ctx(str(tmp_path), effect_class="exec")
    d = canonicalize("run_shell", {"command": ["rm", "-rf", "build"], "env": {"B": "2", "A": 1}, "cwd": "."}, c)
    assert d["args"]["command"] == ["rm", "-rf", "build"]
    assert d["args"]["env"] == {"A": "1", "B": "2"}
    assert d["args"]["cwd"]["path"] == os.path.realpath(str(tmp_path))
    s = canonicalize("run_shell", {"command": "rm -rf / ; echo ok"}, c)
    assert s["args"]["command"] == ["/bin/sh", "-c", "rm -rf / ; echo ok"]
    assert any("shell" in r for r in render_card(s)["risk_lines"])
    # argv list vs. joined string are different effects
    j = canonicalize("run_shell", {"command": "rm -rf build"}, c)
    assert digest(j) != digest(d)


def test_unknown_args_kept_verbatim_and_case_collisions_rejected(tmp_path):
    c = ctx(str(tmp_path))
    d = canonicalize("write_file", {"path": "a", "mode": 0o644, "extra": {"nested": [1, "x"]}}, c)
    assert d["args"]["mode"] == 420 and d["args"]["extra"] == {"nested": [1, "x"]}
    with pytest.raises(CanonicalizationError):
        canonicalize("write_file", {"path": "a", "Path": "/etc/passwd"}, c)
    with pytest.raises(CanonicalizationError):
        canonicalize("write_file", {"path": "a", "big": 2**60}, c)


def test_heuristic_key_case_insensitive(tmp_path):
    c = ctx(str(tmp_path))
    d = canonicalize("write_file", {"FILE": "../" * 40 + "etc/passwd"}, c)
    assert d["args"]["FILE"]["resolved_path"] == "/etc/passwd"


def test_effect_key_ignores_timestamps(tmp_path):
    a = canonicalize("write_file", {"path": "a"}, ctx(str(tmp_path), issued_at=1, expires_at=2))
    b = canonicalize("write_file", {"path": "a"}, ctx(str(tmp_path), issued_at=5, expires_at=9))
    assert digest(a) != digest(b) and effect_key(a) == effect_key(b)


def test_card_trusted_rendering(tmp_path):
    c = ctx(str(tmp_path), effect_class="send")
    d = canonicalize("send_email", {"to": "eve@evil.example", "subject": "hi‮gnp.exe", "body": "x"}, c)
    card = render_card(d, reasons=["first_time_recipient:eve@evil.example"],
                       explanation="Sending the weekly report to your boss bob@corp.example")
    flat = json.dumps({k: v for k, v in card.items() if k != "agent_explanation_untrusted"})
    assert "bob@corp.example" not in flat              # agent text never in trusted fields
    assert "eve@evil.example" in card["title"]
    assert card["agent_explanation_untrusted"]["label"].startswith("Agent's explanation (UNTRUSTED")
    assert "‮" not in flat and "\\u{202E}" in flat  # bidi override escaped
    assert any("invisible" in r for r in card["risk_lines"])
    assert card["digest"] == digest(d)
    n = render_narrated_card(d, "Sending the weekly report to your boss")
    assert n["trusted"] is False and "eve@evil.example" not in json.dumps(n["fields"])


def test_sms_to_is_not_email(tmp_path):
    d = canonicalize("send_message", {"to": "+1 555 0100", "text": "x"}, ctx(str(tmp_path), effect_class="send"))
    assert d["target"] == "+1 555 0100"


def test_multiple_recipients_target_sorted(tmp_path):
    d = canonicalize("send_email", {"to": ["B@x.com", "a@x.com"], "cc": "c@y.com"},
                     ctx(str(tmp_path), effect_class="send"))
    assert d["target"] == "a@x.com,b@x.com,c@y.com"
