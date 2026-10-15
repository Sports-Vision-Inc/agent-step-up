"""AB-family probe against the MCP Python SDK elicitation surface (mcp 2.3.0).

Reuses the AUDIT-owned env audit/.envs/mcp (never edited). Elicitation is a
prompt primitive (form mode collects schema-typed fields; URL mode sends the
user out of band), NOT an effect-bound approval. So the AB family maps onto its
rendering/independence properties rather than effect binding. We execute the
schema renderer, inspect message handling in the shipped module, and EXECUTE an
in-memory server->client elicitation (_mcp_elicit_exec.py) to observe what reaches
the client.
"""
from __future__ import annotations
import io
import json
import os
import subprocess
import sys
import tempfile

from attacks.common import row, write_evidence, VULN, NOT_VULN, PARTIAL, NA
from attacks.targets import AUDIT_ENVS

T = "mcp"
_SITE = None


def _site():
    global _SITE
    if _SITE:
        return _SITE
    base = os.path.join(AUDIT_ENVS, "mcp", "lib")
    if not os.path.isdir(base):
        return None
    for py in sorted(os.listdir(base)):
        sp = os.path.join(base, py, "site-packages")
        if os.path.isdir(os.path.join(sp, "mcp")):
            _SITE = sp
            return sp
    return None


def _execute_elicitation() -> dict:
    """Run _mcp_elicit_exec.py under the AUDIT mcp env's interpreter, in an empty
    working directory (so nothing local shadows imports)."""
    py = os.path.join(AUDIT_ENVS, "mcp", "bin", "python")
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_mcp_elicit_exec.py")
    if not os.path.exists(py):
        return {"ok": False, "error": "audit/.envs/mcp/bin/python missing"}
    try:
        with tempfile.TemporaryDirectory() as cwd:
            out = subprocess.run([py, script], cwd=cwd, capture_output=True, text=True, timeout=180)
        if out.returncode != 0:
            return {"ok": False, "error": (out.stderr or out.stdout)[-2000:]}
        res = json.loads(out.stdout)
        res["ok"] = True
        return res
    except Exception as e:  # recorded, never fatal
        return {"ok": False, "error": repr(e)}


def _available() -> bool:
    return _site() is not None


def run():
    rows = []
    sp = _site()
    if not sp:
        for ab in ("AB4", "AB5", "AB6", "AB1", "AB2"):
            rows.append(row(T, ab, applicable=True, executed=False, outcome=NA,
                            note="audit/.envs/mcp not present"))
        return rows
    if sp not in sys.path:
        sys.path.insert(0, sp)
    import inspect
    from mcp.server import elicitation as el

    log = io.StringIO()
    src = inspect.getsource(el)
    # The free-text `message` is passed straight through to the client with no
    # sanitisation/length-cap in the SDK (display is delegated to the client).
    msg_passthrough = "message=message" in src and "sanitiz" not in src.lower()
    print("elicit_with_validation forwards `message` unmodified:", msg_passthrough, file=log)
    print("elicit_url forwards `message` unmodified too:", "message=message" in src, file=log)

    # Form-mode schema IS validated against PrimitiveSchemaDefinition (good):
    from pydantic import BaseModel
    try:
        class Form(BaseModel):
            confirm: bool
            amount: int
        rendered = el.render_elicitation_schema(Form)
        schema_ok = "properties" in rendered and set(rendered["properties"]) == {"confirm", "amount"}
    except Exception as e:  # pragma: no cover
        schema_ok = False
        print("schema render error:", e, file=log)
    print("form schema validated/rendered:", schema_ok, file=log)
    # AB4 padding / AB5 label-spoof / AB6 non-injective: EXECUTED over an in-memory
    # MCP session (server tool -> ctx.elicit -> client elicitation_callback). We
    # record exactly what reaches the client.
    exe = _execute_elicitation()
    print("\nExecuted elicitation run (attacks/probes/_mcp_elicit_exec.py):", file=log)
    print(json.dumps(exe, indent=1, ensure_ascii=True), file=log)
    ev = write_evidence("mcp_elicit.log", log.getvalue())
    ran = bool(exe.get("ok"))
    checks = {
        "AB4": ("blank-glyph/bidi padding",
                ran and exe.get("AB4_verbatim") and exe.get("AB4_has_U2800_U202E"),
                "A 521-character message with 400x U+2800, U+202E and 50x U+3164 padding reached the "
                "client's elicitation_callback byte-for-byte (no escape, collapse or length cap)."),
        "AB5": ("label spoofing in prompt text",
                ran and exe.get("AB5_verbatim"),
                "Server text imitating trusted labels ('Verified by client: YES', 'Target: ...') reached "
                "the client verbatim, while the tool ran with a different payee."),
        "AB6": ("non-injective rendering",
                ran and exe.get("AB6_identical_requests"),
                "Two different effects (10 to acct-utility-001; 10000 to acct-placeholder-999) produced "
                "byte-identical elicitation requests (message + schema), and both executed after 'accept'."),
    }
    for ab, (name, shown, what) in checks.items():
        if ran:
            rows.append(row(T, ab, applicable=True, executed=True,
                            outcome=VULN if shown else NOT_VULN,
                            severity="medium" if shown else "none",
                            note=f"{name} (executed, in-memory MCP session): {what} "
                                 "The SDK forwards the server-authored `message` unchanged and binds the "
                                 "answer to no effect. The MCP spec leaves display to the client, so this "
                                 "is an SDK-layer observation. A client that sanitises the message and "
                                 "shows which server is asking, or URL mode, mitigates it. In our threat "
                                 "model the text reaching the human is attacker-influenced.",
                            evidence=ev,
                            repro="audit/.envs/mcp/bin/python attacks/probes/_mcp_elicit_exec.py"))
        else:
            rows.append(row(T, ab, applicable=True, executed=False,
                            outcome=VULN if msg_passthrough else PARTIAL, severity="medium",
                            note=f"{name}: STATIC (the executed run failed: {exe.get('error', '?')[:200]}). "
                                 "Source inspection shows the elicitation `message` is forwarded "
                                 "unmodified.", evidence=ev))

    # AB independence: form-mode content round-trips through the client/LLM; URL mode is out of band.
    rows.append(row(T, "AB10", applicable=True, executed=ran, outcome=PARTIAL, severity="medium",
                    note="Form-mode results are returned to the server via the client and are not "
                         "cryptographically bound to any tool-effect digest, so a compromised client/agent "
                         "can alter or synthesise the 'accept' content (docstring even says an agent client "
                         "'might ... automatically generat[e] a response'; our executed run's callback "
                         "synthesises 'accept' in code and the tool runs). URL mode keeps the interaction "
                         "out of band (stronger for P1/P4). No effect-binding either way.", evidence=ev))

    rows.append(row(T, "AB1", applicable=False, executed=False, outcome=NA,
                    note="Elicitation collects typed form fields; it is not an amount-bearing approval of "
                         "a specific effect."))
    rows.append(row(T, "AB2", applicable=False, executed=False, outcome=NA,
                    note="No recipient/target binding: elicitation is a generic prompt, not an effect "
                         "descriptor."))
    for ab, why in [
        ("AB3", "No delegated grant primitive."),
        ("AB7", "No credential enrollment in the elicitation surface."),
        ("AB8", "No concatenated challenge; form schema is validated JSON-Schema (injective)."),
        ("AB9", "URL mode deliberately moves the ceremony off the client; form mode has no signed bytes."),
        ("AB11", "No volume/rate primitive in the elicitation API (host concern)."),
        ("AB12", "No aggregate-limit primitive."),
    ]:
        rows.append(row(T, ab, applicable=False, executed=False, outcome=NA, note=why))
    return rows
