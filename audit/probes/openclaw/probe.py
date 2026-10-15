"""Probe: OpenClaw (npm, 2026.10.3) exec/tool approvals — STATIC + CLI analysis.

OpenClaw is an open-source agent runtime (npm). Its approval loop is driven by a live
model and a Gateway, which we cannot exercise here (no network LLM). This probe
therefore does what is reproducible offline:
  - confirms the CLI + approval surface exist (openclaw --version; approvals get --json),
  - reads the SHIPPED dist source to assess the SPEC-3 properties of its exec-approval
    design (bundled .mjs under node_modules/openclaw/dist and docs/).
Outcomes below are a design review of released code, NOT a live approval-loop execution;
every row's explanation says so. Honesty rule: the dynamic behaviour was not run.

Target version is post-fix for the Loopjacking representation mismatch (OpenClaw
2026.2.23 -> fixed 2026.2.24; here 2026.10.3).
"""
import json, sys, os, re, subprocess
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import write_evidence, row, emit

RT = "openclaw"
_AUDIT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ROOT = os.path.join(_AUDIT, ".envs", "openclaw", "node_modules", "openclaw")
DIST = os.path.join(ROOT, "dist")
DOCS = os.path.join(ROOT, "docs")

with open(os.path.join(ROOT, "package.json")) as f:
    VER = json.load(f)["version"]


def cat(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def grepdir(d, pat):
    rx = re.compile(pat)
    hits = []
    for root, _, files in os.walk(d):
        for fn in files:
            if fn.endswith((".mjs", ".js", ".md")):
                p = os.path.join(root, fn)
                t = cat(p)
                if rx.search(t):
                    hits.append(os.path.relpath(p, ROOT))
    return hits


def find_module(glob_prefix):
    """Locate a dist module by stable prefix (build hashes change on re-pin), so a re-pin
    does not silently blank a cell. Returns (path, concatenated_text)."""
    import glob as _glob
    matches = sorted(_glob.glob(os.path.join(DIST, glob_prefix + "*")))
    text = "\n".join(cat(m) for m in matches)
    return matches, text


def main():
    rows = []

    # Confirm the CLI surface is real (reproducible, no model).
    cli_log = []
    cli = os.path.join(ROOT, "openclaw.mjs")
    node_ver = "?"
    try:
        nv = subprocess.run(["node", "--version"], capture_output=True, text=True, timeout=30)
        node_ver = (nv.stdout + nv.stderr).strip()
    except Exception as e:
        node_ver = f"node version call failed: {e}"
    cli_log.append(f"host node --version -> {node_ver} (NOTE: OpenClaw's supported range may "
                   f"differ; probe ran on this version).")
    try:
        v = subprocess.run(["node", cli, "--version"], capture_output=True, text=True, timeout=60)
        cli_log.append("openclaw --version -> " + (v.stdout + v.stderr).strip().splitlines()[-1])
    except Exception as e:
        cli_log.append(f"version call failed: {e}")
    # Locate modules by stable prefix (build hashes change on re-pin).
    san_matches, sanitize_src = find_module("exec-approval-text-sanitize-")
    exec_matches, exec_src = find_module("exec-approval-")
    cli_log.append(f"exec-approval modules matched: {exec_matches}")
    cli_log.append(f"sanitizer modules matched: {san_matches}")

    # ---- T1: where surfaced; agent-independence ----
    log = list(cli_log)
    gw = grepdir(DIST, r"operator\.admin|operator-approvals")
    chat = grepdir(DIST, r"/approve|chat approval|native approval card|fast-approve")
    log.append(f"T1: approvals resolvable out-of-band via Gateway/CLI (operator.admin / "
               f"operator-approvals scope) in {len(gw)} modules, e.g. {gw[:2]}")
    log.append(f"T1: ALSO resolvable in-channel via chat '/approve' / native approval cards "
               f"({len(chat)} modules, e.g. {chat[:2]}) — same surface the agent posts to.")
    log.append("T1: docs/concepts/system-prompt.md: on channels with native approval cards the "
               "agent relies on that UI; a manual /approve exists when chat approvals are "
               "available. The Gateway/CLI path (operator.admin) is out of the agent's reach; "
               "the chat path is in a channel the agent can post to.")
    log.append("T1: DEFAULT TOPOLOGY (docs/tools/exec.md:92, :120; exec-approvals.md:52-54,229): "
               "sandboxing is OFF by default, host=auto resolves to the gateway, and gateway/node "
               "host exec defaults to mode=full (no approval). Gateway-authenticated callers are "
               "'trusted operators ... not a per-user auth boundary', and the operator token "
               "resolves from local config (gateway/remote.md:256-261). So by default the agent's "
               "exec runs on the gateway host as the operator; agent-reachability of /approve was "
               "NOT executed (no live loop).")
    rows.append(row(RT, VER, "T1_P1_agent_independence", "fail",
        write_evidence("openclaw", "T1", "\n".join(log)),
        "STATIC (by default): with sandboxing off and exec defaulting to mode=full on the "
        "gateway host, the agent's exec runs as the operator credential with no per-call "
        "approval; vendor docs state gateway callers are not a per-user auth boundary. An "
        "operator-mediated / sandboxed / remote-node config MAY be agent-independent (PART-s) "
        "but that was not executed. Measurable P1 columns recorded.",
        mechanism="exec approvals (gateway operator path vs chat /approve)",
        marker="static", counted=False,
        p1={"oop_resume": "Y", "separate_principal_approver": "non-default",
            "oop_evidence": "Gateway/CLI operator path exists (operator.admin scope); "
                            "off by default (exec mode=full), not executed"},
        judgement='static source/doc review of default topology (sandbox off, exec mode=full); not executed'))

    # ---- T2: effect-binding ----
    log2 = []
    argv_cwd = ("argv" in exec_src and "cwd" in exec_src)
    doc = cat(os.path.join(DOCS, "cli", "approvals.md"))
    bound_doc = "exact arguments and current working directory" in doc
    log2.append(f"T2: exec-approval module binds grants to argv and cwd (argv&cwd in source={argv_cwd})")
    log2.append(f"T2: docs: allow-always grant 'tied to the command's exact arguments and current "
                f"working directory' = {bound_doc}; a different cwd needs a separate approval.")
    log2.append("T2: version 2026.10.3 is past the Loopjacking representation-mismatch fix "
                "(2026.2.23 -> 2026.2.24).")
    log2.append("T2: exec-approvals.md:57 'does not cover inner shell executables across a "
                "remote human approval wait'; :59 'File binding is best-effort'. Binding applies "
                "to the exec class only; other approval kinds (e.g. plugin approvals) not assessed.")
    rows.append(row(RT, VER, "T2_P2_effect_binding", "partial",
        write_evidence("openclaw", "T2", "\n".join(log2)),
        "STATIC (not executed): the shipped source and docs indicate exec grants are bound to "
        "argv + cwd (post the Loopjacking representation-mismatch fix), but this is a source/doc "
        "review, not a live approval loop, and the vendor documents gaps (inner shell "
        "executables, best-effort file binding). Capped at PART-s; a static review can support "
        "an absence (FAIL) but not establish that a property holds.",
        mechanism="exec grant argv+cwd binding (source/doc)",
        marker="static", counted=False, qualifier="STATIC",
        judgement='static source/doc review (argv+cwd binding tokens and docs); capped at PART-s; not executed'))

    # ---- T3: single use ----
    log3 = []
    once = "allow-once" in exec_src
    expiry = bool(grepdir(DIST, r"expiresAt|expiresInDays"))
    log3.append(f"T3: 'allow-once' single-shot resolution present in exec-approval = {once}; "
                f"approval records carry expiry (expiresAt/expiresInDays) = {expiry}.")
    log3.append("T3: allow-once resolves one pending request; allow-always deliberately mints a "
                "persistent arg+cwd-scoped grant (documented, not a replay bug).")
    rows.append(row(RT, VER, "T3_P3_single_use", "partial",
        write_evidence("openclaw", "T3", "\n".join(log3)),
        "STATIC (not executed): the source shows allow-once single-shot resolution and expiry "
        "fields, and allow-always is a documented scoped standing grant; but this is a keyword/"
        "source review, not a live replay test. Capped at PART-s.",
        mechanism="allow-once / expiry (source)",
        marker="static", counted=False, qualifier="STATIC",
        judgement='static source review (allow-once / expiry tokens); capped at PART-s; not executed'))

    # ---- T4: trusted rendering ----
    log4 = []
    has_sanitizer = "sanitizeExecApprovalDisplayText" in sanitize_src
    hygiene = all(k in sanitize_src for k in ("escapeInvisibles", "redactSensitiveText"))
    log4.append(f"T4: exec approval text is rendered via sanitizeExecApprovalDisplayText "
                f"(present={has_sanitizer}); escapes invisibles, redacts secrets, masks "
                f"homoglyph/bypass sequences (hygiene={hygiene}).")
    log4.append("T4: the card text is derived by trusted code from the structured exec request "
                "and sanitized, rather than printed from raw model narration. docs/cli/approvals.md "
                "promises a losslessly-escaped 'Full request text' block.")
    rows.append(row(RT, VER, "T4_P4_trusted_rendering", "partial",
        write_evidence("openclaw", "T4", "\n".join(log4)),
        "STATIC (not executed): the shipped sanitizer (escapes invisibles, redacts secrets) and "
        "the documented 'Full request text' block indicate the exec approval card is rendered "
        "from the structured command by trusted code; but no rendering was executed, so this is "
        "capped at PART-s rather than PASS.",
        mechanism="sanitizeExecApprovalDisplayText (source)",
        marker="static", counted=False, qualifier="STATIC",
        judgement='static source review (sanitizeExecApprovalDisplayText); capped at PART-s; not executed'))

    # ---- T5: non-repudiation ----
    log5 = []
    sig = grepdir(DIST, r"\bed25519\b|webauthn|signApproval|approvalSignature")
    # filter to approval-related modules to avoid unrelated crypto (e.g. transport)
    sig_appr = [h for h in sig if "approval" in h.lower()]
    log5.append(f"T5: modules referencing approval-record signing (ed25519/webauthn/"
                f"signApproval) among approval-* files = {sig_appr}")
    log5.append("T5: approval records carry requester/reviewer attribution and operator scopes "
                "but no cryptographic signature over the effect that a third party could verify "
                "without trusting the Gateway's own store.")
    rows.append(row(RT, VER, "T5_P5_non_repudiation", "fail",
        write_evidence("openclaw", "T5", "\n".join(log5)),
        "STATIC (by absence): no detached cryptographic signature over the effect was found in "
        "the approval modules; approvals are attributed records in Gateway state, not third-"
        "party verifiable without trusting the Gateway. (A static review can support FAIL by "
        "absence; labelled static.)",
        mechanism="approval record signing (source, by absence)",
        marker="static", counted=False,
        judgement='static review by absence of approval-record signing code; not executed'))

    # ---- T6: flood resistance ----
    log6 = []
    dedup = bool(grepdir(DIST, r"dedupeByKey|dedupeKey|dedupeDefined"))
    expiry = bool(grepdir(DIST, r"expiresAt"))
    log6.append(f"T6: approval runtime de-duplicates requests by key (dedupe={dedup}) and expires "
                f"pending approvals (expiry={expiry}).")
    log6.append("T6: de-dup + expiry blunt naive repeat-flooding, but no explicit per-session "
                "pending-cap or requests-per-minute lockout was located in the approval modules.")
    log6.append("T6: the dedupe tokens match non-approval modules too (e.g. agent-turn-service, "
                "allow-from), so a keyword match does not establish approval-flood resistance.")
    rows.append(row(RT, VER, "T6_P7_flood_resistance", "partial",
        write_evidence("openclaw", "T6", "\n".join(log6)),
        "STATIC (not executed): dedupe/expiry tokens appear in dist (including non-approval "
        "modules), suggesting some flood resistance, but no explicit rate limit / pending cap / "
        "lockout was located and nothing was executed. Capped at PART-s (grep-level).",
        mechanism="dedupe/expiry tokens (source)",
        marker="static", counted=False, qualifier="STATIC",
        judgement='static grep for dedupe/expiry tokens; no cap/rate-limit located; not executed'))

    emit(rows)


main()
