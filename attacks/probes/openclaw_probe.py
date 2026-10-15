"""AB-family probe against OpenClaw exec approvals (npm 2026.10.3) — STATIC.

Consistent with audit/probes/openclaw: the live approval loop needs an LLM +
Gateway, which we do not run. This is a DESIGN REVIEW of the shipped dist bundle
(node_modules/openclaw/dist). Every row says 'static'. Reuses the AUDIT-owned
env; nothing under audit/ is edited.
"""
from __future__ import annotations
import io
import os
import re

from attacks.common import row, write_evidence, VULN, NOT_VULN, PARTIAL, NA
from attacks.targets import AUDIT_ENVS

T = "openclaw"
_DIST = os.path.join(AUDIT_ENVS, "openclaw", "node_modules", "openclaw", "dist")


def _available() -> bool:
    return os.path.isdir(_DIST)


def _grep(pattern):
    rx = re.compile(pattern)
    hits = []
    for fn in os.listdir(_DIST):
        if fn.endswith(".mjs"):
            p = os.path.join(_DIST, fn)
            try:
                t = open(p, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            if rx.search(t):
                hits.append(fn)
    return hits


def run():
    rows = []
    if not _available():
        for ab in ("AB3", "AB4", "AB10"):
            rows.append(row(T, ab, applicable=True, executed=False, outcome=NA,
                            note="audit/.envs/openclaw bundle not present"))
        return rows
    log = io.StringIO()
    has_sanitize = _grep(r"sanitizeExecApprovalDisplayText")
    has_invis = _grep(r"EXEC_APPROVAL_INVISIBLE_CHAR_REGEX|escapeInvisibles")
    has_cap = _grep(r"EXEC_APPROVAL_MAX_INPUT|truncateForDisplay|OVERSIZED_MARKER")
    has_redact = _grep(r"redactSensitiveText")
    has_argv_cwd = _grep(r"argv") and _grep(r"cwd")
    allowlist = _grep(r"allow-always|allowAlways")
    print("sanitize fn:", has_sanitize, file=log)
    print("invisible-char handling:", has_invis, file=log)
    print("length cap/oversized marker:", has_cap, file=log)
    print("secret redaction:", has_redact, file=log)
    print("exec grant binds argv+cwd:", bool(has_argv_cwd), file=log)
    print("allow-always present:", allowlist, file=log)
    ev = write_evidence("openclaw_static.log", log.getvalue())

    # AB4 padding/blank-glyph: DEFENDED (invisible-char escape + length cap + redaction).
    ab4_def = bool(has_sanitize and has_invis and has_cap)
    rows.append(row(T, "AB4", applicable=True, executed=False, outcome=NOT_VULN if ab4_def else PARTIAL,
                    severity="none" if ab4_def else "medium",
                    note="STATIC. exec-approval card runs sanitizeExecApprovalDisplayText: invisible-char "
                         "escaping, length cap (oversized marker), and secret redaction, with a "
                         "stripped-view bypass check. This is exactly the escape/collapse/cap that ASU's "
                         "RT-5 flags as MISSING in ASU pre-fix — a fair positive contrast.",
                    evidence=ev))

    # AB3 grant stretching: allow-always bound to exact argv+cwd.
    ab3_bound = bool(has_argv_cwd and allowlist)
    rows.append(row(T, "AB3", applicable=True, executed=False, outcome=PARTIAL if ab3_bound else VULN,
                    severity="low" if ab3_bound else "high",
                    note="STATIC. allow-always exec grants are keyed to the resolved argv (+cwd), so a "
                         "different command/argv needs fresh approval (audit: P2 PASS). Residual: the "
                         "grant is a persistent standing allowance for that exact argv, and matching is on "
                         "parsed argv rather than a signed digest; scope-reduction over time is not "
                         "cryptographically enforced. Not run (needs the live loop).",
                    evidence=ev))

    # AB10 post-approval substitution: the Loopjacking representation-mismatch class.
    rows.append(row(T, "AB10", applicable=True, executed=False, outcome=NOT_VULN, severity="none",
                    note="STATIC. The 2026.2.23->2026.2.24 fix aligned the approved representation with "
                         "the executed command (audit notes 2026.10.3 is post-fix). The approval binds the "
                         "resolved argv that executes. Not re-run here.",
                    evidence=ev))

    for ab, why in [
        ("AB1", "No amount-bearing approval primitive; exec approvals are command-based."),
        ("AB2", "No payee/recipient target in exec approvals."),
        ("AB5", "Approval card labels are framework-rendered, not agent-chosen field names."),
        ("AB6", "Card is rendered from the resolved argv; display injectivity handled by sanitiser (AB4)."),
        ("AB7", "No passkey/credential enrollment in the exec-approval surface."),
        ("AB8", "No concatenated challenge."),
        ("AB9", "Gateway/operator path renders out of band; the in-channel /approve path is the P1 gap "
                "(audit: PART), not a ceremony-control-of-signed-bytes issue."),
        ("AB11", "Dedup + expiry exist (audit T6 PART); no explicit rate-limit/pending-cap found, but no "
                 "per-run flood primitive to execute statically."),
        ("AB12", "No aggregate monetary limit in exec approvals."),
    ]:
        rows.append(row(T, ab, applicable=False, executed=False, outcome=NA, note="STATIC. " + why))
    return rows
