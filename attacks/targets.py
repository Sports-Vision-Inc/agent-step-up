"""Provenance for every third-party target under test.

Each entry records the exact repo/version, the commit or release pinned, the
license, and HOW it was obtained so results are reproducible. Clones live under
attacks/.targets/ (gitignored); installed runtimes are reused from audit/.envs/
(owned by AUDIT — we never edit them).
"""
from __future__ import annotations
import os

ATTACKS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(ATTACKS_DIR)
TARGETS_DIR = os.path.join(ATTACKS_DIR, ".targets")
AUDIT_ENVS = os.path.join(REPO_ROOT, "audit", ".envs")

TARGETS = {
    "ap2": {
        "name": "Google AP2 reference implementation",
        "repo": "github.com/google-agentic-commerce/AP2",
        "commit": "e1ea56db72a6385bce3e5c1112b3a56ce60acb43",
        "ref": "v0.2.0 (main @ 2026-04-29)",
        "license": "Apache-2.0",
        "obtained": "git clone -> attacks/.targets/ap2",
        "subject": "Python SDK mandate constraint checking (ap2.sdk.constraints) + "
                   "web-client MandateCard sample renderer",
        "scope": "IntentMandate/CartMandate/PaymentMandate constraints; SD-JWT binding is "
                 "signed by the holder key (strong P2 by construction).",
    },
    "agt": {
        "name": "Microsoft Agent Governance Toolkit — ADR-0030 action-bound approval",
        "repo": "github.com/microsoft/agent-governance-toolkit",
        "commit": "47abed7446d47e74cfa76d01a5913bb873ffcad9",
        "ref": "main @ 2026-10-13",
        "license": "MIT",
        "obtained": "git clone --depth 1 -> attacks/.targets/agt",
        "subject": "agentmesh.governance.approval_protocol (binding/digest/coordinator/store)",
        "scope": "ADR-0030: SHA-256 over RFC8785 JCS of the full action binding; "
                 "consume-once; execution-time revalidation; hash-linked chain.",
    },
    "mcp": {
        "name": "MCP Python SDK — elicitation (form + URL modes)",
        "repo": "PyPI mcp (reused from audit/.envs/mcp)",
        "commit": "n/a (wheel)",
        "ref": "mcp 2.3.0",
        "license": "MIT",
        "obtained": "reused audit/.envs/mcp (AUDIT-owned; not edited)",
        "subject": "mcp.server.elicitation (elicit_with_validation, elicit_url, "
                   "render_elicitation_schema)",
        "scope": "Elicitation is a form/URL prompt, not an effect-bound approval primitive.",
    },
    "openclaw": {
        "name": "OpenClaw exec approvals / allow-always grants",
        "repo": "npm openclaw (reused from audit/.envs/openclaw)",
        "commit": "n/a (npm dist)",
        "ref": "openclaw 2026.10.3",
        "license": "see package (Apache-2.0 per bundle)",
        "obtained": "reused audit/.envs/openclaw/node_modules (AUDIT-owned; not edited)",
        "subject": "exec-approval-registration / approval / exec-control-command-guard (dist .mjs)",
        "scope": "STATIC design review of shipped bundle; the live loop needs an LLM/Gateway "
                 "(not run), consistent with audit/probes/openclaw.",
    },
    "frameworks": {
        "name": "In-process agent frameworks (HITL callbacks)",
        "repo": "various (reused from audit/.envs)",
        "commit": "n/a",
        "ref": "openai-agents 0.23.1, langgraph 1.2.15, google-adk 2.12.0, agno 3.1.3, "
               "pydantic-ai 2.56.0, crewai 1.15.27, autogen-agentchat 0.7.5, smolagents 1.26.0",
        "license": "various OSS",
        "obtained": "reused audit/results/matrix.json (AUDIT-owned)",
        "subject": "per-runtime human-approval primitives",
        "scope": "Cross-referenced to the AUDIT matrix so we do not duplicate its probes; "
                 "the AB family is mapped onto AUDIT's P1..P7 findings.",
    },
    "asu": {
        "name": "ASU gateway (this repo) — the reference DEFENSE",
        "repo": "this repository (asu/)",
        "commit": None,  # filled at run time: git rev-parse HEAD (+ "-dirty")
        "ref": "see commit at run time",
        "license": "repo license",
        "obtained": "local import",
        "subject": "asu.app.create_app with approval_mode=asu + packaged default policy",
        "scope": "Live gateway (uvicorn, asu mode, receipt re-verification) driven by the red-team "
                 "harness and tests/test_attacks_asu_live.py; every cell maps to named pytest node ids "
                 "run at the stamped commit.",
    },
}

# The approval-binding attack family (docs/fixers/attacks.md), with the
# strengthened-adversary variants X1-X3 from docs/critique/formal.md noted.
ATTACKS = {
    "AB1":  "Amount cancellation / multi-amount ambiguity",
    "AB2":  "Decoy-field target/recipient confusion",
    "AB3":  "Grant/mandate stretching beyond signed constraints",
    "AB4":  "Card padding / blank-glyph / bidi hiding",
    "AB5":  "Label spoofing via agent-chosen field names",
    "AB6":  "Non-injective rendering (distinct effects, identical display)",
    "AB7":  "Enrollment squatting (agent registers the approving credential)",
    "AB8":  "Challenge/encoding ambiguity (non-injective concatenation)",
    "AB9":  "Ceremony control (renderer also chooses what is signed)",
    "AB10": "Post-approval substitution (Loopjacking-style baseline)",
    "AB11": "Approval flooding within one run",
    "AB12": "Threshold splitting under aggregate limits",
}
