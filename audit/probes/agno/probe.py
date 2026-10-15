"""Probe: Agno human-in-the-loop (requires_confirmation / @approval + continue_run).

Documented HITL patterns:
  (1) @tool(requires_confirmation=True): the run pauses with a ToolExecution on
      run_response.tools; the caller sets confirmed=True and calls continue_run.
  (2) AgentOS remote continue: POST /agents/{id}/runs/{run_id}/continue with a tools
      JSON body (agno/os/routers/agents/router.py -> continue_run_dispatch), the
      realistic capability for Loopjacking (arXiv 2609.21081, reported for AgentOS
      2.5.6-3.0.9).
  (3) @approval(type="required"): an approval record whose resolve/delete is admin-only
      under AuthorizationConfig(user_isolation=True) (agno/os/routers/approvals/router.py).

Effect-binding (T2), freshness (T3), flood (T6) and the separate-principal approver
(T1) are measured over REAL HTTP against a uvicorn-hosted AgentOS app via
audit/probes/agno/agentos_http.py (no in-process router shortcut). The in-process
continue_run path is used only to show the by-construction in-host confirmation and the
in-process rollback.
"""
import importlib.metadata as M, sys, os, json, copy
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import write_evidence, row, emit, EVID_DIR
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import agentos_http as AOS

# Agno and uvicorn attach a logging.StreamHandler(sys.stdout) at logger-creation time,
# which would corrupt the JSON that run_all parses from stdout. Swap sys.stdout to stderr
# BEFORE importing agno (so every handler binds to stderr), and emit the final JSON to the
# saved real stdout.
_REAL_STDOUT = sys.stdout
sys.stdout = sys.stderr

RT = "agno"
VER = M.version("agno")

from agno.agent import Agent
from agno.models.openai.chat import OpenAIChat
from agno.tools import tool

LEDGER = []


@tool(requires_confirmation=True)
def wire_transfer(amount: int, to: str) -> str:
    """Send a wire transfer."""
    LEDGER.append({"amount": amount, "to": to})
    return f"sent {amount} to {to}"


class StubModel(OpenAIChat):
    """Deterministic stub: turn 1 emits a wire_transfer tool call; later turns finish."""
    def __init__(self, args):
        super().__init__(id="stub", api_key="x")
        object.__setattr__(self, "_turn", 0)
        object.__setattr__(self, "_args", args)

    def _process_model_response(self, messages, assistant_message, model_response,
                               response_format=None, tools=None, tool_choice=None,
                               run_response=None, compress_tool_results=False):
        self._turn += 1
        if self._turn == 1:
            assistant_message.role = "assistant"
            assistant_message.tool_calls = [{
                "id": "call1", "type": "function",
                "function": {"name": "wire_transfer", "arguments": json.dumps(self._args)},
            }]
            model_response.tool_calls = assistant_message.tool_calls
        else:
            assistant_message.role = "assistant"
            assistant_message.content = "done"
            model_response.content = "done"
        return None


def build(args):
    return Agent(model=StubModel(args), tools=[wire_transfer], telemetry=False)


def paused_tools(r):
    return [t for t in (r.tools or []) if getattr(t, "is_paused", False)]


def main():
    rows = []
    # Run the real-HTTP AgentOS experiments once; reuse across rows.
    try:
        aos = {"version": AOS.VER, "default": AOS._exp_default()}
        try:
            aos["approval_isolated"] = AOS._exp_approval(True)
        except Exception as e:
            aos["approval_isolated"] = {"error": repr(e)}
        try:
            aos["approval_default_isolation"] = AOS._exp_approval(False)
        except Exception as e:
            aos["approval_default_isolation"] = {"error": repr(e)}
    except Exception as e:
        aos = {"error": repr(e)}
    dflt = aos.get("default", {})
    appr = aos.get("approval_isolated", {})
    appr_d = aos.get("approval_default_isolation", {})

    # ---- T1: agent-independence (BY CONSTRUCTION) + measurable P1 columns ----
    LEDGER.clear()
    log = []
    agent = build({"amount": 10, "to": "alice"})
    r = agent.run("pay")
    pt = paused_tools(r)
    log.append(f"T1: run paused with {len(pt)} tool(s) awaiting confirmation")
    for t in pt:
        t.confirmed = True
    agent.continue_run(r)
    log.append(f"T1: in-process confirmed=True + continue_run -> ledger={LEDGER}")
    t1_ok = bool(LEDGER)  # the in-host answer path must actually execute (else not_run)
    # P1 (a) out-of-process resume: AgentOS persists the paused run; a networked client
    # resumes it via POST /continue by run_id (see agentos_http default experiment).
    oop = "Y" if dflt.get("start_status") == "PAUSED" else "N"
    # P1 (b) separate-principal approver: @approval under user_isolation=True makes resolve
    # admin-only, so the requester cannot resolve its own approval (self_resolve 403/404,
    # continue-while-pending 403). This is a SHIPPED but NON-DEFAULT secure config
    # (default user_isolation=False lets an approvals:write holder self-resolve).
    admin_only = (appr.get("self_resolve_status") in (403, 404)
                  and appr.get("self_resolve_with_write_status") in (403, 404)
                  and appr.get("continue_while_pending_status") == 403)
    default_self = appr_d.get("self_resolve_with_write_status") == 200
    ships = "non-default" if admin_only else "no"
    log.append(f"T1: AgentOS @approval admin-only-resolve under user_isolation=True: "
               f"self_resolve={appr.get('self_resolve_status')}, "
               f"self_resolve_with_write={appr.get('self_resolve_with_write_status')}, "
               f"continue_while_pending={appr.get('continue_while_pending_status')} "
               f"-> admin_only={admin_only}")
    log.append(f"T1: default user_isolation=False lets an approvals:write requester "
               f"self-resolve (status={appr_d.get('self_resolve_with_write_status')}).")
    rows.append(row(RT, VER, "T1_P1_agent_independence", "fail" if t1_ok else "not_run",
        write_evidence("agno", "T1", "\n".join(log)),
        "BY CONSTRUCTION (dagger): the pause is a ToolExecution on run_response in the same "
        "process; setting confirmed=True + continue_run authorizes it. Measured: out-of-"
        "process resume via the AgentOS /continue endpoint; a SEPARATE-PRINCIPAL approver "
        "ships (@approval admin-only resolve) but is NON-DEFAULT (requires "
        "user_isolation=True; the default lets an approvals:write requester self-resolve).",
        mechanism="requires_confirmation + continue_run; @approval admin-only resolve (AgentOS)",
        marker="dagger", counted=False,
        p1={"oop_resume": oop, "separate_principal_approver": ships,
            "oop_evidence": "AgentOS POST /continue by run_id (real HTTP)"}))

    # ---- T2: effect-binding over the AgentOS remote continue path (L2) ----
    log2 = []
    l2_sub = bool(dflt.get("L2_executed_B"))
    log2.append(f"T2 L2 (remote continue, client-supplied tools JSON with a different field "
                f"set): executed_B={l2_sub} (shown={dflt.get('shown')}).")
    log2.append(f"T2 L3 (after a legitimate admin approval, the requester's continue still "
                f"substitutes tool_args): executed_B_after_admin="
                f"{appr.get('L2_executed_B_after_admin')}.")
    log2.append("T2 L1 (in-process mutation of ToolExecution.tool_args) also substitutes but "
                "is not scored as a gap (the in-process holder is the approver).")
    log2.append("T2 root cause: agno/agent/_run.py::_apply_requirement_tools replaces the "
                "stored run_response.tools with the client-supplied ToolExecutions "
                "(tool_args included); the team path (_merge_requirement_decision) keeps only "
                "decision fields, a fix not applied to single agents.")
    levels = {
        "L1": "substituted (in-process tool_args mutation) — not a binding gap",
        "L2": "substituted" if l2_sub else "resist",
        "L3": "substituted" if appr.get("L2_executed_B_after_admin") else "resist",
    }
    t2o = "fail" if l2_sub else "pass"
    rows.append(row(RT, VER, "T2_P2_effect_binding", t2o,
        write_evidence("agno", "T2", "\n".join(log2)),
        "the documented AgentOS continue endpoint accepts a client-supplied tools JSON and "
        "executes its tool_args; nothing binds the approved call to the executed one "
        "(Loopjacking class). Reproduced over real HTTP on agno==" + VER + "; see "
        "evidence/agno_agentos_versions.log for the version sweep.",
        mechanism="AgentOS POST /continue (remote continue path)", levels=levels))

    # ---- T3: single use ----
    log3 = []
    # same_call: the remote continue payload POSTed twice (measured over HTTP).
    same_call_execs = dflt.get("replay_executions")
    log3.append(f"T3 same_call (remote continue payload POSTed twice): executions="
                f"{same_call_execs} (first={dflt.get('replay_first')}). On this version a "
                + ("re-POST DOES re-execute the call." if (same_call_execs or 0) >= 2 else
                   "re-POST does NOT re-execute (the stored copy of an already-run call is kept)."))
    # rollback: in-process snapshot of the paused run, continue twice.
    LEDGER.clear()
    rollback_execs = None
    try:
        a = build({"amount": 5, "to": "bob"})
        rr = a.run("pay")
        snap = copy.deepcopy(rr)
        for t in paused_tools(rr):
            t.confirmed = True
        a.continue_run(rr)
        for t in paused_tools(snap):
            t.confirmed = True
        try:
            a.continue_run(snap)
        except Exception as e:
            log3.append(f"T3 rollback: second continue raised {type(e).__name__}: {e}")
        rollback_execs = len(LEDGER)
        log3.append(f"T3 rollback (continue a deep-copied paused run): ledger={LEDGER}")
    except Exception as e:
        log3.append(f"T3 rollback failed: {type(e).__name__}: {e}")
    levels3 = {
        "same_call": "consumed relative to run state" if (same_call_execs or 0) <= 1 else "re-exec",
        "rollback": "double-exec" if (rollback_execs or 0) >= 2 else "resist",
        "cross_call": "n/a",
    }
    outcome3 = "partial"
    if (same_call_execs or 0) >= 2:
        outcome3 = "fail"
    elif (rollback_execs or 0) < 2:
        outcome3 = "pass"
    expl3 = (("a remote continue replay RE-EXECUTES on this version (same_call="
              f"{same_call_execs}); ") if (same_call_execs or 0) >= 2 else
             ("a remote continue replay is consumed relative to the stored run state (no "
              "re-execution on re-POST on this version); ")) + (
             "the confirmation carries no nonce/expiry and an in-process rollback of the "
             f"paused run {'double-executes' if (rollback_execs or 0) >= 2 else 'does not re-execute'}.")
    rows.append(row(RT, VER, "T3_P3_single_use", outcome3,
        write_evidence("agno", "T3", "\n".join(log3)), expl3,
        mechanism="remote replay + in-process rollback",
        qualifier=("STATE" if outcome3 == "partial" else None), levels=levels3))

    # ---- T4: who renders ----
    log4 = ["T4: Agno exposes the paused ToolExecution with tool_name and tool_args "
            "(structured data) for the integrator / AgentOS UI to render; it ships no trusted "
            "card and no untrusted-text box, and the confirmation UX sits in the same app "
            "surface as the agent."]
    rows.append(row(RT, VER, "T4_P4_trusted_rendering", "partial",
        write_evidence("agno", "T4", "\n".join(log4)),
        "structured tool_name/tool_args available, but no framework-enforced trusted "
        "rendering path separate from the agent surface.",
        mechanism="paused ToolExecution fields", qualifier="INT",
        judgement="source/API review: paused ToolExecution tool_name/tool_args are exposed as structured data and the framework ships no renderer or untrusted-text box; no rendering experiment can select PASS/PART/FAIL, so PART/INT is the auditor's reading of the API surface"))

    # ---- T5: non-repudiation ----
    log5 = ["T5: confirmation is ToolExecution.confirmed (bool); the AgentOS approval record "
            "attributes resolved_by but carries no signature/key/receipt over the effect. "
            "Not third-party verifiable without trusting the AgentOS store."]
    rows.append(row(RT, VER, "T5_P5_non_repudiation", "fail",
        write_evidence("agno", "T5", "\n".join(log5)),
        "approval stored as an unsigned boolean / attributed record; no verifiable receipt "
        "over the effect.",
        mechanism="unsigned ToolExecution.confirmed / approval record",
        judgement='source/API review: ToolExecution.confirmed / approval record is an unsigned field; absence of any signing/receipt code path was established by reading the API, not by an experiment whose observed value selects FAIL'))

    # ---- T6: flood resistance WITHIN A SINGLE RUN ----
    log6 = []
    flood = dflt.get("flood_pending_single_run")
    log6.append(f"T6 (single run over HTTP): one model turn emitted 20 tool calls -> {flood} "
                f"paused tools in ONE run, no throttle/cap.")
    rows.append(row(RT, VER, "T6_P7_flood_resistance", "fail" if (flood or 0) >= 20 else "partial",
        write_evidence("agno", "T6", "\n".join(log6)),
        f"a single run paused on {flood} tool confirmations with no built-in rate limit / "
        "pending cap.",
        mechanism="parallel tool calls in one run"))

    # Version-sweep evidence note (filled by run_all.py's multi-version sweep when present).
    _write_versions_note(aos)
    # Emit JSON to the real stdout (logs were routed to stderr above).
    print(json.dumps(rows, indent=2), file=_REAL_STDOUT)


def _write_versions_note(aos):
    note = os.path.join(EVID_DIR, "agno_agentos_versions.log")
    try:
        existing = open(note).read() if os.path.exists(note) else ""
    except OSError:
        existing = ""
    line = (f"agno=={aos.get('version','?')}: remote-continue L2 substitution="
            f"{aos.get('default',{}).get('L2_executed_B')}, same-call replay executions="
            f"{aos.get('default',{}).get('replay_executions')}, "
            f"@approval admin-only(user_isolation=True) self_resolve_with_write="
            f"{aos.get('approval_isolated',{}).get('self_resolve_with_write_status')}\n")
    if line not in existing:
        with open(note, "a") as f:
            if not existing:
                f.write("# AgentOS remote-continue substitution / @approval across agno "
                        "versions.\n# Loopjacking published range: AgentOS 2.5.6-3.0.9.\n"
                        "# Run: audit/.envs/<env>/bin/python audit/probes/agno/agentos_http.py\n")
            f.write(line)


main()
