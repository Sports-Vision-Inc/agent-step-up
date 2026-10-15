"""Probe: Pydantic AI deferred-tool approval (requires_approval + DeferredToolResults).

Documented HITL pattern: a tool is declared with requires_approval=True (or the
agent output_type includes DeferredToolRequests). When the model calls it, the run
ends with a DeferredToolRequests output listing approvals (ToolCallPart). The
application resumes with run_sync(..., deferred_tool_results=requests.build_results(
approvals={id: ToolApproved()/ToolDenied()})). ToolApproved has an explicit
override_args channel for approver edits. Ref: pydantic_ai/_deferred.py, tools.py.
"""
import importlib.metadata as M, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import write_evidence, row, emit

RT = "pydantic-ai"
VER = M.version("pydantic-ai-slim")

from pydantic_ai import Agent, ToolApproved, ToolDenied
from pydantic_ai.tools import DeferredToolRequests
from pydantic_ai.models.function import FunctionModel, AgentInfo
from pydantic_ai.messages import ModelResponse, ModelMessage, ToolCallPart, TextPart

LEDGER = []


def model_fn(messages, info: AgentInfo) -> ModelResponse:
    # Turn 1: call the tool. Later turns: finish (tool result present in history).
    called = any(
        isinstance(p, ToolCallPart) and p.tool_name == "wire_transfer"
        for m in messages for p in getattr(m, "parts", [])
    )
    if not called:
        return ModelResponse(parts=[ToolCallPart(
            tool_name="wire_transfer",
            args={"amount": 10, "to": "alice"}, tool_call_id="call1")])
    return ModelResponse(parts=[TextPart(content="done")])


def build():
    agent = Agent(FunctionModel(model_fn), output_type=[str, DeferredToolRequests])

    @agent.tool_plain(requires_approval=True)
    def wire_transfer(amount: int, to: str) -> str:
        LEDGER.append({"amount": amount, "to": to})
        return f"sent {amount} to {to}"

    return agent


def main():
    rows = []

    # ---- T1: where surfaced + can agent code answer ----
    LEDGER.clear()
    log = []
    agent = build()
    res = agent.run_sync("pay")
    out = res.output
    log.append(f"T1: run output type = {type(out).__name__}; approvals pending = "
               f"{[(c.tool_name, c.args) for c in out.approvals] if isinstance(out, DeferredToolRequests) else out}")
    # Approve in-process and resume.
    results = out.build_results(approvals={out.approvals[0].tool_call_id: ToolApproved()})
    res2 = agent.run_sync(message_history=res.all_messages(), deferred_tool_results=results)
    log.append(f"T1: ledger after in-process ToolApproved() + resume = {LEDGER}; final={res2.output!r}")
    t1_ok = bool(LEDGER)  # the in-host answer path must actually execute (else not_run)
    # P1 measurable: out-of-process resume. The pending request + message history are
    # serializable (ModelMessagesTypeAdapter) and resume takes message_history +
    # deferred_tool_results, so the decision can be produced in another process.
    oop = "N"
    try:
        from pydantic_ai.messages import ModelMessagesTypeAdapter
        ag = build()
        rr = ag.run_sync("pay")
        blob = ModelMessagesTypeAdapter.dump_json(rr.all_messages())
        hist = ModelMessagesTypeAdapter.validate_json(blob)
        oop = "Y" if hist else "N"
        log.append("T1: message history dumps/loads via ModelMessagesTypeAdapter; resume "
                   "accepts (message_history, deferred_tool_results) -> out-of-process resume.")
    except Exception as e:
        log.append(f"T1: oop check failed: {type(e).__name__}: {e}")
    rows.append(row(RT, VER, "T1_P1_agent_independence", "fail" if t1_ok else "not_run",
        write_evidence("pydantic_ai", "T1", "\n".join(log)),
        "BY CONSTRUCTION (dagger): approval is a DeferredToolRequests object returned into "
        "the same process; the application constructs ToolApproved()/DeferredToolResults "
        "in-process. Measured: out-of-process resume is possible (serializable history + "
        "resume API); the SDK ships no separate-principal approver.",
        mechanism="requires_approval=True + DeferredToolResults",
        marker="dagger", counted=False,
        p1={"oop_resume": oop, "separate_principal_approver": "no",
            "oop_evidence": "ModelMessagesTypeAdapter round-trip + resume API"}))

    # ---- T2: effect-binding — capability ladder ----
    log2 = []
    # L1 (approver's own override_args) is a documented edit channel, not scored as a gap.
    # L2 (uniform): the resumer supplies the message_history to resume(); a party that holds
    # the stored history edits the recorded ToolCallPart.args, then the approver answers with
    # a PLAIN ToolApproved(). The executed effect is the tampered one.
    LEDGER.clear()
    agent = build()
    res = agent.run_sync("pay")
    out = res.output
    tcid = out.approvals[0].tool_call_id
    shown = out.approvals[0].args
    log2.append(f"T2 L2: approver shown args = {shown}")
    hist = res.all_messages()
    for m in hist:
        for p in m.parts:
            if isinstance(p, ToolCallPart):
                p.args = {"amount": 9999, "to": "mallory"}
    agent.run_sync(message_history=hist,
                   deferred_tool_results=out.build_results(approvals={tcid: ToolApproved()}))
    log2.append(f"T2 L2: ledger after caller-supplied-history edit + plain ToolApproved() = {LEDGER}")
    l2_sub = any(e == {"amount": 9999, "to": "mallory"} for e in LEDGER)
    levels = {
        "L1": "substituted (ToolApproved(override_args=...)) — documented approver channel, not a gap",
        "L2": "substituted" if l2_sub else "resist",
        "L3": "substituted (message history IS the backing store; same as L2)",
    }
    t2o = "fail" if l2_sub else "pass"
    rows.append(row(RT, VER, "T2_P2_effect_binding", t2o,
        write_evidence("pydantic_ai", "T2", "\n".join(log2)),
        "resume() accepts a caller-supplied message_history; a party holding the stored "
        "history edits the recorded ToolCallPart.args and a plain ToolApproved() then "
        "executes the tampered effect. Same state-holder capability that makes LangGraph and "
        "Agno fail, so this cell is FAIL (not PASS)." if l2_sub else
        "a caller-supplied-history edit did not reach execution.",
        mechanism="caller-supplied message_history on resume", levels=levels))

    # ---- T3: single use ----
    log3 = []
    LEDGER.clear()
    agent = build()
    res = agent.run_sync("pay")
    out = res.output
    tcid = out.approvals[0].tool_call_id
    results = out.build_results(approvals={tcid: ToolApproved()})
    res2 = agent.run_sync(message_history=res.all_messages(), deferred_tool_results=results)
    log3.append(f"T3: ledger after first approve = {LEDGER}")
    # same_call: replay the same results against the POST-execution history.
    same_call_replay = False
    try:
        res3 = agent.run_sync(message_history=res2.all_messages(), deferred_tool_results=results)
        same_call_replay = len(LEDGER) > 1
        log3.append(f"T3 same_call: replay against POST-execution history = {LEDGER}; out={res3.output!r}")
    except Exception as e:
        log3.append(f"T3 same_call: replay against post-exec history raised {type(e).__name__}: {e}")
    # rollback: re-apply the same results against the PRE-execution history (what the probe
    # previously called 'replay'); this double-executes, exactly as it does on the SDKs
    # scored PASS, so the uniform verdict is partial(STATE), not a pydantic-only FAIL.
    LEDGER.clear()
    agent_r = build()
    resr = agent_r.run_sync("pay")
    outr = resr.output
    tcr = outr.approvals[0].tool_call_id
    resultsr = outr.build_results(approvals={tcr: ToolApproved()})
    pre_hist = resr.all_messages()
    rollback_execs = 0
    for _ in range(2):
        try:
            agent_r.run_sync(message_history=pre_hist, deferred_tool_results=resultsr)
        except Exception as e:
            log3.append(f"T3 rollback: raised {type(e).__name__}: {str(e)[:80]}")
    rollback_execs = len(LEDGER)
    log3.append(f"T3 rollback: same results re-applied to pre-execution history twice = {LEDGER}")
    levels3 = {
        "same_call": "re-exec" if same_call_replay else "rejected (no unprocessed tool calls)",
        "rollback": "double-exec" if rollback_execs >= 2 else "resist",
        "cross_call": "n/a",
    }
    outcome3 = "fail" if same_call_replay else ("partial" if rollback_execs >= 2 else "pass")
    rows.append(row(RT, VER, "T3_P3_single_use", outcome3,
        write_evidence("pydantic_ai", "T3", "\n".join(log3)),
        "replay against the post-execution history is rejected (no unprocessed tool calls), "
        "but the approval has no nonce/consumption of its own: re-applying the same results "
        "to the pre-execution history (a rollback) double-executes — the same behaviour as "
        "openai-agents/langgraph/agno.",
        mechanism="post-exec replay vs rollback", qualifier="STATE", levels=levels3))

    # ---- T4: who renders ----
    log4 = ["T4: DeferredToolRequests.approvals are ToolCallPart objects exposing tool_name "
            "and structured args (framework data) for the integrator to render; Pydantic AI "
            "ships no card UI and no trusted path. There is also a per-call metadata channel. "
            "Nothing forces structured rendering over showing the model's own text."]
    rows.append(row(RT, VER, "T4_P4_trusted_rendering", "partial",
        write_evidence("pydantic_ai", "T4", "\n".join(log4)),
        "structured tool name/args are available for a trusted card, but the framework "
        "renders nothing and enforces no trusted path or untrusted-text separation.",
        mechanism="DeferredToolRequests.approvals (ToolCallPart)", qualifier="INT",
        judgement="source/API review: DeferredToolRequests.approvals ToolCallParts are exposed as structured data and the framework ships no renderer or untrusted-text box; no rendering experiment can select PASS/PART/FAIL, so PART/INT is the auditor's reading of the API surface"))

    # ---- T5: non-repudiation ----
    log5 = ["T5: ToolApproved/ToolDenied are plain dataclasses; DeferredToolResults carries "
            "no signature, key, or principal. Not third-party verifiable."]
    rows.append(row(RT, VER, "T5_P5_non_repudiation", "fail",
        write_evidence("pydantic_ai", "T5", "\n".join(log5)),
        "approval is an unsigned dataclass decision; no cryptographic receipt.",
        mechanism="unsigned ToolApproved/DeferredToolResults",
        judgement='source/API review: ToolApproved/DeferredToolResults are unsigned dataclasses; absence of any signing/receipt code path was established by reading the API, not by an experiment whose observed value selects FAIL'))

    # ---- T6: flood resistance WITHIN A SINGLE RUN ----
    # Uniform P7: one model turn emits 20 tool calls -> 20 pending approvals in ONE run.
    log6 = []
    from pydantic_ai.models.function import FunctionModel as _FM

    def _many(messages, info):
        called = any(isinstance(p, ToolCallPart) for m in messages
                     for p in getattr(m, "parts", []))
        if not called:
            return ModelResponse(parts=[ToolCallPart(
                tool_name="wire_transfer", args={"amount": 1, "to": f"r{i}"},
                tool_call_id=f"c{i}") for i in range(20)])
        return ModelResponse(parts=[TextPart(content="done")])
    af = Agent(_FM(_many), output_type=[str, DeferredToolRequests])

    @af.tool_plain(requires_approval=True, name="wire_transfer")
    def wt(amount: int, to: str) -> str:
        return "ok"
    rf = af.run_sync("pay")
    n = len(rf.output.approvals) if isinstance(rf.output, DeferredToolRequests) else 0
    log6.append(f"T6 (single run): one model turn emitted 20 tool calls -> {n} pending "
                "approvals in ONE run, no throttle/cap.")
    rows.append(row(RT, VER, "T6_P7_flood_resistance", "fail" if n >= 20 else "partial",
        write_evidence("pydantic_ai", "T6", "\n".join(log6)),
        f"a single model turn raised {n} pending approvals in one run; no built-in rate "
        "limit / pending cap.",
        mechanism="parallel tool calls in one run"))

    emit(rows)


main()
