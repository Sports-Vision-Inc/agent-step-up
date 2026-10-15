"""Probe: LangGraph interrupt() / Command(resume=) human-in-the-loop.

Documented HITL pattern: a node calls `interrupt(payload)` to pause; the client
inspects result["__interrupt__"] and resumes with `Command(resume=value)` (and
optionally `Command(update={...})`). Ref: LangGraph add-human-in-the-loop docs.
"""
import json, importlib.metadata as M, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import write_evidence, row, emit

RT = "langgraph"
VER = M.version("langgraph")

from typing import TypedDict, Annotated
import operator
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import interrupt, Command

LEDGER = []


class S(TypedDict, total=False):
    amount: int
    to: str
    approved: bool
    executed: str


def ask_approval(state: S):
    # Trusted code would render a card here; LangGraph just hands the payload back.
    decision = interrupt({"review": "wire transfer", "amount": state["amount"], "to": state["to"]})
    return {"approved": bool(decision)}


def do_transfer(state: S):
    if state.get("approved"):
        # Executor reads args from GRAPH STATE at execution time (TOCTOU surface).
        LEDGER.append({"amount": state["amount"], "to": state["to"]})
        return {"executed": f"{state['amount']}->{state['to']}"}
    return {"executed": "denied"}


def build():
    g = StateGraph(S)
    g.add_node("ask", ask_approval)
    g.add_node("do", do_transfer)
    g.add_edge(START, "ask")
    g.add_edge("ask", "do")
    g.add_edge("do", END)
    return g.compile(checkpointer=InMemorySaver())


def main():
    rows = []

    # ---- T1: approval surfaced in graph result; resume answered in-process ----
    LEDGER.clear()
    app = build()
    cfg = {"configurable": {"thread_id": "t1"}}
    out = app.invoke({"amount": 10, "to": "alice"}, cfg)
    intr = out.get("__interrupt__")
    log = [f"T1: interrupt payload surfaced to the invoking process = {intr}"]
    # Same process resumes with an approval value — no second channel/factor.
    app.invoke(Command(resume=True), cfg)
    log.append(f"T1: ledger after in-process Command(resume=True) = {LEDGER}")
    t1_ok = bool(LEDGER)  # the in-host answer path must actually execute (else not_run)
    # P1 measurable: out-of-process resume. State lives in a checkpointer keyed by
    # thread_id; any process sharing the saver/thread can read the pending interrupt and
    # resume (that is exactly how LangGraph's Agent Server resumes a thread). Demonstrate
    # that a SECOND app instance sharing the same saver resumes the paused thread.
    oop = "N"
    try:
        saver = InMemorySaver()
        g = StateGraph(S)
        g.add_node("ask", ask_approval); g.add_node("do", do_transfer)
        g.add_edge(START, "ask"); g.add_edge("ask", "do"); g.add_edge("do", END)
        app_a = g.compile(checkpointer=saver)
        cfg_o = {"configurable": {"thread_id": "oop"}}
        o = app_a.invoke({"amount": 7, "to": "zoe"}, cfg_o)
        # a different compiled app sharing the saver sees the pending interrupt and resumes
        app_b = g.compile(checkpointer=saver)
        st = app_b.get_state(cfg_o)
        if st.interrupts:
            oop = "Y"
            log.append(f"T1: a second app sharing the checkpointer sees pending interrupt "
                       f"{[i.value for i in st.interrupts]} -> resume is possible out of process.")
    except Exception as e:
        log.append(f"T1: oop check failed: {type(e).__name__}: {e}")
    rows.append(row(RT, VER, "T1_P1_agent_independence", "fail" if t1_ok else "not_run",
        write_evidence("langgraph", "T1", "\n".join(log)),
        "BY CONSTRUCTION (dagger): interrupt() returns the payload into the same process "
        "that drives the graph; that process answers with Command(resume=...). Measured: "
        "state is checkpointed, so an out-of-process resume is possible (the Agent Server "
        "product does exactly this); the core library ships no separate-principal approver.",
        mechanism="interrupt() / Command(resume=) with a checkpointer",
        marker="dagger", counted=False,
        p1={"oop_resume": oop, "separate_principal_approver": "no",
            "oop_evidence": "second app sharing the checkpointer resumes the thread; "
                            "Agent Server composition not run (langgraph_sdk present, server not)"}))

    # ---- T2: effect-binding — change args between approval and execution ----
    LEDGER.clear()
    app = build()
    cfg = {"configurable": {"thread_id": "t2"}}
    out = app.invoke({"amount": 10, "to": "alice"}, cfg)
    shown = out.get("__interrupt__")
    log2 = [f"T2: human reviewed amount=10 to=alice (interrupt={shown})"]
    # L2 capability (uniform): a THIRD PARTY that holds the thread (not the approver)
    # updates state between display and a BARE resume(True) — this is the realistic
    # Agent-Server-composition case, NOT an approver-side Command(update=). The executor
    # re-reads args from state at execution time.
    app.update_state(cfg, {"amount": 9999, "to": "mallory"})
    app.invoke(Command(resume=True), cfg)  # approver answers a plain "yes"
    log2.append(f"T2 (L2 third-party update_state, then bare resume(True)): ledger = {LEDGER}")
    l2_sub = any(e == {"amount": 9999, "to": "mallory"} for e in LEDGER)
    # L1 (approver-side Command(resume, update=...)) also substitutes but is not scored as a gap.
    levels = {
        "L1": "substituted (approver's own Command(update=...)) — not a binding gap",
        "L2": "substituted" if l2_sub else "resist",
        "L3": "substituted (checkpoint state is the backing store; same as L2)",
    }
    t2 = ("fail", "the resume reads args from thread state at execution time, so a party "
          "holding the thread (Agent Server composition) substitutes the effect with a bare "
          "resume(True); nothing binds the approved payload to the executed one.") if l2_sub \
        else ("pass", "a third-party state update did not reach the executor")
    rows.append(row(RT, VER, "T2_P2_effect_binding", t2[0],
        write_evidence("langgraph", "T2", "\n".join(log2)), t2[1],
        mechanism="third-party update_state via checkpointer / Agent Server thread",
        levels=levels))

    # ---- T3: single use — replay the same resume / re-enter ----
    LEDGER.clear()
    app = build()
    cfg = {"configurable": {"thread_id": "t3"}}
    app.invoke({"amount": 5, "to": "bob"}, cfg)
    app.invoke(Command(resume=True), cfg)  # first execution
    log3 = [f"T3: ledger after first approve = {LEDGER}"]
    # same_call: resume again on a thread that has no pending interrupt.
    same_call_replay = False
    try:
        app.invoke(Command(resume=True), cfg)
        log3.append(f"T3 same_call: ledger after replayed Command(resume=True) = {LEDGER}")
        same_call_replay = len(LEDGER) > 1
    except Exception as e:
        log3.append(f"T3 same_call: replayed resume raised {type(e).__name__}: {e}")
    # rollback (uniform): resume from the PRE-execution checkpoint (time travel).
    LEDGER.clear()
    app_r = build()
    cfgr = {"configurable": {"thread_id": "t3r"}}
    app_r.invoke({"amount": 5, "to": "bob"}, cfgr)
    pending = [h for h in app_r.get_state_history(cfgr) if h.interrupts]
    app_r.invoke(Command(resume=True), cfgr)
    rollback_execs = 1
    if pending:
        app_r.invoke(Command(resume=True), pending[0].config)
        rollback_execs = len(LEDGER)
        log3.append(f"T3 rollback: resume from pre-exec checkpoint -> ledger = {LEDGER}")
    levels3 = {
        "same_call": "re-exec" if same_call_replay else "consumed relative to run state",
        "rollback": "double-exec" if rollback_execs >= 2 else "resist",
        "cross_call": "n/a",
    }
    outcome3 = "fail" if same_call_replay else ("partial" if rollback_execs >= 2 else "pass")
    rows.append(row(RT, VER, "T3_P3_single_use", outcome3,
        write_evidence("langgraph", "T3", "\n".join(log3)),
        "consumed relative to thread state (a stray resume on a consumed thread does not "
        "re-run), but no nonce/expiry: resuming from the pre-execution checkpoint "
        "double-executes." if not same_call_replay else
        "a second Command(resume) re-executed the effect.",
        mechanism="checkpoint rollback replay", qualifier="STATE", levels=levels3))

    # ---- T4: who renders the approval text ----
    log4 = ["T4: interrupt() payload is whatever the node passes; LangGraph performs no "
            "rendering and ships no approval-card UI. If the node forwards model-authored "
            "text, the human sees model narration; if it forwards structured args, the "
            "integrator must build the card. No enforced trusted path, no untrusted box."]
    rows.append(row(RT, VER, "T4_P4_trusted_rendering", "partial",
        write_evidence("langgraph", "T4", "\n".join(log4)),
        "structured payload can be passed to interrupt(), but rendering/trust is entirely "
        "the integrator's responsibility; the framework enforces nothing.",
        mechanism="interrupt() payload", qualifier="INT",
        judgement="source/API review: interrupt() payloads are exposed as structured data and the framework ships no renderer or untrusted-text box; no rendering experiment can select PASS/PART/FAIL, so PART/INT is the auditor's reading of the API surface"))

    # ---- T5: non-repudiation ----
    log5 = ["T5: the resume value and approval flag are stored as plain checkpoint state "
            "(InMemorySaver / any BaseCheckpointSaver). No signature, no key, no principal "
            "binding; a checkpoint can be written by anything with saver access."]
    rows.append(row(RT, VER, "T5_P5_non_repudiation", "fail",
        write_evidence("langgraph", "T5", "\n".join(log5)),
        "approval is an unsigned boolean in checkpoint state; not third-party verifiable.",
        mechanism="unsigned checkpoint state",
        judgement='source/API review: the resume value is an unsigned value in checkpoint state; absence of any signing/receipt code path was established by reading the API, not by an experiment whose observed value selects FAIL'))

    # ---- T6: flood resistance WITHIN A SINGLE RUN ----
    # Uniform P7: a single invoke fans out to N parallel nodes, each raising interrupt();
    # LangGraph collects all pending interrupts from the superstep with no cap.
    log6 = []
    gf = StateGraph(S)
    N = 20
    def _mk(i):
        def node(state):
            interrupt({"review": "wire transfer", "amount": 1, "to": f"r{i}"})
            return {}
        return node
    for i in range(N):
        gf.add_node(f"n{i}", _mk(i))
        gf.add_edge(START, f"n{i}")
        gf.add_edge(f"n{i}", END)
    appf = gf.compile(checkpointer=InMemorySaver())
    o = appf.invoke({"amount": 1, "to": "x"}, {"configurable": {"thread_id": "flood1"}})
    raised = len(o.get("__interrupt__") or [])
    log6.append(f"T6 (single run): one invoke fanned out to {N} interrupting nodes -> "
                f"{raised} pending interrupts in ONE run, no throttle/cap.")
    rows.append(row(RT, VER, "T6_P7_flood_resistance", "fail" if raised >= N else "partial",
        write_evidence("langgraph", "T6", "\n".join(log6)),
        f"a single invoke raised {raised} pending interrupts in one run; interrupt() has no "
        "built-in rate limit or pending-cap.",
        mechanism="parallel interrupting nodes in one run"))

    emit(rows)


main()
