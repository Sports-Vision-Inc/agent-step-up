"""Probe: AutoGen / AG2 UserProxyAgent human confirmation (autogen-agentchat).

Documented HITL pattern: add a UserProxyAgent to a team. When it is that agent's
turn, on_messages() emits a UserInputRequestedEvent and calls input_func(prompt)
(default cancellable_input over stdin) to get the user's reply, which re-enters the
conversation as a TextMessage/HandoffMessage. This is a conversational turn, not an
effect-bound approval. Ref: autogen_agentchat/agents/_user_proxy_agent.py.
"""
import asyncio, importlib.metadata as M, sys, os, inspect
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import write_evidence, row, emit

RT = "autogen-agentchat"
VER = M.version("autogen-agentchat")

from autogen_agentchat.agents import UserProxyAgent
from autogen_agentchat.messages import TextMessage
from autogen_core import CancellationToken


async def main():
    rows = []

    # ---- T1: input_func is programmatic, same channel ----
    log = []
    answered = {"n": 0}

    def auto_input(prompt: str) -> str:
        answered["n"] += 1
        return "APPROVE"  # auto-answer in-process

    up = UserProxyAgent("user", input_func=auto_input)
    resp = await up.on_messages([TextMessage(content="May I wire $10 to alice?", source="agent")],
                                CancellationToken())
    log.append(f"T1: UserProxyAgent returned {resp.chat_message.content!r} via in-process input_func "
               f"(called {answered['n']}x); default input_func is cancellable_input (stdin).")
    t1_ok = resp.chat_message.content == "APPROVE" and answered["n"] == 1
    rows.append(row(RT, VER, "T1_P1_agent_independence", "fail" if t1_ok else "not_run",
        write_evidence("autogen", "T1", "\n".join(log)),
        "BY CONSTRUCTION (dagger): the user's reply is produced by input_func (default stdin "
        "of the agent process); any code in the process answers it, and the reply re-enters "
        "the same message stream the agent drives. No out-of-band factor; no separate-"
        "principal approver.",
        mechanism="UserProxyAgent.input_func",
        marker="dagger", counted=False,
        p1={"oop_resume": "N", "separate_principal_approver": "no",
            "oop_evidence": "input_func default is cancellable_input on process stdin"}))

    # ---- T2: effect-binding ----
    # Consistency rule (AUD-8): UserProxyAgent is a conversational turn, not an effect-bound
    # approval. Mark n/a (as smolagents' absent gate is n/a); the documented pre-execution
    # GATE is CodeExecutorAgent(approval_func=...), probed as a separate row below.
    log2 = ["T2: UserProxyAgent yields a free-text reply into the conversation; it gates no "
            "specific tool call and carries no effect descriptor. It is a conversational turn, "
            "not an approval — reported n/a. The approval mechanism is "
            "CodeExecutorAgent(approval_func=...); see the gate row."]
    rows.append(row(RT, VER, "T2_P2_effect_binding", "na",
        write_evidence("autogen", "T2", "\n".join(log2)),
        "UserProxyAgent is a conversational input turn, not an effect-bound approval; scored "
        "n/a for consistency. See the CodeExecutorAgent.approval_func gate row.",
        mechanism="UserProxyAgent conversational turn",
        judgement='UserProxyAgent (a conversational input turn) is not an effect-bound approval mechanism (auditor classification from its documented purpose); scored n/a for consistency, not measured'))

    # ---- T3: single use ----
    log3 = ["T3: the reply is a chat message with no nonce/expiry/consumption semantics; it is "
            "ordinary conversation history and can be reused/re-sent by the orchestrator."]
    rows.append(row(RT, VER, "T3_P3_single_use", "na",
        write_evidence("autogen", "T3", "\n".join(log3)),
        "no approval token exists to be single-use; the reply is plain conversation text.",
        mechanism="UserProxyAgent conversational turn",
        judgement='UserProxyAgent (a conversational input turn) is not an effect-bound approval mechanism (auditor classification from its documented purpose); scored n/a for consistency, not measured'))

    # ---- T4: who renders ----
    log4 = ["T4: the prompt shown is a fixed 'Enter your response:' string; the user reacts to "
            "the preceding conversation (model narration). UserProxy is a conversational turn, "
            "not an approval card — reported n/a; the gate's rendering is in the gate row."]
    rows.append(row(RT, VER, "T4_P4_trusted_rendering", "na",
        write_evidence("autogen", "T4", "\n".join(log4)),
        "UserProxyAgent is a conversational turn, not an approval card; scored n/a for "
        "consistency. Trusted rendering of the gate is assessed in the approval_func row.",
        mechanism="UserProxyAgent conversational turn",
        judgement='UserProxyAgent (a conversational input turn) is not an effect-bound approval mechanism (auditor classification from its documented purpose); scored n/a for consistency, not measured'))

    # ---- T5: non-repudiation ----
    log5 = ["T5: the reply is an unsigned TextMessage appended to history; no key, signature, "
            "or receipt. Not third-party verifiable."]
    rows.append(row(RT, VER, "T5_P5_non_repudiation", "fail",
        write_evidence("autogen", "T5", "\n".join(log5)),
        "approval is unsigned chat text; no verifiable record.",
        mechanism="unsigned TextMessage",
        judgement='source/API review: the reply is an unsigned TextMessage; absence of any signing/receipt code path was established by reading the API, not by an experiment whose observed value selects FAIL'))

    # ---- T6: flood resistance (UserProxy conversational turns) ----
    log6 = []
    n = 0
    for i in range(20):
        u = UserProxyAgent(f"u{i}", input_func=lambda p: "APPROVE")
        await u.on_messages([TextMessage(content=f"approve {i}?", source="agent")], CancellationToken())
        n += 1
    log6.append(f"T6: {n}/20 input requests issued back-to-back, no throttle/limit")
    rows.append(row(RT, VER, "T6_P7_flood_resistance", "fail" if n >= 20 else "partial",
        write_evidence("autogen", "T6", "\n".join(log6)),
        "no built-in rate limit / pending cap on human-input requests.",
        mechanism="UserProxyAgent conversational turn"))

    # ============ NEW ROW: the documented pre-execution GATE ============
    rows.extend(await _approval_func_rows())
    emit(rows)


GATE_RT = "autogen-agentchat (CodeExecutorAgent.approval_func)"


async def _approval_func_rows():
    """CodeExecutorAgent(approval_func=...) is a documented pre-execution approval that
    receives the EXACT code to run; without it the agent auto-approves all code and logs a
    warning. Ref: autogen_agentchat/agents/_code_executor_agent.py."""
    import tempfile
    rows = []
    try:
        from autogen_agentchat.agents import CodeExecutorAgent, ApprovalRequest, ApprovalResponse
        from autogen_ext.code_executors.local import LocalCommandLineCodeExecutor
    except Exception as e:
        return [row(GATE_RT, VER, t, "not_run",
                    write_evidence("autogen_gate", t, f"approval_func API unavailable: {e!r}"),
                    f"CodeExecutorAgent.approval_func not importable: {e!r}")
                for t in ("T1_P1_agent_independence", "T2_P2_effect_binding",
                          "T3_P3_single_use", "T4_P4_trusted_rendering",
                          "T5_P5_non_repudiation", "T6_P7_flood_resistance")]

    seen = []

    def approve(req):
        seen.append(req.code)
        return ApprovalResponse(approved=True, reason="ok")

    ex = LocalCommandLineCodeExecutor(work_dir=tempfile.mkdtemp())
    agent = CodeExecutorAgent("x", code_executor=ex, approval_func=approve)
    outputs = []
    code_block = "```python\nprint('ledger amount=10 to=acct-a')\n```"
    for i in range(2):
        r = await agent.on_messages([TextMessage(content=code_block, source="user")],
                                    CancellationToken())
        outputs.append(r.chat_message.content.strip())

    # T1: approval_func is called in-process (the host supplies it).
    t1_gate_ok = len(seen) == 2 and len(outputs) == 2
    rows.append(row(GATE_RT, VER, "T1_P1_agent_independence", "fail" if t1_gate_ok else "not_run",
        write_evidence("autogen_gate", "T1",
            f"approval_func called {len(seen)}x in process; outputs={outputs}"),
        "BY CONSTRUCTION (dagger): approval_func is a callback the host supplies and that runs "
        "in the agent process; no out-of-band factor, no separate-principal approver.",
        mechanism="CodeExecutorAgent(approval_func=...)",
        marker="dagger", counted=False,
        p1={"oop_resume": "N", "separate_principal_approver": "no",
            "oop_evidence": "approval_func is an in-process callback"}))

    # T2: the approved text equals the executed code (the callback receives the exact code).
    bound = all("ledger amount=10 to=acct-a" in c for c in seen) and len(seen) == 2
    rows.append(row(GATE_RT, VER, "T2_P2_effect_binding", "pass" if bound else "fail",
        write_evidence("autogen_gate", "T2",
            f"approved code (per call) = {[c.replace(chr(10),' | ') for c in seen]}; "
            f"executions={len(outputs)}"),
        "the approval callback receives the exact code that will run and execution uses that "
        "same code, so the approved effect equals the executed effect (local binding)."
        if bound else "approved text did not match executed code.",
        mechanism="approval_func receives the exact code",
        levels={"L1": "n/a", "L2": "resist (same code object approved and executed)", "L3": "n/a"}))

    # T3: approval is requested per execution.
    rows.append(row(GATE_RT, VER, "T3_P3_single_use", "pass" if len(seen) == 2 else "fail",
        write_evidence("autogen_gate", "T3",
            f"{len(outputs)} executions required {len(seen)} approvals (one per execution)"),
        "each code execution requests its own approval; a prior approval does not carry over.",
        mechanism="per-execution approval_func",
        levels={"same_call": "re-approved", "rollback": "n/a", "cross_call": "re-approved"}))

    # T4: the callback receives the structured code; rendering is the integrator's.
    rows.append(row(GATE_RT, VER, "T4_P4_trusted_rendering", "partial",
        write_evidence("autogen_gate", "T4",
            "ApprovalRequest exposes the exact code + context to approval_func; the SDK ships "
            "no card UI and no untrusted-text box."),
        "the exact code is available to a trusted renderer, but the SDK renders nothing; "
        "rendering is the integrator's responsibility (INT).",
        mechanism="ApprovalRequest.code", qualifier="INT",
        judgement="source/API review: ApprovalRequest.code/context are exposed as structured data and the framework ships no renderer or untrusted-text box; no rendering experiment can select PASS/PART/FAIL, so PART/INT is the auditor's reading of the API surface"))

    rows.append(row(GATE_RT, VER, "T5_P5_non_repudiation", "fail",
        write_evidence("autogen_gate", "T5",
            "ApprovalResponse(approved: bool, reason) is unsigned; no receipt."),
        "the approval response is an unsigned dataclass; no verifiable record.",
        mechanism="unsigned ApprovalResponse",
        judgement='source/API review: ApprovalResponse(approved, reason) is an unsigned dataclass; absence of any signing/receipt code path was established by reading the API, not by an experiment whose observed value selects FAIL'))

    rows.append(row(GATE_RT, VER, "T6_P7_flood_resistance", "not_run",
        write_evidence("autogen_gate", "T6",
            "single-run flood of approval_func requests not exercised here."),
        "flood resistance of the gate not measured here.",
        mechanism="CodeExecutorAgent(approval_func=...)"))
    return rows


asyncio.run(main())
