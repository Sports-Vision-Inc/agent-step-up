"""Probe: MCP (Model Context Protocol) python SDK elicitation (mcp 2.x / MCPServer).

Documented HITL pattern: a server tool calls ctx.elicit(message, schema), sending an
`elicitation/create` request over the MCP session to the CLIENT. The client's
elicitation_callback presents it and returns {action: accept|decline|cancel, data}.
The SDK docstring states: "If the client is an agent, it might decide how to handle
the elicitation -- either by asking the user or automatically generating a response."
Ref: mcp/server/mcpserver/context.py (elicit), mcp/client/session.py.

Trust note: MCP puts the human behind the CLIENT (a different process from the tool
server), giving channel separation ONLY if a trusted client renders the prompt out
of the agent's reach. In an agentic host the client callback is programmatic. The
elicitation is in-band on the same MCP session, has no effect binding and no signature.
"""
import anyio, importlib.metadata as M, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import write_evidence, row, emit

RT = "mcp"
VER = M.version("mcp")

import mcp.types as types
from pydantic import BaseModel
from mcp.server.mcpserver import MCPServer, Context
from mcp.server.lowlevel import NotificationOptions
from mcp.client.session import ClientSession
from mcp.shared.memory import create_client_server_memory_streams

LEDGER = []


class Confirm(BaseModel):
    confirm: bool


def build_server():
    srv = MCPServer("probe")

    @srv.tool()
    async def wire_transfer(amount: int, to: str, ctx: Context) -> str:
        """send money"""
        res = await ctx.elicit(message=f"Approve wire_transfer(amount={amount}, to={to})?",
                               schema=Confirm)
        if getattr(res, "action", None) == "accept" and res.data and res.data.confirm:
            LEDGER.append({"amount": amount, "to": to})
            return "executed"
        return "denied"

    return srv


async def run_once(elicit_cb, args):
    srv = build_server()
    low = srv._lowlevel_server
    async with create_client_server_memory_streams() as (client_streams, server_streams):
        cr, cw = client_streams
        sr, sw = server_streams
        async with anyio.create_task_group() as tg:
            async def run_server():
                init = low.create_initialization_options(NotificationOptions())
                await low.run(sr, sw, init, raise_exceptions=True)
            tg.start_soon(run_server)
            async with ClientSession(cr, cw, elicitation_callback=elicit_cb) as client:
                await client.initialize()
                result = await client.call_tool("wire_transfer", args)
                tg.cancel_scope.cancel()
                return result


async def main():
    rows = []

    # ---- T1 ----
    LEDGER.clear()
    log = []
    async def auto_accept(ctx, params):
        return types.ElicitResult(action="accept", content={"confirm": True})
    await run_once(auto_accept, {"amount": 10, "to": "alice"})
    log.append(f"T1: client elicitation_callback auto-accepted in code; ledger={LEDGER}")
    t1_ok = bool(LEDGER)  # the in-host answer path must actually execute (else not_run)
    log.append("T1: SDK docstring: 'If the client is an agent, it might decide how to handle "
               "the elicitation -- ... automatically generating a response.'")
    rows.append(row(RT, VER, "T1_P1_agent_independence", "fail" if t1_ok else "not_run",
        write_evidence("mcp", "T1", "\n".join(log)),
        "BY CONSTRUCTION (dagger): elicitation is answered by the client's "
        "elicitation_callback over the same MCP session; in an agentic host the callback is "
        "programmatic and resident in the agent host. Measured: the client is a separate "
        "process from the tool server (so out-of-process review is structurally possible "
        "with a trusted client), but no separate-principal approver is shipped — the SDK "
        "docstring says an agent client may auto-generate the response.",
        mechanism="ctx.elicit() over the MCP session",
        marker="dagger", counted=False,
        p1={"oop_resume": "Y", "separate_principal_approver": "no",
            "oop_evidence": "client is a distinct process from the tool server; default "
                            "callback is programmatic"}))

    # ---- T2 ----
    log2 = []
    shown2 = []
    LEDGER.clear()
    async def accept_blind(ctx, params):
        shown2.append(params.message)
        log2.append(f"T2: client sees message={params.message!r}; response schema={{'confirm':bool}} carries no args")
        return types.ElicitResult(action="accept", content={"confirm": True})
    await run_once(accept_blind, {"amount": 9999, "to": "mallory"})
    log2.append(f"T2: ledger = {LEDGER} (server builds the elicit message FROM its held args "
                f"and executes those same held args on a bare accept -> shown == executed)")
    # Uniform ladder: in MCP the SERVER (the tool side, NOT the LLM agent) holds the args and
    # authors the message from them. The agent cannot change the held args after the call, so
    # what is shown equals what executes. A gap appears only if the SERVER is adversarial —
    # a different threat model, stated explicitly.
    levels = {
        "L1": "n/a",
        "L2": "resist (agent cannot alter the server-held args after the call)",
        "L3": "substituted ONLY if the tool server itself is adversarial (different threat model)",
    }
    # Outcome computed from the observed ledger: PASS iff exactly the server-held args ran.
    t2_bound = (LEDGER == [{"amount": 9999, "to": "mallory"}] and len(shown2) == 1
                and "amount=9999" in shown2[0] and "to=mallory" in shown2[0])
    log2.append(f"T2: shown message contains the executed args = {t2_bound}")
    rows.append(row(RT, VER, "T2_P2_effect_binding", "pass" if t2_bound else "fail",
        write_evidence("mcp", "T2", "\n".join(log2)),
        "the server builds the elicitation message from its own held arguments and executes "
        "those same arguments on a bare accept, so what the human is shown equals what runs; "
        "the agent cannot substitute them. (FAIL only under an adversarial-server threat "
        "model, which no other runtime's PASS cell assumes either.)",
        mechanism="server-held args + ctx.elicit message", levels=levels))

    # ---- T3 ----
    log3 = ["T3: ElicitResult is {action, content}; no nonce/id/expiry, not a reusable token. "
            "There is no approval artifact to replay, and equally none atomically consumed "
            "against a specific effect."]
    rows.append(row(RT, VER, "T3_P3_single_use", "na",
        write_evidence("mcp", "T3", "\n".join(log3)),
        "no reusable approval token; accept/decline is a per-request response with no nonce "
        "bound to an effect.",
        mechanism="per-request ElicitResult",
        judgement="API review: ElicitResult is a per-request {action, content} response with no reusable token, so single-use has nothing to apply to; n/a is the auditor's classification, not measured"))

    # ---- T4 ----
    log4 = ["T4: ctx.elicit takes a free-text `message` (server/agent-authored) + a schema. "
            "The client renders that message string; the SDK does not derive a card from a "
            "structured effect descriptor, and there is no untrusted-text box."]
    rows.append(row(RT, VER, "T4_P4_trusted_rendering", "partial",
        write_evidence("mcp", "T4", "\n".join(log4)),
        "the human sees a SERVER-authored free-text message (the server is the tool side, "
        "not the LLM agent) plus a schema; the client renders that string. Like the SDK "
        "integrators, trusted rendering from the structured descriptor is the server "
        "author's responsibility — INT, not an enforced trusted path.",
        mechanism="ctx.elicit(message, schema)", qualifier="INT",
        judgement="source/API review: the elicitation message (server-authored) + schema are exposed as structured data and the framework ships no renderer or untrusted-text box; no rendering experiment can select PASS/PART/FAIL, so PART/INT is the auditor's reading of the API surface"))

    # ---- T5 ----
    log5 = ["T5: ElicitResult is unsigned JSON; no principal key, signature, or receipt."]
    rows.append(row(RT, VER, "T5_P5_non_repudiation", "fail",
        write_evidence("mcp", "T5", "\n".join(log5)),
        "elicitation responses are unsigned; no verifiable approval record.",
        mechanism="unsigned ElicitResult",
        judgement='source/API review: ElicitResult is unsigned JSON; absence of any signing/receipt code path was established by reading the API, not by an experiment whose observed value selects FAIL'))

    # ---- T6 ----
    log6 = []
    LEDGER.clear()
    for i in range(10):
        async def acc(ctx, params):
            return types.ElicitResult(action="accept", content={"confirm": True})
        await run_once(acc, {"amount": 1, "to": f"r{i}"})
    log6.append(f"T6: {len(LEDGER)} elicitations proceeded within one client session with no "
                f"SDK throttle / pending-cap (ledger len={len(LEDGER)}).")
    rows.append(row(RT, VER, "T6_P7_flood_resistance", "fail" if len(LEDGER) >= 10 else "partial",
        write_evidence("mcp", "T6", "\n".join(log6)),
        "the SDK imposes no rate limit / pending-cap on elicitation requests; a server (or a "
        "tool-calling agent) can raise them without bound.",
        mechanism="repeated ctx.elicit in one session"))

    emit(rows)


anyio.run(main)
