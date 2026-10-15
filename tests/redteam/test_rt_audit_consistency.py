"""Red-team (audit-fairness critic): the runtime matrix must apply ONE criterion per
property across runtimes. Each test re-runs a small counter-experiment in the
runtime's isolated venv (audit/.envs/<env>) and asserts that the published
matrix cell is consistent with it. Tests skip when the venv or matrix is absent.

These assert the *correct measurement*, so they FAIL against the current
audit/results/matrix.json and pass once the matrix/probes are corrected.
See docs/critique/audit.md (findings AUD-2, AUD-3, AUD-4, AUD-6).
"""
import json
import os
import subprocess
import textwrap

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
AUDIT = os.path.join(ROOT, "audit")
MATRIX = os.path.join(AUDIT, "results", "matrix.json")


def _matrix():
    if not os.path.exists(MATRIX):
        pytest.skip("matrix.json not generated")
    with open(MATRIX) as f:
        return {(r["runtime"], r["test"]): r for r in json.load(f)}


def _run(env, code):
    py = os.path.join(AUDIT, ".envs", env, "bin", "python")
    if not os.path.exists(py):
        pytest.skip(f"venv {env} not present")
    p = subprocess.run([py, "-c", textwrap.dedent(code)], capture_output=True,
                       text=True, timeout=300, cwd=AUDIT,
                       env={**os.environ, "PYDANTIC_AI_NO_BANNER": "1"})
    lines = [l for l in p.stdout.splitlines() if l.startswith("RESULT ")]
    assert lines, f"experiment produced no RESULT line: {p.stderr[-800:]}"
    return json.loads(lines[-1][len("RESULT "):])


PYD_PRELUDE = """
import json
from pydantic_ai import Agent, ToolApproved
from pydantic_ai.tools import DeferredToolRequests
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.messages import ModelResponse, ToolCallPart, TextPart
LEDGER = []
def model_fn(messages, info):
    if not any(isinstance(p, ToolCallPart) for m in messages for p in getattr(m, "parts", [])):
        return ModelResponse(parts=[ToolCallPart(tool_name="wire_transfer",
            args={"amount": 10, "to": "alice"}, tool_call_id="call1")])
    return ModelResponse(parts=[TextPart(content="done")])
agent = Agent(FunctionModel(model_fn), output_type=[str, DeferredToolRequests])
@agent.tool_plain(requires_approval=True)
def wire_transfer(amount: int, to: str) -> str:
    LEDGER.append({"amount": amount, "to": to}); return "ok"
"""


def test_p2_same_capability_same_verdict_pydantic_vs_langgraph_agno():
    """AUD-2: LangGraph/Agno T2=FAIL because the party that holds run state can
    change the args after the human saw them. Granting that same capability against
    pydantic-ai (edit the stored message history, then a plain ToolApproved())
    also executes the substituted args, so pydantic-ai T2 must not be PASS while
    LangGraph/Agno are FAIL for the same capability."""
    m = _matrix()
    res = _run("pydantic_ai", PYD_PRELUDE + """
res = agent.run_sync("pay"); out = res.output
hist = res.all_messages()
for msg in hist:
    for p in msg.parts:
        if isinstance(p, ToolCallPart): p.args = {"amount": 9999, "to": "mallory"}
agent.run_sync(message_history=hist,
               deferred_tool_results=out.build_results(approvals={"call1": ToolApproved()}))
print("RESULT " + json.dumps({"substituted": {"amount": 9999, "to": "mallory"} in LEDGER}))
""")
    if not res["substituted"]:
        pytest.skip("substitution not reproduced on this pydantic-ai version")
    lg = m.get(("langgraph", "T2_P2_effect_binding"), {}).get("outcome")
    pyd = m.get(("pydantic-ai", "T2_P2_effect_binding"), {}).get("outcome")
    assert not (lg == "fail" and pyd == "pass"), (
        "inconsistent P2 criterion: pydantic-ai executes substituted args under the "
        "same state-holder capability that makes langgraph FAIL, yet pydantic-ai is PASS")


def test_p3_same_replay_criterion_pydantic_vs_openai_agents():
    """AUD-3: pydantic-ai T3=FAIL comes from re-submitting the same approval against
    the PRE-execution history (a rollback). The identical rollback against
    openai-agents (resume the same approved RunState JSON twice) also double-executes.
    The two cells must therefore agree."""
    m = _matrix()
    res = _run("openai_agents", """
import asyncio, json, copy, sys
sys.argv = ["x"]
src = open("probes/openai_agents/probe.py").read().split("async def main():")[0]
src = src.replace("from common import write_evidence, row, emit", "")
g = {"__file__": "probes/openai_agents/probe.py"}; exec(src, g)
async def main():
    agent = g["new_agent"](); Runner = g["Runner"]; RunState = g["RunState"]
    r = await Runner.run(agent, "pay"); st = r.to_state(); st.approve(r.interruptions[0])
    js = st.to_json()
    for _ in range(2):
        await Runner.run(agent, await RunState.from_json(agent, copy.deepcopy(js)))
    print("RESULT " + json.dumps({"executions": len(g["LEDGER"])}))
asyncio.run(main())
""")
    oai = m.get(("openai-agents", "T3_P3_single_use"), {}).get("outcome")
    pyd = m.get(("pydantic-ai", "T3_P3_single_use"), {}).get("outcome")
    if res["executions"] >= 2:
        assert oai == pyd, (
            f"inconsistent P3 criterion: rollback replay double-executes on openai-agents "
            f"too, but matrix has openai-agents={oai}, pydantic-ai={pyd}")


def test_p3_google_adk_measured_at_documented_flow_layer():
    """AUD-4: ADK T3=FAIL was obtained by calling FunctionTool.run_async directly with a
    hand-built ToolContext, bypassing the confirmation flow that T2 credits. Through the
    real Runner, re-sending the identical confirmation does NOT re-execute (the flow
    drops already-consumed confirmations), so the matrix must not say FAIL."""
    m = _matrix()
    res = _run("google_adk", """
import asyncio, json
from google.adk.agents import LlmAgent
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_response import LlmResponse
from google.adk.runners import InMemoryRunner
from google.adk.tools.function_tool import FunctionTool
from google.genai import types
LEDGER = []
def wire_transfer(amount: int, to: str) -> dict:
    \"\"\"Send a wire transfer.\"\"\"
    LEDGER.append({"amount": amount, "to": to}); return {"ok": True}
class Stub(BaseLlm):
    model: str = "stub"
    async def generate_content_async(self, req, stream=False):
        fc = any(p.function_call for c in req.contents for p in (c.parts or []) if p.function_call)
        if not fc:
            yield LlmResponse(content=types.Content(role="model", parts=[types.Part(
                function_call=types.FunctionCall(id="fc1", name="wire_transfer",
                                                 args={"amount": 10, "to": "alice"}))]))
        else:
            yield LlmResponse(content=types.Content(role="model", parts=[types.Part(text="done")]))
async def main():
    agent = LlmAgent(name="a", model=Stub(),
                     tools=[FunctionTool(wire_transfer, require_confirmation=True)])
    runner = InMemoryRunner(agent=agent, app_name="app")
    s = await runner.session_service.create_session(app_name="app", user_id="u")
    conf = None
    async for ev in runner.run_async(user_id="u", session_id=s.id,
            new_message=types.Content(role="user", parts=[types.Part(text="pay")])):
        for fc in ev.get_function_calls():
            if fc.name == "adk_request_confirmation": conf = fc
    for _ in range(2):
        msg = types.Content(role="user", parts=[types.Part(function_response=types.FunctionResponse(
            id=conf.id, name="adk_request_confirmation", response={"confirmed": True}))])
        try:
            async for ev in runner.run_async(user_id="u", session_id=s.id, new_message=msg): pass
        except Exception:
            pass
    print("RESULT " + json.dumps({"executions": len(LEDGER)}))
asyncio.run(main())
""")
    adk = m.get(("google-adk", "T3_P3_single_use"), {}).get("outcome")
    if res["executions"] == 1:
        assert adk != "fail", ("google-adk T3 is FAIL, but an end-to-end replay of the "
                               "same confirmation through the documented Runner flow "
                               "executes the effect only once")


def test_static_only_rows_are_not_reported_as_pass():
    """AUD-6: OpenClaw rows are keyword greps over a minified bundle (e.g. P2 PASS iff the
    strings 'argv' and 'cwd' both occur in one file). A static, unexecuted review cannot
    establish that a property holds; such cells must be capped below PASS."""
    m = _matrix()
    bad = [(rt, t) for (rt, t), r in m.items()
           if r["outcome"] == "pass" and "STATIC REVIEW" in r.get("explanation", "")]
    assert not bad, f"static-only (not executed) cells reported as PASS: {bad}"
