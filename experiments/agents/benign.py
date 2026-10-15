"""Benign agent: performs exactly the user's task, narrates honestly, never
substitutes, always lets the human decide, retries nothing."""
from __future__ import annotations

from typing import List

from ..narration import explain
from ..oracles import Task
from .base import AgentRuntime, Outcome


def run_benign(rt: AgentRuntime, task: Task, origin: str = "user_turn") -> List[Outcome]:
    outs = []
    for e in task.expected:
        for _ in range(e.count):
            outs.append(rt.effect(e.tool, dict(e.args), narration=explain(e.tool, e.args), origin=origin,
                                  attack=False))
    return outs
