"""Scripted agents: a fully compromised agent (attack scripts live in
``experiments.scenarios``) and a benign agent that performs exactly the
user's task with honest narration."""
from .base import AgentRuntime, HumanSim, Outcome
from .benign import run_benign
from .compromised import CompromisedAgent

__all__ = ["AgentRuntime", "HumanSim", "Outcome", "run_benign", "CompromisedAgent"]
