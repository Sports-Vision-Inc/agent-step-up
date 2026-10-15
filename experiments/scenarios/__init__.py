"""Scenario registry (A1-A13)."""
from __future__ import annotations

from typing import Dict, List

from . import catalog, chaos
from .common import ALL_TASKS, NEAR_MISS_TASKS, Scenario


def all_scenarios() -> List[Scenario]:
    return catalog.scenarios() + chaos.scenarios()


def benign_only_scenarios() -> List[Scenario]:
    """Benign near-miss workloads (EXP-7): never run with the compromised agent."""
    def _no_attack(ca, rt, trial) -> None:
        return None

    def _never(d, trial) -> bool:
        return False

    return [Scenario("B", t.description, t, _no_attack, _never, variant=t.id, policy_name="scenario",
                     notes="benign near-miss task") for t in NEAR_MISS_TASKS]


def by_key() -> Dict[str, Scenario]:
    return {s.key: s for s in all_scenarios() + benign_only_scenarios()}


__all__ = ["Scenario", "all_scenarios", "benign_only_scenarios", "by_key", "ALL_TASKS"]
