"""Reproducibility guards for the headline attack-suite findings.

Each test runs a probe directly and asserts the specific executed outcome, so a
regression in a target (or in our probe) is caught. Probes that need a missing
clone/env are skipped, not failed.
"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from attacks.probes import ap2_probe, agt_probe, mcp_probe, openclaw_probe  # noqa: E402


def _by_attack(rows):
    return {r["attack_id"]: r for r in rows}


@pytest.mark.skipif(not ap2_probe._available(), reason="AP2 clone not present")
def test_ap2_binds_amount_payee_currency():
    r = _by_attack(ap2_probe.run())
    # AP2 enforces single typed amount, payee-by-id, and currency at the constraint layer.
    assert r["AB1"]["outcome"] == "not_vulnerable"
    assert r["AB2"]["outcome"] == "not_vulnerable"
    assert r["AB3"]["outcome"] == "not_vulnerable"
    # Display-vs-binding gap in the sample card, and integrator-dependent budget splitting.
    assert r["AB6"]["outcome"] in ("partial", "not_vulnerable")
    assert r["AB12"]["outcome"] == "partial"


@pytest.mark.skipif(not agt_probe._available(), reason="AGT clone not present")
def test_agt_action_binding_blocks_substitution():
    r = _by_attack(agt_probe.run())
    assert r["AB10"]["outcome"] == "not_vulnerable"   # digest mismatch on substitution
    assert r["AB2"]["outcome"] == "not_vulnerable"    # full-parameters digest, no decoy target
    assert r["AB5"]["outcome"] == "not_vulnerable"    # advisory LLM cannot resolve
    assert r["AB11"]["outcome"] == "partial"          # no in-module rate limit


@pytest.mark.skipif(not mcp_probe._available(), reason="MCP env not present")
def test_mcp_elicitation_message_unsanitized():
    r = _by_attack(mcp_probe.run())
    assert r["AB4"]["outcome"] == "vulnerable"
    assert r["AB5"]["outcome"] == "vulnerable"
    assert r["AB6"]["outcome"] == "vulnerable"


@pytest.mark.skipif(not openclaw_probe._available(), reason="OpenClaw bundle not present")
def test_openclaw_sanitizes_exec_card():
    r = _by_attack(openclaw_probe.run())
    # Positive control: OpenClaw does the escape/collapse/cap that ASU RT-5 flags as missing.
    assert r["AB4"]["outcome"] == "not_vulnerable"
    assert r["AB3"]["outcome"] in ("partial", "not_vulnerable")


@pytest.mark.skipif(not mcp_probe._available(), reason="MCP env not present")
def test_mcp_elicitation_attacks_are_executed_not_static():
    r = _by_attack(mcp_probe.run())
    for ab in ("AB4", "AB5", "AB6"):
        assert r[ab]["executed"], r[ab]["note"]
