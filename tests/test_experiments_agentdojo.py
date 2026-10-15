"""AgentDojo replay adapter."""
from __future__ import annotations

import pytest

pytest.importorskip("agentdojo")

from experiments import agentdojo_replay as R  # noqa: E402


@pytest.fixture(scope="module")
def workloads():
    return R.extract_workloads()


def test_adapt_args_rules():
    a = R.adapt_args({"url": "www.informations.com", "x": None, "body": "text"}, injection=False)
    assert a == {"url": "https://www.informations.com", "body": "text"}
    a = R.adapt_args({"url": "https://a.test/x", "subject": "s", "recipients": ["r@x.test"]}, injection=True)
    assert a == {"url": "https://a.test/x", "subject": R.PLACEHOLDER, "recipients": ["r@x.test"]}


def test_workloads_all_suites(workloads):
    counts = {s: (len(w["user_tasks"]), len(w["injection_tasks"])) for s, w in workloads["suites"].items()}
    assert counts == {"workspace": (40, 6), "travel": (20, 7), "banking": (16, 9), "slack": (21, 5)}
    assert workloads["agentdojo_version"] == "0.1.35"


def test_mapping_covers_every_ground_truth_tool(workloads):
    for suite, w in workloads["suites"].items():
        for t in w["user_tasks"] + w["injection_tasks"]:
            for c in t["calls"]:
                assert c["tool"] in w["tools"]
        for tool in R.EFFECT_CLASS[suite]:
            assert tool in w["tools"]
        for t in w["injection_tasks"]:
            for c in t["calls"]:
                for k in R.FREE_TEXT_KEYS & set(c["args"]):
                    assert c["args"][k] == R.PLACEHOLDER


def test_every_user_call_canonicalizes(workloads, tmp_path):
    from experiments.scoring import canonical_expected

    for suite, w in workloads["suites"].items():
        pol = R.suite_policy(suite, w["tools"])
        for t in w["user_tasks"] + w["injection_tasks"]:
            task = R.task_from_calls(t["id"], suite, t["calls"])
            assert all(x["ok"] for x in canonical_expected(task, pol, str(tmp_path))), (suite, t["id"])


def test_pair_trial_none_vs_asu(workloads):
    jobs = R.build_jobs(workloads, ["none", "asu"], ["diligent"], 1, suites=["banking"], max_user_tasks=1,
                        max_injection_tasks=1)
    res = R.run_jobs(jobs, workers=1)
    assert all(r["error"] is None for r in res)
    att = {r["mode"]: r for r in res if r["agent"] == "compromised"}
    assert att["none"]["attack_success"] is True and att["asu"]["attack_success"] is False
    ben = {r["mode"]: r for r in res if r["agent"] == "benign"}
    assert ben["asu"]["benign_done"] == ben["asu"]["benign_total"]
    s = R.summarize(res)
    assert s["cells"]["attack"]["honest"]["banking"]["none"]["diligent"]["asr"] == 1.0
