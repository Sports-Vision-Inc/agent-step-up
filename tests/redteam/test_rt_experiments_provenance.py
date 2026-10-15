"""Experiments methods critic (docs/critique/experiments.md, findings EXP-1 and EXP-9).

Asserts the SOUND behaviour; both tests fail on the current code.

1. Experiment trials must run the gateway in its deployed enrollment
   configuration, not dev_mode (tokenless first enrollment). Otherwise the
   P1/enrollment surface that the defense depends on is not what was
   measured, and enrollment squatting cannot be scored.
2. Every results manifest must record the exact source revision (git commit
   + dirty flag) so that published numbers can be traced to code.
"""
from __future__ import annotations

import json
import os

from experiments.harness import Trial
from experiments.policies import scenario_policy

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_experiment_trial_does_not_use_dev_mode_enrollment(tmp_path):
    t = Trial("asu", scenario_policy(), tmp_root=str(tmp_path))
    try:
        assert t.config.dev_mode is False, "experiments measure an insecure dev_mode gateway"
    finally:
        t.close()


def test_results_manifest_records_source_revision():
    path = os.path.join(REPO, "experiments", "results", "manifest.json")
    with open(path, "r", encoding="utf-8") as f:
        man = json.load(f)
    assert man.get("git_commit"), "manifest.json has no git commit: results cannot be tied to code"
    assert "git_dirty" in man, "manifest.json does not say whether the tree was dirty"
