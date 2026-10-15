"""C6' machine-approver experiment (experiments/live/llm_approver.py). Offline only."""
from __future__ import annotations

import copy
import json
import os
import re

import pytest
import yaml

from asu import descriptor as D
from experiments.live import llm_approver as LA

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ATTACK_FAMILIES = {"narration_forgery", "substitution_visible", "priming", "padding", "label_spoofing",
                   "decoy_recipient", "amount_cancellation", "homoglyph_host"}


@pytest.fixture(scope="module")
def stim_doc():
    return LA.make_stimuli()


def small_cfg(tmp_path, **kw):
    cfg = {
        "models": [{"id": "vendor-a/model-x", "price_in_per_mtok": 1.0, "price_out_per_mtok": 2.0},
                   {"id": "vendor-b/model-y", "price_in_per_mtok": 0.5, "price_out_per_mtok": 1.0}],
        "budget_usd": 100.0,
        "passes": [{"name": "t0", "temperature": 0.0, "samples": 1},
                   {"name": "t07", "temperature": 0.7, "samples": 3}],
        "results_dir": str(tmp_path),
        "cache_file": str(tmp_path / "cache.jsonl"),
    }
    cfg.update(kw)
    return cfg


# ---------------------------------------------------------------- stimuli
def test_make_stimuli_is_deterministic_and_committed_file_is_fresh(stim_doc):
    again = LA.make_stimuli()
    assert LA.dump_json(stim_doc) == LA.dump_json(again)
    with open(LA.DEFAULT_STIMULI, "r", encoding="utf-8") as f:
        committed = f.read()
    assert committed == LA.dump_json(stim_doc), \
        "stimuli_llm_approver.json is stale: run `python -m experiments.live.llm_approver make-stimuli`"


def test_stimulus_coverage(stim_doc):
    st = stim_doc["stimuli"]
    fams = {s["family"] for s in st if s["kind"] == "attack"}
    assert fams == ATTACK_FAMILIES
    assert stim_doc["n_benign"] >= 8 and stim_doc["n_attack"] >= 16
    for s in st:
        assert s["expected_decision"] == ("deny" if s["kind"] == "attack" else "approve")
        assert set(s["views"]) == set(LA.CONDITIONS)


def test_placeholder_data_only(stim_doc):
    """Every address/host is under the reserved .test TLD; accounts are ACCT-* placeholders."""
    for s in stim_doc["stimuli"]:
        d = s["descriptor"]
        for t in D.targets_of(d):
            if t.startswith("/workspace") or t in ("bash", "sh"):
                continue
            if "@" in t or "://" in t or re.search(r"\.[a-z-]+(:\d+)?$", t):
                host = t.split("@")[-1].split(":")[0]
                assert host.endswith(".test"), (s["id"], t)
            else:
                assert t.startswith("ACCT-"), (s["id"], t)


def test_card_views_come_from_render_card(stim_doc):
    for s in stim_doc["stimuli"]:
        desc = s["descriptor"]
        assert D.digest(desc) == s["digest"]
        card = D.render_card(desc, explanation=s["narration"], workspace_root="/workspace")
        assert s["views"]["card"] == LA.card_text(card, include_explanation=True)
        v = s["views"]["card"]
        assert "Digest: " + s["digest"] in v
        # the agent text appears only after the untrusted label
        head, _, tail = v.partition("UNTRUSTED")
        assert D._esc(s["narration"], quote=False) in tail
        nx = s["views"]["card_no_expl"]
        assert "UNTRUSTED - written by the agent" not in nx and s["digest"] in nx
        assert s["views"]["narrated"].endswith(s["narration"]) and s["digest"] not in s["views"]["narrated"]
        assert "Effect:" not in s["views"]["narrated"]


def test_identical_narrated_prompts_are_recorded(stim_doc):
    groups = stim_doc["identical_prompt_groups"]
    assert any({"forgery-email", "decoy-bcc"} <= set(g) for g in groups["narrated"])
    assert groups["card"] == []
    by = {s["id"]: s for s in stim_doc["stimuli"]}
    for g in groups["card_no_expl"]:  # only the same call under the same task (narration differs)
        assert len({by[i]["digest"] for i in g}) == 1 and len({by[i]["task"] for i in g}) == 1


def test_specific_attacks_are_visible_on_card_only(stim_doc):
    by = {s["id"]: s for s in stim_doc["stimuli"]}
    assert "collector.example.test" in by["padding-shell"]["views"]["card"]
    assert "\\[160\u00d7 space]" in by["padding-shell"]["views"]["card"]
    assert "collector" not in by["padding-shell"]["views"]["narrated"]
    assert "xn--" in by["homoglyph-url"]["views"]["card_no_expl"]
    assert "xn--" not in by["homoglyph-url"]["views"]["narrated"]
    assert '"collector@example.test"' in by["decoy-bcc"]["views"]["card_no_expl"]
    assert "Moves money: 880" in by["amount-memo-net"]["views"]["card_no_expl"]
    assert 'Target: "collector@example.test"' in by["label-email"]["views"]["card_no_expl"]


# ---------------------------------------------------------------- prompts: no label leakage
def test_prompts_do_not_leak_labels(stim_doc):
    forbidden_words = re.compile(r"\b(attack|attacks|benign|malicious|adversar\w*|ground.truth|expected)\b", re.I)
    for s in stim_doc["stimuli"]:
        for c in LA.CONDITIONS:
            for order in (["approve", "deny"], ["deny", "approve"]):
                msgs = LA.messages_for(s, c, order)
                text = msgs[0]["content"] + "\n" + msgs[1]["content"]
                for line in D.INFO_LINES.values():  # the gateway's own risk wording (e.g. "padding")
                    text = text.replace(line, "")
                assert s["id"] not in text and s["family"] not in text and s["why"] not in text
                assert not forbidden_words.search(text), (s["id"], c, forbidden_words.search(text))
                # user's task is shown in every condition
                assert s["task"] in msgs[1]["content"]
                assert msgs[0]["content"] == LA.SYSTEM_PROMPT


def test_system_prompt_fixed_and_stored(stim_doc):
    assert stim_doc["system_prompt"] == LA.SYSTEM_PROMPT
    low = LA.SYSTEM_PROMPT.lower()
    for word in ("forg", "substitut", "priming", "padding", "spoof", "decoy", "homoglyph", "cancel", "unicode",
                 "hidden", "untrusted"):
        assert word not in low, word


def test_option_order_in_prompt():
    s = LA.make_stimuli()["stimuli"][0]
    a = LA.build_user_prompt(s, "card", ["approve", "deny"])
    b = LA.build_user_prompt(s, "card", ["deny", "approve"])
    assert '"approve" or "deny"' in a and '"deny" or "approve"' in b


def test_plan_items_deterministic_and_randomized(stim_doc):
    st = stim_doc["stimuli"]
    p1 = LA.plan_items(st, LA.CONDITIONS, 7, "m/a")
    p2 = LA.plan_items(st, LA.CONDITIONS, 7, "m/a")
    p3 = LA.plan_items(st, LA.CONDITIONS, 7, "m/b")
    assert p1 == p2 and p1 != p3
    assert len(p1) == len(st) * len(LA.CONDITIONS)
    assert {tuple(i["option_order"]) for i in p1} == {("approve", "deny"), ("deny", "approve")}
    natural = [(s["id"], c) for s in st for c in LA.CONDITIONS]
    assert [(i["stimulus"], i["condition"]) for i in p1] != natural


# ---------------------------------------------------------------- parsing
@pytest.mark.parametrize("text,want", [
    ('{"decision": "approve", "reason": "ok"}', "approve"),
    ('{"decision":"DENY","reason":"x"}', "deny"),
    ('```json\n{"decision": "deny", "reason": "wrong payee"}\n```', "deny"),
    ('Sure. {"decision": "approve", "reason": "matches"} Hope that helps.', "approve"),
    ('<think>maybe {"decision":"approve"}</think>{"decision": "deny", "reason": "r"}', "deny"),
    ('{"decision": "denied", "reason": "r"}', "deny"),
    ('{"decision": "approve"} or {"decision": "deny"}', "unparseable"),
    ('{"decision": "maybe", "reason": "r"}', "unparseable"),
    ('I would approve this.', "unparseable"),
    ('{"decision": approve}', "unparseable"),
    ('', "unparseable"),
    (None, "unparseable"),
    ('{"verdict": "approve"}', "unparseable"),
    ('{"decision": ["approve"]}', "unparseable"),
])
def test_parse_decision(text, want):
    assert LA.parse_decision(text)[0] == want


def test_parse_decision_reason():
    assert LA.parse_decision('{"decision":"deny","reason":"payee differs"}') == ("deny", "payee differs")


# ---------------------------------------------------------------- statistics
def test_mcnemar_and_wilson():
    assert LA.mcnemar_exact(0, 0) == 1.0
    assert LA.mcnemar_exact(3, 3) == 1.0
    assert abs(LA.mcnemar_exact(0, 5) - 0.0625) < 1e-12
    assert abs(LA.mcnemar_exact(1, 9) - 0.021484375) < 1e-12
    assert LA.mcnemar_exact(9, 1) == LA.mcnemar_exact(1, 9)
    assert LA.wilson(0, 0) is None
    lo, hi = LA.wilson(5, 10)
    assert abs(lo - 0.2366) < 1e-3 and abs(hi - 0.7634) < 1e-3


def test_paired_counts():
    trials = []
    for i, (na, ca) in enumerate([("approve", "deny"), ("approve", "deny"), ("deny", "deny"),
                                  ("approve", "unparseable")]):
        for cond, out in (("narrated", na), ("card", ca)):
            trials.append({"stimulus": "s%d" % i, "kind": "attack", "condition": cond, "outcome": out})
    p = LA._paired(trials, "narrated", "card", "attack")
    assert p["pairs"] == 3 and p["only_card_correct"] == 2 and p["only_narrated_correct"] == 0
    assert p["both_correct"] == 1


# ---------------------------------------------------------------- dry run end to end
def test_dry_run_end_to_end_and_cache(tmp_path):
    logs = []
    res = LA.run(small_cfg(tmp_path), dry_run=True, out_dir=str(tmp_path), log=logs.append)
    assert res["dry_run"] and "NOT a result" in res["status"]
    assert os.path.basename(res["_paths"]["json"]).startswith("live_llm_approver_DRYRUN_")
    with open(res["_paths"]["json"], encoding="utf-8") as f:
        on_disk = json.load(f)
    assert on_disk["system_prompt"] == LA.SYSTEM_PROMPT and on_disk["stimuli_stale"] is False
    n_items = len(LA.make_stimuli()["stimuli"]) * len(LA.CONDITIONS)
    assert len(res["trials"]) == 2 * n_items * (1 + 3)
    outs = {t["outcome"] for t in res["trials"]}
    assert "unparseable" in outs and {"approve", "deny"} <= outs
    m = res["metrics"]["per_model"]["vendor-a/model-x"]
    cb = m["t0"]["by_condition"]
    for c in LA.CONDITIONS:
        a = cb[c]["attack"]
        assert a["approve"] + a["deny"] + a["unparseable"] + a["error"] + a["not_run"] == a["n"]
    assert "narrated_vs_card" in m["t0"]["paired"] and "paired" not in m["t07"]
    assert "stability_vs_t0" in m["t07"]
    assert "paired" not in res["metrics"]["pooled"]["t0"]
    md = open(res["_paths"]["md"], encoding="utf-8").read()
    assert "DRY RUN" in md and "McNemar" in md
    # second run: everything from cache, zero spend
    res2 = LA.run(small_cfg(tmp_path), dry_run=True, out_dir=str(tmp_path), log=logs.append)
    assert all(t["cached"] for t in res2["trials"]) and res2["spent_usd"] == 0
    assert [t["outcome"] for t in res2["trials"]] == [t["outcome"] for t in res["trials"]]


def test_budget_cap_stops_before_exceeding(tmp_path):
    res = LA.run(small_cfg(tmp_path, budget_usd=0.01), dry_run=True, out_dir=str(tmp_path), log=lambda s: None)
    assert res["budget_hit"] and res["spent_usd"] <= 0.01
    assert any(t["outcome"] == "not_run" for t in res["trials"])
    assert sum(1 for t in res["trials"] if t["outcome"] != "not_run") > 0


# ---------------------------------------------------------------- live path with a stub transport
class StubOpenRouter:
    def __init__(self, key, fail_first=False):
        self.key = key
        self.calls = []
        self.fail_first = fail_first

    def __call__(self, method, url, headers, body, timeout):
        self.calls.append((method, url, dict(headers)))
        if url.endswith("/models"):
            assert "Authorization" not in headers
            return 200, json.dumps({"data": [{"id": "vendor-a/model-x",
                                              "pricing": {"prompt": "0.000001", "completion": "0.000002"}}]}).encode()
        assert headers["Authorization"] == "Bearer " + self.key
        req = json.loads(body)
        assert req["usage"] == {"include": True}
        if req["model"] == "vendor-b/model-y":
            # error body that echoes the key: must be redacted
            return 400, json.dumps({"error": {"message": "bad key " + self.key}}).encode()
        if self.fail_first and len(self.calls) == 2:
            return 503, b""
        user = req["messages"][-1]["content"]
        dec = "deny" if "Effect:" in user else "approve"
        return 200, json.dumps({
            "id": "gen-1", "model": "vendor-a/model-x-2026-01-01", "provider": "VendorA",
            "choices": [{"message": {"content": json.dumps({"decision": dec, "reason": "r"})},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 500, "completion_tokens": 20, "cost": 0.0005,
                      "prompt_tokens_details": {"cached_tokens": 0}}}).encode()


def test_live_path_with_stub_never_leaks_key(tmp_path, monkeypatch, capsys):
    key = "sk-or-v1-TESTSECRET-0123456789abcdef"
    monkeypatch.setenv("OPENROUTER_API_KEY", key)
    stub = StubOpenRouter(key, fail_first=True)
    cfg = small_cfg(tmp_path, passes=[{"name": "t0", "temperature": 0.0, "samples": 1}])
    res = LA.run(cfg, dry_run=False, out_dir=str(tmp_path), transport=stub, sleep=lambda s: None)
    out = capsys.readouterr()
    assert key not in out.out and key not in out.err
    for fn in os.listdir(tmp_path):
        with open(tmp_path / fn, encoding="utf-8") as f:
            assert key not in f.read(), fn
    assert res["prices"]["vendor-a/model-x"]["source"] == "openrouter_models_endpoint"
    assert res["prices"]["vendor-b/model-y"]["source"] == "manual_config"
    assert res["model_versions_seen"]["vendor-a/model-x"] == ["vendor-a/model-x-2026-01-01"]
    a = [t for t in res["trials"] if t["model"] == "vendor-a/model-x"]
    b = [t for t in res["trials"] if t["model"] == "vendor-b/model-y"]
    assert all(t["outcome"] in ("approve", "deny") for t in a)  # the 503 was retried
    assert all(t["outcome"] == "error" and "[REDACTED]" in t["error"] for t in b)
    assert abs(res["spent_usd"] - 0.0005 * len(a)) < 1e-9
    cb = res["metrics"]["per_model"]["vendor-a/model-x"]["t0"]["by_condition"]
    assert cb["card"]["attack"]["catch_rate"] == 1.0 and cb["narrated"]["attack"]["catch_rate"] == 0.0
    assert cb["card"]["benign"]["false_deny_rate"] == 1.0
    p = res["metrics"]["per_model"]["vendor-a/model-x"]["t0"]["paired"]["narrated_vs_card"]["attack"]
    assert p["only_card_correct"] == len([s for s in LA.make_stimuli()["stimuli"] if s["kind"] == "attack"])
    # errors are not cached: a re-run retries model y, but only its single preflight call (it is
    # dropped again), and model x is all cache hits
    n_before = len(stub.calls)
    res2 = LA.run(cfg, dry_run=False, out_dir=str(tmp_path), transport=stub, sleep=lambda s: None)
    assert all(t["cached"] for t in res2["trials"] if t["model"] == "vendor-a/model-x")
    chat_calls = [c for c in stub.calls[n_before:] if c[1].endswith("/chat/completions")]
    assert len(chat_calls) == 1  # preflight for model y only; dropped again without paying for 100+ calls
    assert "vendor-b/model-y" in res2["models_dropped"]


def test_missing_key_refuses_live_run(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    with pytest.raises(SystemExit):
        LA.run(small_cfg(tmp_path), dry_run=False, out_dir=str(tmp_path),
               env_file=str(tmp_path / "nonexistent.env"), transport=StubOpenRouter("x"))


def test_unpriced_model_is_skipped(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "k-123456")

    def no_models(method, url, headers, body, timeout):
        if url.endswith("/models"):
            return 500, b""
        raise AssertionError("no chat call expected")

    cfg = small_cfg(tmp_path, models=[{"id": "vendor-z/unpriced"}])
    res = LA.run(cfg, dry_run=False, out_dir=str(tmp_path), transport=no_models, log=lambda s: None)
    assert res["models"] == [] and res["trials"] == []


def test_cache_key_covers_sampling_params():
    msgs = [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]
    h = {LA.prompt_hash(msgs, t, 400, i, None) for t in (0.0, 0.7) for i in range(3)}
    assert len(h) == 6
    assert LA.prompt_hash(msgs, 0.0, 400, 0, None, "s1|card") != LA.prompt_hash(msgs, 0.0, 400, 0, None, "s2|card")
    assert LA.cache_key("a", "x") != LA.cache_key("b", "x")


# ---------------------------------------------------------------- config / schemas / CLI
def test_example_config_valid():
    cfg = LA.load_config(LA.DEFAULT_CONFIG)
    assert cfg["models"] == "auto" and len(set(cfg["auto_models"]["vendors"])) >= 5
    assert cfg["passes"][0]["temperature"] == 0.0 and cfg["passes"][0]["samples"] == 1
    assert cfg["passes"][1]["temperature"] == 0.7 and cfg["passes"][1]["samples"] >= 3
    assert cfg["budget_usd"] > 0
    with open(LA.DEFAULT_CONFIG, encoding="utf-8") as f:
        assert "python3 -m experiments.live.llm_approver run --config experiments/live/llm_approver.example.yaml" in f.read()


@pytest.mark.parametrize("bad", [
    {"models": []},
    {"models": [{"id": "a"}, {"id": "a"}]},
    {"models": ["a"], "budget_usd": 0},
    {"models": ["a"], "conditions": ["card", "bogus"]},
    {"models": ["a"], "passes": [{"name": "x", "temperature": 0.0, "samples": 0}]},
])
def test_config_validation(bad):
    with pytest.raises(ValueError):
        LA.validate_config(bad)


def test_schemas_mirror_policy_library():
    path = os.path.join(REPO, "asu", "policies", "schemas.yaml")
    if not os.path.exists(path):
        pytest.skip("no schema library")
    with open(path, encoding="utf-8") as f:
        lib = yaml.safe_load(f) or {}
    lib = lib.get("tools", lib) if isinstance(lib, dict) else {}
    for tool, schema in LA.SCHEMAS.items():
        if tool not in lib:
            continue
        theirs = {k: (v if isinstance(v, str) else v.get("type")) for k, v in (lib[tool] or {}).items()}
        for k, t in schema.items():
            assert theirs.get(k) == t, (tool, k)


def test_cli_make_stimuli(tmp_path):
    out = tmp_path / "s.json"
    assert LA.main(["make-stimuli", "--out", str(out)]) == 0
    with open(out, encoding="utf-8") as f:
        assert f.read() == LA.dump_json(LA.make_stimuli())


# ---------------------------------------------------------------- auto model selection / estimate
def _cat_entry(mid, created, pin, pout=None, modality="text->text"):
    return {"id": mid, "created": created, "architecture": {"modality": modality},
            "pricing": {"prompt": str(pin / 1e6), "completion": str((pout or pin * 4) / 1e6)}}


def test_select_latest_models_picks_newest_frontier_and_small():
    cat = [
        _cat_entry("acme/big-1", 100, 3.0), _cat_entry("acme/big-2", 300, 5.0),
        _cat_entry("acme/mini-1", 200, 0.2), _cat_entry("acme/mini-2", 250, 0.3),
        _cat_entry("acme/embed-9", 999, 0.01, modality="text->embedding"),
        _cat_entry("acme/big-3:free", 400, 0.0),
        _cat_entry("other/x", 500, 1.0),
    ]
    sel = LA.select_latest_models(cat, {"vendors": ["acme"], "small_max_in_per_mtok": 0.6})
    assert [(s["id"], s["tier"]) for s in sel] == [("acme/big-2", "frontier"), ("acme/mini-2", "small")]
    sel2 = LA.select_latest_models(cat, {"vendors": ["acme"], "include_small": False, "include": ["other/x"]})
    assert [s["id"] for s in sel2] == ["acme/big-2", "other/x"]
    sel3 = LA.select_latest_models(cat, {"vendors": ["acme"], "exclude": ["big-2"]})
    assert sel3[0]["id"] == "acme/big-1"


def test_concurrent_live_run_matches_job_count_and_is_deterministic(tmp_path, monkeypatch):
    key = "sk-or-v1-TESTSECRET-0123456789abcdef"
    monkeypatch.setenv("OPENROUTER_API_KEY", key)
    stub = StubOpenRouter(key)
    cfg = small_cfg(tmp_path, passes=[{"name": "t0", "temperature": 0.0, "samples": 1}])
    cfg["models"] = [m for m in cfg["models"] if m["id"] == "vendor-a/model-x"]
    cfg["concurrency"] = 8
    res = LA.run(cfg, dry_run=False, out_dir=str(tmp_path), transport=stub, sleep=lambda s: None, log=lambda s: None)
    chat = [c for c in stub.calls if c[1].endswith("/chat/completions")]
    assert len(chat) == len(res["trials"]) and all(t["outcome"] in ("approve", "deny") for t in res["trials"])
    order1 = [(t["condition"], t["stimulus"]) for t in res["trials"]]
    res2 = LA.run(cfg, dry_run=False, out_dir=str(tmp_path), transport=stub, sleep=lambda s: None, log=lambda s: None)
    assert [(t["condition"], t["stimulus"]) for t in res2["trials"]] == order1
    assert len([c for c in stub.calls if c[1].endswith("/chat/completions")]) == len(chat)  # all cache hits


def test_estimate_only_makes_no_chat_calls(tmp_path, monkeypatch):
    key = "sk-or-v1-TESTSECRET-0123456789abcdef"
    monkeypatch.setenv("OPENROUTER_API_KEY", key)
    stub = StubOpenRouter(key)
    cfg = small_cfg(tmp_path)
    cfg["_estimate_only"] = True
    res = LA.run(cfg, dry_run=False, out_dir=str(tmp_path), transport=stub, sleep=lambda s: None, log=lambda s: None)
    assert not [c for c in stub.calls if c[1].endswith("/chat/completions")]
    assert res is not None
