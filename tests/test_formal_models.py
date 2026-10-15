"""Tests for the FORMAL area (formal/).

Tamarin (revision 2, D-005) -- the models whose verdicts are in results.json:
* run_all.py flags an ill-formed theory as an error (critique F10).
* Mutation tests: weakening the ASU Tamarin model in specific ways must make
  the corresponding lemma FALSIFIED (the proofs are not vacuous).
* Static lint, hypothesis wiring (H1-H3) and model<->code correspondence.
* Shape/honesty checks on the committed formal/results.json.

Maude (LEGACY revision-1 encoding, bounded; not in results.json):
* property encodings on hand-written traces, mutation tests and the quick
  end-to-end run against the legacy expected table.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FORMAL = ROOT / "formal"
MAUDE_DIR = FORMAL / "maude"
TAMARIN_DIR = FORMAL / "tamarin"

sys.path.insert(0, str(FORMAL))
import run_all  # noqa: E402

MAUDE = run_all.find_maude()
needs_maude = pytest.mark.skipif(MAUDE is None, reason="maude not installed")


def maude(script: str, timeout: float = 120) -> str:
    proc = subprocess.run([MAUDE, "-no-banner", "-no-advise"], input=script + "\nquit\n",
                          capture_output=True, text=True, timeout=timeout)
    out = proc.stdout + proc.stderr
    assert "Warning" not in out and "Error" not in out, out
    return out


def red_bool(expr: str) -> bool:
    out = maude(f"load {MAUDE_DIR / 'common.maude'}\nred in ASU-CONFIG : {expr} .")
    m = re.search(r"result Bool: (true|false)", out)
    assert m, out
    return m.group(1) == "true"


E1 = "eff(c1, x1)"
E2 = "eff(c2, x1)"
A0 = "aid(0)"


def L(*events: str) -> str:
    return "log(" + (" ;; ".join(events) if events else "nil") + ")"


@needs_maude
class TestPropertyEncodings:
    def test_L1_honest_trace_ok(self):
        assert not red_bool(f"badL1({L(f'approve(u, {A0}, {E1})', f'exec(u, {A0}, {E1})')})")

    def test_L1_exec_without_approval(self):
        assert red_bool(f"badL1({L(f'exec(u, {A0}, {E1})')})")

    def test_L1_approval_after_exec_is_violation(self):
        assert red_bool(f"badL1({L(f'exec(u, {A0}, {E1})', f'approve(u, {A0}, {E1})')})")

    def test_L1_substituted_effect(self):
        assert red_bool(f"badL1({L(f'approve(u, {A0}, {E1})', f'exec(u, {A0}, {E2})')})")

    def test_L1_compromise_escape(self):
        assert not red_bool(f"badL1({L(f'exec(u, {A0}, {E2})', 'compromise(u)')})")

    def test_L1sig(self):
        assert not red_bool(f"badL1sig({L(f'signed(u, {A0}, h({E1}))', f'exec(u, {A0}, {E1})')})")
        assert red_bool(f"badL1sig({L(f'signed(u, {A0}, h({E1}))', f'exec(u, {A0}, {E2})')})")

    def test_L2(self):
        assert not red_bool(f"badL2({L(f'exec(u, {A0}, {E1})', f'exec(u, aid(1), {E1})')})")
        assert red_bool(f"badL2({L(f'exec(u, {A0}, {E1})', 'approve(u, aid(1), eff(c1, x2))', f'exec(u, {A0}, {E1})')})")

    def test_L3(self):
        assert not red_bool(f"badL3({L(f'approve(u, {A0}, {E1})', f'approved(u, {A0}, {E1})')})")
        assert red_bool(f"badL3({L(f'approve(u, {A0}, {E1})', f'approved(u, aid(1), {E1})')})")

    def test_L4sig(self):
        sig = f"sig(tup(tagA, h({E1}), {A0}, nc(0)), sk(u))"
        assert not red_bool(f"badL4sig(ik({sig}) {L(f'signed(u, {A0}, h({E1}))')})")
        assert red_bool(f"badL4sig(ik({sig} ; pk(u)) {L()})")
        assert not red_bool(f"badL4sig(ik({sig}) {L('compromise(u)')})")

    def test_L4mac_key_leak(self):
        effs = f"effs({E1} ; {E2})"
        signed = f"signed(u, {A0}, h({E1}))"
        # only the genuine MAC known: fine
        mac = f"mac(tup(tagA, h({E1}), {A0}, nc(0)), key(u))"
        assert not red_bool(f"badL4mac(ik({mac} ; {A0}) {effs} {L(signed)})")
        # key leaked: judge accepts a digest never MACed by the device
        assert red_bool(f"badL4mac(ik({mac} ; {A0} ; key(u)) {effs} {L(signed, 'gwcorrupt(u)')})")

    def test_L5(self):
        ok = L("approvegrant(u, aid(0), c1)", "execg(u, aid(0), c1, eff(c1, x2))")
        assert not red_bool(f"badL5({ok})")
        assert red_bool(f"badL5({L('approvegrant(u, aid(0), c1)', 'execg(u, aid(0), c1, eff(c2, x1))')})")
        assert red_bool(f"badL5({L('execg(u, aid(0), c1, eff(c1, x1))')})")

    def test_L5b(self):
        two = ["execg(u, aid(0), c1, eff(c1, x1))"] * 2
        assert not red_bool(f"badL5b({L(*two)})")
        assert red_bool(f"badL5b({L(*(two + ['execg(u, aid(0), c1, eff(c1, x2))']))})")


def _search(model_file: Path, module_text: str | None, pred: str, init: str = "init(2, 3, c1 ; c2)") -> str:
    out = maude(f"load {model_file}\nsearch [1] {init} =>* C:Config such that {pred}(C:Config) .", timeout=300)
    if "No solution." in out:
        return "verified_bounded"
    assert "Solution 1" in out, out
    return "falsified"


def _mutant(tmp_path: Path, old: str, new: str) -> Path:
    src = (MAUDE_DIR / "asu.maude").read_text()
    assert old in src, old
    text = src.replace(old, new).replace("load common.maude", f"load {MAUDE_DIR / 'common.maude'}")
    p = tmp_path / "mutant.maude"
    p.write_text(text)
    return p


@needs_maude
class TestMutationsAreCaught:
    """Each weakening of the ASU model must be detected by the bounded search."""

    def test_baseline_asu_holds(self):
        for pred in ("badL1", "badL2", "badL3", "badL4sig", "badL5", "badL5b"):
            assert _search(MAUDE_DIR / "asu.maude", None, pred) == "verified_bounded", pred

    def test_execute_agent_copy_breaks_L1(self, tmp_path):
        p = _mutant(tmp_path, "budget(Q) log(L ;; exec(U, A, E))\n   if memb(A, K) and h(E2) == h(E) .",
                    "budget(Q) log(L ;; exec(U, A, E2))\n   if memb(A, K) .")
        assert _search(p, None, "badL1") == "falsified"

    def test_no_consume_breaks_L2(self, tmp_path):
        p = _mutant(tmp_path, "   => ik(K) effs(E2 ; ES) budget(Q) log(L ;; exec(U, A, E))",
                    "   => apst(U, A, N, E) ik(K) effs(E2 ; ES) budget(Q) log(L ;; exec(U, A, E))")
        assert _search(p, None, "badL2") == "falsified"

    def test_unbound_signature_breaks_L3(self, tmp_path):
        # gateway accepts a signature for ANY of U's approvals (id not bound)
        p = _mutant(tmp_path, "   if S == sig(tup(tagA, h(E), A, N), sk(U)) .",
                    "   if sig(tup(tagA, HD, A2, N2), sk(U)) := S .")
        p.write_text(p.read_text().replace("vars U A G N E E2 C S HD : Msg .",
                                           "vars U A G N E E2 C S HD A2 N2 : Msg ."))
        assert _search(p, None, "badL3") == "falsified"

    def test_no_scope_check_breaks_L5(self, tmp_path):
        p = _mutant(tmp_path, "   if memb(G, K) and scope(E) == C .", "   if memb(G, K) .")
        assert _search(p, None, "badL5") == "falsified"

    def test_extra_grant_use_breaks_L5b(self, tmp_path):
        p = _mutant(tmp_path, "   => gst(U, G, C, 2) ik(S ; K)", "   => gst(U, G, C, 3) ik(S ; K)")
        assert _search(p, None, "badL5b") == "falsified"


@needs_maude
def test_legacy_maude_quick_run_matches_expected(tmp_path):
    out = tmp_path / "results.json"
    rc = run_all.main(["--only", "maude", "--quick", "--timeout", "300", "--out", str(out),
                       "--trace-dir", str(tmp_path / "traces")])
    doc = json.loads(out.read_text())
    assert rc == 0 and doc["mismatches_vs_expected"] == 0
    got = {(r["model"], r["lemma"]): r["result"] for r in doc["results"]}
    # The five required weakened variants each produce an attack trace.
    assert got[("v1_unbound", "L1_effect_binding")] == "falsified"
    assert got[("v2_narration", "L1_effect_binding")] == "falsified"
    assert got[("v3_replay", "L2_single_use")] == "falsified"
    assert got[("v4_totp_relay", "L3_agent_independence")] == "falsified"
    assert got[("v4b_chat_confirm", "L3_agent_independence")] == "falsified"
    assert got[("v5_mac", "L4_non_repudiation")] == "falsified"
    # Full protocol: no counterexample, and not vacuous.
    for lem in ("L1_effect_binding", "L2_single_use", "L3_agent_independence",
                "L4_non_repudiation", "L5_grant_scope", "L5b_grant_max_uses"):
        assert got[("asu", lem)] == "verified_bounded"
    for lem in ("exec_possible", "grant_exec_possible", "judge_possible"):
        assert got[("asu", lem)] == "verified"
    for r in doc["results"]:
        if r["result"] == "falsified" and r["kind"] == "safety":
            assert r["trace"] and Path(r["trace"]).exists()


# ---------------------------------------------------------------- Tamarin lint

SPTHY = sorted(TAMARIN_DIR.glob("*.spthy"))


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def test_all_tamarin_models_present():
    names = {p.stem for p in SPTHY}
    assert set(run_all.EXPECTED) <= names


@pytest.mark.parametrize("path", SPTHY, ids=lambda p: p.stem)
def test_spthy_static_lint(path):
    raw = path.read_text()
    text = _strip_comments(raw)
    assert re.search(r"^theory \w+\s*\nbegin", text, re.M)
    assert text.rstrip().endswith("end")
    for o, c in ("()", "[]", "<>"):
        if o == "<":
            continue  # '<' also used in temporal ordering (#j < #i)
        assert text.count(o) == text.count(c), (path.name, o)
    assert text.count('"') % 2 == 0
    lemmas = re.findall(r"^lemma\s+(\w+)", text, re.M)
    assert len(lemmas) == len(set(lemmas))
    assert "exec_possible" in lemmas, "every model needs a non-vacuity lemma"
    # every linear fact consumed in a premise must be produced by some rule
    rules = re.findall(r"rule\s+\w+:\s*(?:let\b.*?\bin\s*)?\[(.*?)\]\s*--\[(.*?)\]->\s*\[(.*?)\]", text, re.S)
    assert len(rules) == len(re.findall(r"^rule\s", text, re.M)), "rule regex missed a rule"
    assert rules, path.name
    produced, consumed = set(), set()
    for prem, _act, concl in rules:
        consumed |= set(re.findall(r"(?<![!\w])([A-Z]\w*)\(", prem)) - {"In", "Fr"}
        produced |= set(re.findall(r"(?<![!\w])([A-Z]\w*)\(", concl)) - {"Out"}
        consumed |= {"!" + f for f in re.findall(r"!(\w+)\(", prem)}
        produced |= {"!" + f for f in re.findall(r"!(\w+)\(", concl)}
    missing = consumed - produced
    assert not missing, (path.name, missing)
    # every action used in a lemma is emitted by some rule (no vacuous lemma)
    actions = set()
    for _p, act, _c in rules:
        actions |= set(re.findall(r"(\w+)\(", act))
    lemma_text = "\n".join(re.findall(r'^lemma[^"]*"(.*?)"', text, re.M | re.S))
    used = set(re.findall(r"([A-Z]\w*)\([^)]*\)\s*@", lemma_text))
    assert used <= actions, (path.name, used - actions)


# ---------------------------------------------------------------- results.json

ALLOWED = {"verified", "falsified", "timeout", "verified_bounded", "not_run", "error"}


def _results():
    path = FORMAL / "results.json"
    assert path.exists(), "run formal/run_all.sh"
    return json.loads(path.read_text())


def test_committed_results_shape_and_honesty():
    doc = _results()
    assert doc["mismatches_vs_expected"] == 0
    assert doc["errors"] == 0
    assert doc["model_revision"].startswith("2")
    tamarin_available = bool(doc["tools"].get("tamarin"))
    assert tamarin_available, "results.json must carry Tamarin verdicts (D-003)"
    for r in doc["results"]:
        assert {"model", "lemma", "result", "seconds", "engine"} <= set(r)
        assert r["engine"] == "tamarin"
        assert r["result"] in ALLOWED
        assert r["result"] != "error", r
        assert r["matches_expected"] is True, r
        if r["result"] == "falsified":
            assert r.get("trace") and (FORMAL / r["trace"]).exists()


def test_results_cover_every_lemma_of_every_model():
    doc = _results()
    got = {(r["model"], r["lemma"]) for r in doc["results"]}
    for model, table in run_all.EXPECTED.items():
        lemmas = set(run_all.spthy_lemmas(TAMARIN_DIR / f"{model}.spthy"))
        assert lemmas == set(table), (model, lemmas ^ set(table))
        assert {(model, l) for l in lemmas} <= got


def test_results_record_hypotheses_for_asu():
    doc = _results()
    for r in doc["results"]:
        if r["model"] == "asu" and r["lemma"] in run_all.HYPOTHESES:
            assert r["hypotheses"] == run_all.HYPOTHESES[r["lemma"]]


# ------------------------------------------------- hypothesis wiring (H1-H3)

ASU_TEXT = (TAMARIN_DIR / "asu.spthy").read_text()
H_MARK = {"H1": "not (Ex #d. DecidesOnExplanation(U, {aid}) @ #d)",
          "H2": "not (Ex #o. EnrollmentOpen() @ #o)",
          "H3": "not (Ex #c. CeremonyControl(U) @ #c)"}


def _lemma_body(name: str) -> str:
    m = re.search(rf'^lemma {name}:\s*(?:exists-trace)?\s*"(.*?)"', ASU_TEXT, re.M | re.S)
    assert m, name
    return re.sub(r"\s+", " ", m.group(1))


@pytest.mark.parametrize("lemma", sorted(run_all.HYPOTHESES))
def test_lemma_states_exactly_its_hypotheses(lemma):
    body = _lemma_body(lemma)
    if lemma.startswith(("L2", "L5b")):
        assert "Ex #d" not in body and "EnrollmentOpen" not in body
        return
    aid = "gid" if "L5" in lemma else "aid"
    for h, marker in H_MARK.items():
        present = marker.format(aid=aid) in body
        assert present == (h in run_all.HYPOTHESES[lemma]), (lemma, h)


def test_attack_variants_drop_exactly_one_hypothesis_of_their_main_lemma():
    pairs = {"X1_L1_effect_binding_noH1": ("L1_effect_binding", "H1"),
             "X1_L3_agent_independence_noH1": ("L3_agent_independence", "H1"),
             "X2_L4c_consent_nonrepudiation_noH3": ("L4c_consent_nonrepudiation", "H3"),
             "X2_L1_effect_binding_noH3": ("L1_effect_binding", "H3"),
             "X3_L1_effect_binding_open_enrollment": ("L1_effect_binding", "H2"),
             "X3_L1_sig_binding_open_enrollment": ("L1_sig_binding", "H2"),
             "X3_L4_non_repudiation_open_enrollment": ("L4_non_repudiation", "H2"),
             "X3_L5_grant_scope_open_enrollment": ("L5_grant_scope", "H2")}
    for x, (main, h) in pairs.items():
        assert set(run_all.HYPOTHESES[main]) - set(run_all.HYPOTHESES[x]) == {h}, x
        # identical conclusion: strip the hypotheses and compare
        def concl(n):
            return _lemma_body(n).split("==>", 1)[1]
        assert concl(x) == concl(main), x


def test_no_vacuous_gateway_corruption_rule():
    # critique F2 / mutant M5: the old Corrupt_Gateway only re-output pk(U).
    assert "Corrupt_Gateway" not in _strip_comments(ASU_TEXT)
    assert "rule Origin_Controls_Ceremony" in ASU_TEXT


def test_no_tautological_grant_conjunct():
    # critique F6: L5 must not compare the executed effect with the rule's own pattern.
    assert "c2 = c" not in _lemma_body("L5_grant_scope")
    assert "HumanApproves(U, gid," in _lemma_body("L5_grant_scope")


def test_compromise_escapes_are_time_ordered():
    # critique F12
    for path in SPTHY:
        text = _strip_comments(path.read_text())
        for m in re.finditer(r"(?<!not \()Ex #k\. Compromise\(U\) @ #k([^|\n]*)", text):
            assert "#k < #i" in m.group(1), (path.name, m.group(0))


# ------------------------------------------------- model <-> code correspondence

def test_challenge_encoding_matches_code():
    """The model's challenge tuple <'ASU-APPROVAL-v2', h, aid, gd> stands for
    SHA-256(JCS({tag, digest, approval_id, nonce, grant_digest})) (D-005 item 1)."""
    from asu.authn import receipt

    assert receipt.CHALLENGE_TAG == "ASU-APPROVAL-v2"
    assert "'ASU-APPROVAL-v2'" in ASU_TEXT
    msg = receipt.challenge_message("ab" * 32, "apr_X", "n0", None)
    obj = json.loads(msg)
    assert set(obj) == {"tag", "digest", "approval_id", "nonce", "grant_digest"}
    assert obj["grant_digest"] is None
    # injectivity of the encoding on the split that broke v1 (critique F4)
    assert (receipt.compute_challenge("ab" * 32, "apr_AAAABBBB", "NONCE123")
            != receipt.compute_challenge("ab" * 32, "apr_AAAA", "BBBBNONCE123"))


CORRESPONDENCE_SYMBOLS = {
    "asu/authn/receipt.py": ["def challenge_message", "def compute_challenge", "def approval_challenge",
                             "def grant_digest", "def verify_receipt"],
    "asu/jcs.py": ["def canonicalize"],
    "asu/descriptor.py": ["def digest", "def render_card", "def render_narrated_card"],
    "asu/grants.py": ["def build_grant_request", "def grant_matches", "def try_use_grant"],
    "asu/store.py": ["def mark_approved", "def consume"],
    "asu/gateway.py": ["def _execute_approved", "def _execute_unbound", "def chat_confirm",
                       "def _check_totp"],
    "asu/authn/routes.py": ["def register_options", "def approval_options", "def approval_verify"],
}


def test_correspondence_table_symbols_exist():
    readme = (FORMAL / "README.md").read_text()
    for rel, syms in CORRESPONDENCE_SYMBOLS.items():
        src = (ROOT / rel).read_text()
        for sym in syms:
            assert sym in src, (rel, sym)
            assert sym.split()[-1] in readme, ("README correspondence table lacks", sym)


# ------------------------------------------------- Tamarin execution tests

TAMARIN = run_all.find_tamarin()
needs_tamarin = pytest.mark.skipif(TAMARIN is None, reason="tamarin-prover not installed")


@needs_tamarin
def test_run_all_flags_wellformedness_failure(tmp_path, monkeypatch):
    bad = tmp_path / "bad.spthy"
    bad.write_text("""theory Bad
begin
rule R: [ In(x) ] --[ A(x) ]-> [ St(x, s) ]
rule S: [ St(x, s) ] --[ B(x) ]-> [ ]
lemma ok: exists-trace "Ex x #i. B(x) @ #i"
end
""")
    monkeypatch.setattr(run_all, "TAMARIN_DIR", tmp_path)
    monkeypatch.setattr(run_all, "TRACE_DIR", tmp_path / "traces")
    rec = run_all.run_tamarin_job(TAMARIN, "bad", "ok", 120)
    assert rec["result"] == "error", rec
    assert "ill-formed" in rec["detail"]


def _tamarin_verdict(path: Path, lemma: str) -> str:
    for _attempt in range(2):  # one retry if the prover dies without a verdict (e.g. OOM under load)
        proc = subprocess.run([TAMARIN, f"--prove={lemma}", str(path)], capture_output=True, text=True,
                              timeout=600, env={**__import__("os").environ, "LC_ALL": "C.UTF-8"})
        out = proc.stdout + proc.stderr
        if "summary of summaries" in out:
            break
    assert not run_all.WF_FAIL.search(out), out[-3000:]
    m = re.search(rf"^\s*{lemma}\s+\(all-traces\):\s+(verified|falsified)", out, re.M)
    assert m, out[-3000:]
    return m.group(1)


def _asu_mutant(tmp_path: Path, old: str, new: str) -> Path:
    assert old in ASU_TEXT, old
    p = tmp_path / "asu_mutant.spthy"
    p.write_text(ASU_TEXT.replace(old, new))
    return p


ASU_MUTANTS = [
    # grant matching ignores the target (bound field) -> grant stretching
    ("L5_grant_scope", "Eq(t2, t), Eq(r2, r), LeqNat(a2:nat, cap:nat),", "Eq(t2, t), LeqNat(a2:nat, cap:nat),"),
    # grant matching ignores the amount bound
    ("L5_grant_scope", "Eq(t2, t), Eq(r2, r), LeqNat(a2:nat, cap:nat),", "Eq(t2, t), Eq(r2, r), LeqNat(a2:nat, a2:nat),"),
    # grant digest not covered by the verified challenge
    ("L5_grant_scope", "verify(s, <'ASU-APPROVAL-v2', h(e), aid, h(g)>, pkU)",
     "verify(s, <'ASU-APPROVAL-v2', h(e), aid, 'null'>, pkU)"),
    # approval id not in the signed challenge -> cross-approval replay (critique M2)
    ("L1_sig_binding", "Eq(verify(s, <'ASU-APPROVAL-v2', h(e), aid, 'null'>, pkU), true),\n      Approved",
     "Eq(verify(s, <'ASU-APPROVAL-v2', h(e), aidX, 'null'>, pkU), true),\n      Approved"),
    # gateway executes the agent's resubmitted args
    ("L1_effect_binding", "--[ Eq(h(e2), h(e)), Execute(U, aid, e) ]->", "--[ Execute(U, aid, e2) ]->"),
    # approval not consumed
    ("L2_single_use", "[ ApprovedSt(U, aid, e, gd, s), In(<'exec', aid, e2>) ]",
     "[ ApprovedSt(U, aid, e, gd, s), In(<'exec', aid, e2>) ]\n  --[ ]->\n    [ !Again(U, aid, e, gd, s) ]\n\n"
     "rule Gateway_Execute_Again:\n    [ !Again(U, aid, e, gd, s), In(<'exec', aid, e2>) ]"),
]


@needs_tamarin
@pytest.mark.parametrize("lemma,old,new", ASU_MUTANTS, ids=[f"{m[0]}-{i}" for i, m in enumerate(ASU_MUTANTS)])
def test_tamarin_mutant_is_caught(tmp_path, lemma, old, new):
    p = _asu_mutant(tmp_path, old, new)
    if "aidX" in new:
        # aidX is then an unbound variable; bind it from the input instead
        p.write_text(p.read_text().replace("[ Pending(U, aid, e, g), In(s), !Pk(U, pkU) ]\n  --[ Eq(verify(s, <'ASU-APPROVAL-v2', h(e), aidX",
                                           "[ Pending(U, aid, e, g), In(<aidX, s>), !Pk(U, pkU) ]\n  --[ Eq(verify(s, <'ASU-APPROVAL-v2', h(e), aidX"))
    assert _tamarin_verdict(p, lemma) == "falsified"


@needs_tamarin
def test_tamarin_unmutated_L5_verifies():
    assert _tamarin_verdict(TAMARIN_DIR / "asu.spthy", "L5_grant_scope") == "verified"
