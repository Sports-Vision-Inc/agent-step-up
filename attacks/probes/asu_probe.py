"""ASU gateway as the reference DEFENSE.

This probe does not re-implement the attacks on ASU. Each AB cell maps to
pytest node ids that EXECUTE the attack, either against the live gateway
(tests/redteam/rt_live.py: uvicorn-served create_app, asu mode, a software passkey
human and a bearer-token-only agent) or against the exact gateway function that
enforces the property. A passing test means ASU blocks the attack. A failing test
means ASU is vulnerable at the stamped commit.

Rules:
  * Every ASU cell has at least one mapped test. A cell is reported as
    ``executed`` only if all of its mapped tests ran (passed or failed) in this
    run. An ERROR, a missing node id or a skip makes the cell ``n/a`` and
    not-executed. That result is indeterminate, never a verdict.
  * AB9 is special. Its second test runs the documented by-design limitation
    (formal X2 / H3): consent-level P5 needs an honest rendering origin. That
    test passes when the limitation behaves as documented, so the cell is
    ``partial`` (severity info), not ``not_vulnerable``.
"""
from __future__ import annotations

import os
import subprocess
import sys

from attacks.common import row, write_evidence, tree_state, VULN, NOT_VULN, PARTIAL, NA
from attacks.targets import REPO_ROOT

T = "asu"
_RT = "tests/redteam/"
_LIVE = "tests/test_attacks_asu_live.py::"

# AB cell -> node ids whose PASS means "ASU blocks it".
AB_TESTS = {
    "AB1": [_RT + "test_rt_redteam_grant_stretch.py::test_grant_amount_cancellation_does_not_exceed_signed_cap"],
    "AB2": [_RT + "test_rt_redteam_grant_stretch.py::test_grant_decoy_account_key_does_not_redirect_payee",
            _RT + "test_rt_redteam_grant_stretch.py::test_grant_decoy_account_key_does_not_redirect_email",
            _RT + "test_rt_redteam_decoy_target.py::test_decoy_account_does_not_bypass_first_time_recipient",
            _RT + "test_rt_redteam_decoy_target.py::test_card_title_names_the_real_recipient"],
    "AB3": [_RT + "test_rt_redteam_grant_stretch.py::test_grant_amount_cancellation_does_not_exceed_signed_cap",
            _RT + "test_rt_redteam_grant_stretch.py::test_grant_decoy_account_key_does_not_redirect_payee",
            _RT + "test_rt_redteam_grant_stretch.py::test_grant_decoy_account_key_does_not_redirect_email"],
    "AB4": [_RT + "test_rt_redteam_card_render.py::test_blank_padding_is_escaped_or_flagged",
            _RT + "test_rt_redteam_card_render.py::test_shell_interpreter_flagged_for_any_shell"],
    "AB5": [_RT + "test_rt_redteam_card_render.py::test_agent_arg_names_cannot_impersonate_trusted_labels"],
    "AB6": [_RT + "test_rt_formal_render_injective.py::test_distinct_effects_render_distinct_cards",
            _RT + "test_rt_formal_render_injective.py::test_bool_vs_string_render_distinct_cards"],
    "AB7": [_RT + "test_rt_redteam_enrollment.py::test_agent_cannot_enroll_passkey_for_provisioned_user",
            _RT + "test_rt_crypto_enroll_squat.py::test_agent_cannot_enroll_own_passkey_and_self_approve",
            _RT + "test_rt_formal_open_enrollment.py::test_default_config_refuses_unauthenticated_first_enrollment"],
    "AB8": [_RT + "test_rt_crypto_challenge_ambiguity.py::test_receipt_not_valid_for_resplit_id_and_nonce",
            _RT + "test_rt_formal_challenge_split.py::test_positive_control_receipt_verifies",
            _RT + "test_rt_formal_challenge_split.py::test_receipt_does_not_verify_for_resplit_approval_id_and_nonce"],
    "AB9": [_LIVE + "test_ab9_agent_cannot_reach_the_ceremony",
            _LIVE + "test_ab9_consent_needs_honest_rendering_origin_by_design"],
    "AB10": [_LIVE + "test_ab10_post_approval_substitution_is_409",
             _LIVE + "test_ab10_cross_session_use_of_an_approval_is_refused"],
    "AB11": [_LIVE + "test_ab11_flood_within_one_session_is_rate_limited",
             _LIVE + "test_ab11_flood_across_a_users_sessions_is_capped_per_user",
             _LIVE + "test_ab11_repeated_denials_lock_the_session_out"],
    "AB12": [_LIVE + "test_ab12_threshold_splitting_hits_the_aggregate_and_grant_caps"],
}

# What a PASS shows, per cell (kept short; the test docstrings carry the detail).
_SHOWS = {
    "AB1": "under a grant signed for max 10 USD, a call with amount=10000,total=-10000 does not execute",
    "AB2": "a decoy account/recipient key neither redirects a grant nor hides a first-time recipient; "
           "the card title names the real recipient",
    "AB3": "a grant cannot be stretched past its signed amount cap or to another payee/email recipient",
    "AB4": "blank-glyph padding is escaped/collapsed and flagged; `bash -c` and other interpreters are flagged",
    "AB5": "agent-chosen argument names are denied by the closed schema, and on untyped tools render only "
           "as `arg.<name>` in a separate Arguments section",
    "AB6": "distinct descriptors (incl. bool vs string) render distinct cards",
    "AB7": "with the default config the agent cannot enroll its own passkey, for a new or a provisioned user",
    "AB8": "the v2 tagged JCS challenge is injective: a receipt never verifies for a re-split (id, nonce)",
    "AB10": "different payee/amount/extra arg/tool under an approved id -> 409 effect_mismatch, nothing runs; "
            "a bare execute runs the stored descriptor once; replay -> 403; another session -> 404",
    "AB11": "default policy: 1 pending card per session (identical retry de-duplicated), 6 calls/min -> 429, "
            "3 pending per user across sessions -> 429 max_pending_per_user, 3 denials -> 429 deny_lockout",
    "AB12": "splitting into 10 USD pieces under a grant stops at the aggregate window (5 effects / 200 USD "
            "per 600 s); the step-up card offers no grant",
}

SEV = {"AB1": "critical", "AB2": "critical", "AB3": "critical", "AB12": "critical", "AB7": "high",
       "AB10": "critical", "AB9": "high", "AB4": "medium", "AB5": "medium", "AB6": "medium",
       "AB8": "medium", "AB11": "low"}


def _run_pytest(node_ids):
    """Return ({node_id: 'pass'|'fail'|'error'|'skip'}, raw_output)."""
    env = dict(os.environ, LC_ALL="C.UTF-8")
    cmd = [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "--tb=short", "-q", "-rA", *node_ids]
    out = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, env=env, timeout=900)
    text = out.stdout + "\n" + out.stderr
    status = {}
    for line in text.splitlines():
        line = line.strip()
        for tag, val in (("PASSED ", "pass"), ("FAILED ", "fail"),
                         ("ERROR ", "error"), ("SKIPPED ", "skip")):
            if line.startswith(tag):
                status[line[len(tag):].split(" ")[0]] = val
    return status, text


def _cell(ids, status):
    res = [status.get(n, "missing") for n in ids]
    if any(r in ("error", "missing", "skip") for r in res):
        return "indeterminate", res
    if all(r == "pass" for r in res):
        return "pass", res
    return "fail", res


def run():
    rows = []
    st = tree_state(REPO_ROOT)
    stamp = st["stamp"]
    short = stamp[:12] + ("-dirty" if st["dirty"] else "")
    all_ids = sorted({n for ids in AB_TESTS.values() for n in ids})
    status, raw = _run_pytest(all_ids)
    ev = write_evidence(
        "asu_redteam.log",
        f"ASU commit tested: {stamp}\n"
        f"tree dirty: {st['dirty']} (asu/ dirty: {st['asu_dirty']}; dirty paths: "
        f"{', '.join(st['dirty_paths'][:40]) or 'none'})\n"
        f"Every ASU cell maps to the node ids below; the cell is executed only if all of them ran.\n\n"
        + "\n".join(f"{ab}: " + " ".join(AB_TESTS[ab]) for ab in sorted(AB_TESTS, key=lambda a: int(a[2:])))
        + f"\n\npytest -rA output:\n{raw}")

    for ab in sorted(AB_TESTS, key=lambda a: int(a[2:])):
        ids = AB_TESTS[ab]
        oc, res = _cell(ids, status)
        repro = f"{os.path.basename(sys.executable)} -m pytest " + " ".join(ids)
        tag = f"[ASU@{short}]"
        if oc == "indeterminate":
            rows.append(row(T, ab, applicable=True, executed=False, outcome=NA, severity="none",
                            note=f"{tag} INDETERMINATE: mapped test(s) did not run cleanly "
                                 f"({dict(zip(ids, res))}). Not a vulnerability verdict.",
                            repro=repro, evidence=ev))
            continue
        if ab == "AB9":
            agent_ok = res[0] == "pass"
            limitation_reproduced = res[1] == "pass"
            if not agent_ok:
                outcome, sev = VULN, SEV[ab]
                note = (f"{tag} The agent reached the approval ceremony with its bearer token "
                        f"({ids[0]} failed).")
            else:
                outcome, sev = PARTIAL, "info"
                note = (f"{tag} Executed against the live gateway. (1) The agent's bearer token is 401 on "
                        "/v1/authn pending/view/options/verify and cannot enroll a passkey, so the agent "
                        "cannot control what is signed. (2) BY-DESIGN LIMITATION, consistent with formal X2 "
                        "/ assumption H3 and D-005 item 7: a page served from the rendering origin, holding "
                        "the human's web login, showed card A and obtained a signature over approval B's "
                        "challenge (authenticators do not display the challenge). The receipt for B "
                        "verified at KEY LEVEL and B executed. "
                        + ("This was reproduced. " if limitation_reproduced else
                           "This did NOT reproduce in this run; check the test. ")
                        + "So P5 is key-level. Consent-level non-repudiation holds only under an honest "
                        "rendering origin. 'partial' records that trust assumption. It is not an "
                        "agent-reachable attack.")
            rows.append(row(T, ab, applicable=True, executed=True, outcome=outcome, severity=sev,
                            note=note, repro=repro, evidence=ev))
            continue
        if oc == "pass":
            outcome, sev = NOT_VULN, "none"
            note = f"{tag} Executed; all mapped tests pass: {_SHOWS[ab]}."
        else:
            outcome, sev = VULN, SEV[ab]
            failed = [n for n, r in zip(ids, res) if r == "fail"]
            note = f"{tag} Executed; FAILED (ASU vulnerable at this commit): {', '.join(failed)}."
        if ab == "AB11" and oc == "pass":
            note += (" Residual: the per-user caps are set in the packaged default.yaml. A policy that "
                     "omits them (the experiment policies) keeps per-session behaviour only (RT-9).")
        rows.append(row(T, ab, applicable=True, executed=True, outcome=outcome, severity=sev,
                        note=note, repro=repro, evidence=ev))
    return rows
