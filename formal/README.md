# formal/ — Tamarin models of ASU (revision 2)

Revision 2 implements DECISIONS D-005 (items 1, 7 and 8) and the findings F1–F12 in
`docs/critique/formal.md`. ASU is the reference defense of the paper (D-004). The models
state **what it guarantees, and under which hypotheses**. They are not a claim of
novelty: formal models of agent approval already exist (Jiang et al. 2609.00060, AITH 2604.07695).

| What | Where |
|---|---|
| Full protocol, with the three strengthened adversaries and their hypothesis markers | `tamarin/asu.spthy` |
| Baselines (V1 unbound, V2 narrated card, V4a TOTP, V4b chat-confirm) | `tamarin/v1_unbound.spthy`, `v2_narration.spthy`, `v4_totp_relay.spthy`, `v4b_chat_confirm.spthy` |
| V3 mutant (no consumption); V5 straw man (shared-key MAC) | `tamarin/v3_replay.spthy`, `v5_mac.spthy` |
| Runner and expected table | `run_all.py` (`EXPECTED`, `HYPOTHESES`), `run_all.sh` |
| Verdicts, proofs and attack traces | `results.json`, `traces/` |
| Legacy bounded Maude encoding of the revision-1 rules | `maude/` (not in `results.json`, see "Legacy Maude") |

```
formal/install.sh                     # tamarin-prover 1.10.0 + maude into formal/bin (gitignored)
formal/run_all.sh                     # every Tamarin lemma; TIMEOUT=600 s per lemma; writes results.json
python3 -m pytest tests/test_formal_models.py
```

`run_all.sh` exits non-zero on any mismatch against `EXPECTED`, any error, or any lemma that is
missing from the table. It also exits non-zero if Tamarin prints `wellformedness check failed`: that
run is recorded as `error` and its verdict is discarded (F10). The whole run takes about 3 minutes.

## Assumptions

The adversary is the **agent**, modelled as a Dolev-Yao attacker. It picks every tool call, including
any structured effect ⟨tool, target, amount⟩ and any explanation text. It sees everything the gateway
returns and every WebAuthn assertion, and it can send any message to any gateway rule.

Three hypotheses are **part of the theory**, not hidden in it. Each one is a rule that the adversary
can use, and each rule emits a marker action. A lemma states the hypotheses it relies on as
conjuncts of its premise:

| | Hypothesis | Violating rule (marker) | Code / deployment counterpart |
|---|---|---|---|
| **H1** | The human decides from the **trusted fields** of the card only: the gateway-rendered descriptor and grant. The human does not decide from the agent-supplied explanation box. | `Human_DecidesOnExplanation` (`DecidesOnExplanation(U, aid)`), stated per approval | The explanation box is collapsed by default and labelled untrusted (D-005 item 6, `render_card`). A8 priming is exactly the violation of H1. Human-factors measurement belongs to the paper, not the model. |
| **H2** | **Enrollment is closed.** Only the device holder can enroll a principal's first credential. | `Open_Enrollment` + `Agent_Enrolls` (`EnrollmentOpen()`) | D-005 item 2: a one-time out-of-band enrollment token is required unless `dev_mode: true`. |
| **H3** | **Honest rendering origin.** The page that drives the authenticator shows the card that matches the challenge it hands to the authenticator. | `Origin_Controls_Ceremony` (`CeremonyControl(U)`). It replaces the old `Corrupt_Gateway` rule, which was a no-op (F2, mutant M5). | The gateway serves the approval page and chooses the challenge (`approval_options`). Authenticators do not display the challenge. H3 is the "honest rendering origin" trust assumption for consent-level P5 (D-005 item 7). For L1–L3/L5 it is implied by the honest-gateway trust base of SPEC §3. |

The remaining modelling assumptions are named here and are **not** hypotheses of any lemma:

* **A-Chan.** The gateway→origin channel (`ToDevice`) has integrity. Confidentiality is *not* assumed:
  the agent learns `aid` and every assertion.
* **A-Render.** Rendering is injective. In the model, `render/1` has a left inverse
  (`unrender(render(x)) = x`), and the human rules read `unrender(card field)`. On the code side, the
  obligation is the type-faithful `render_card` with its injectivity property test (D-005 item 6,
  `tests/redteam/test_rt_formal_render_injective.py`).
* **A-UI.** Only the human operates the authenticator UI. The agent cannot drive the user's browser or
  auto-answer the prompt. This is a deployment requirement, and it fails if the agent controls the browser
  in which the approval page runs.
* **A-Enc (challenge encoding).** The code's challenge is
  `SHA-256(JCS({"tag":"ASU-APPROVAL-v2","digest":h,"approval_id":id,"nonce":n,"grant_digest":g|null}))`
  (`asu/authn/receipt.py challenge_message`, JCS by `asu/jcs.py canonicalize`, RFC 8785). JCS of an
  object with a fixed key set is injective in the field values, and SHA-256 is assumed collision
  resistant. The challenge is therefore modelled as the free tuple `⟨'ASU-APPROVAL-v2', h, aid, gd⟩`
  with `gd = h(g)` or `'null'`. This replaces the v1 unframed concatenation, whose `approval_id‖nonce`
  split was ambiguous (F4).
* **Perfect cryptography.** Signatures are unforgeable without the key. `h` is a free function standing
  for SHA-256(JCS(·)).
* **Device keys.** Device keys are honest unless `Compromise_Device` fires. Every escape is
  **time-ordered** (`Compromise(U) @ #k & #k < #i`), so a compromise *after* the event does not
  excuse it (F12). Receipts carry no trusted time, so a judge cannot tell a post-compromise forgery from a
  genuine receipt.

## Lemmas and results (Tamarin 1.10.0, all unbounded)

`results.json` has 53 rows, **0 mismatches and 0 errors**. Proof sizes are given in steps.

### ASU (`asu.spthy`)

| Lemma | Statement (premise ⇒ conclusion, or earlier compromise) | Hyp. | Result |
|---|---|---|---|
| `L1_effect_binding` | Execute(U,aid,e) ⇒ the human approved e for aid beforehand | H1 H2 H3 | verified (26) |
| `L1_sig_binding` | Execute(U,aid,e) ⇒ U's authenticator signed h(e) for aid | H2 | verified (26) |
| `L2_single_use` | at most one Execute per aid | — | verified (28) |
| `L3_agent_independence` | Approved(U,aid,e) ⇒ the human approved e for aid | H1 H2 H3 | verified (31) |
| `L4_non_repudiation` (**key-level P5**, D-005 item 7) | JudgeAccepts(U,aid,hd,gd) with only pk(U) ⇒ U's authenticator signed exactly (hd, aid, gd). **Holds even when the rendering origin controls the ceremony.** | H2 | verified (14) |
| `L4c_consent_nonrepudiation` (consent-level P5) | JudgeAccepts(U,aid,h(e),gd) ⇒ the human approved e | H1 H2 H3 | verified (14) |
| `L5_grant_scope` | ExecuteGrant(U,gid,⟨t,r,a⟩) ⇒ the human approved, on card gid, an effect ⟨t,r,a₀⟩ **and** the gateway-built grant ⟨'grant',U,t,r,a₀⟩ with a ≤ a₀ | H1 H2 H3 | verified (36) |
| `L5b_grant_max_uses` | at most max_uses (= 2) grant executions | — | verified (768) |
| `exec_possible`, `grant_exec_possible`, `judge_possible` | exists-trace witnesses under H1–H3 with no compromise (non-vacuity) | | verified |

**X1–X3: strengthened-adversary attack variants.** Each variant is the **same theory** as a main lemma
with exactly one hypothesis dropped and the conclusion unchanged. The tests check this. Because the
variant lives in the same file, the attacked model cannot drift from the verified one.

| Variant | Dropped | Lemmas | Result | Attack |
|---|---|---|---|---|
| X1 | H1 | `X1_L1_effect_binding_noH1`, `X1_L3_agent_independence_noH1` | falsified (5, 6) | E.g. the agent writes the explanation "send 5 to alice" for an effect paying 500 to mallory. The human decides on the box and taps. The signature binds the real h(e), so L1_sig and L4 still hold. This is exactly the V2 verdict pattern. |
| X2 | H3 | `X2_L4c_consent_nonrepudiation_noH3`, `X2_L1_effect_binding_noH3` | falsified (8, 8) | The origin shows card e and has the authenticator sign the challenge for h(e′). The judge accepts h(e′), which the human never saw. Key-level `L4_non_repudiation` still verifies in the same theory. |
| X3 | H2 | `X3_L1_effect_binding_open_enrollment`, `X3_L1_sig_…`, `X3_L4_…`, `X3_L5_…` | falsified (8, 8, 5, 11) | The agent enrolls the first credential of an unused principal and then approves its own calls and grants. |

### Baselines, mutant and straw man

| Model | Code counterpart | Expected to fail (and fails) | Holds |
|---|---|---|---|
| V1 `v1_unbound` | mode `unbound`: `_execute_unbound`, `run_approved` session flag | L1 (agent resubmits e′; then the run-approved session executes later calls with no approval at all), L1_sig (the device never signs h(e)) | L2, L3 |
| V2 `v2_narration` | mode `narrated-card`: `render_narrated_card` | L1, L3: a careful human reads the whole card, and the card *is* the narration | L1_sig, L2, L4 |
| V3 `v3_replay` | **mutant**, no implementation | L2 | L1, L1_sig, L3, L4 |
| V4a `v4_totp_relay` | mode `totp`: `_check_totp`, in-call `totp_code` path, `totp_verify` | L1, L3: a code typed into the agent's chat for approval a₀ approves a₁, or rides along with a new call | L2 |
| V4b `v4b_chat_confirm` | mode `chat-confirm`: `chat_confirm` | L1, L3: the agent writes the "yes" itself | L2 |
| V5 `v5_mac` | **straw man**, no implementation (aiAuthZ-style shared-key MAC; the judge must be *handed* the key) | L4: a corrupt gateway mints MACs | L1–L3 (honest gateway) |

Revision-2 changes to the baselines:
* V1 gained the `run_approved` behaviour. V1's L4 "straw judge" was dropped, because the code marks
  unbound receipts `verifiable: false` (F9).
* V4a gained the in-call path and single-use time steps.
* V4b's unbound variable is fixed (F10).
* The no-op `Corrupt_Gateway` rule was removed from V1–V4b.

### Reading the results honestly

* **ASU vs V2 (F1).** ASU and V2 sign the same v2 challenge over h(e). They differ only in whether the card
  carries trusted fields. The separation is: *ASU gives L1 to a human who decides on the trusted
  fields (H1); V2 gives it to no one.*
* **P5 (F2, D-005 item 7).** The unconditional claim is key-level: *a third party with pk_U can verify
  that U's authenticator signed digest h for approval id* (`L4_non_repudiation`). The consent-level claim
  "U approved h" is `L4c`. It holds only under H3 (honest rendering origin), and X2 shows that it fails
  without H3. The separation from V5 is that a corrupt gateway cannot mint a receipt after the fact,
  without a live ceremony in which the user taps.
* **Depth.** The proofs are short (5–36 steps; `L5b` takes 768). They rest on two mechanisms:
  unforgeability of a signature over a fresh approval id, and linear facts that can be consumed once.
  The hard parts of the problem are stated as hypotheses H1–H3 and assumptions A-*, not proved.
  The mutation tests in `tests/test_formal_models.py` show the lemmas are not vacuous. Each of the
  following makes the named lemma falsified:
  * dropping the target check, the amount bound or the grant digest at grant execution (L5);
  * dropping the aid from the verified challenge (L1_sig);
  * executing the agent's resubmitted args (L1);
  * not consuming the approval (L2).
* **What the digest re-check does.** `Eq(h(e2), h(e))` in `Gateway_Execute` mirrors the code but is not
  load-bearing in the model (critique mutant M1). The model's gateway executes its *stored* e. In the
  code, the re-check matters together with the re-canonicalisation of `raw_args` (symlink TOCTOU), which
  is not modelled.

## Grants (F6, D-005 items 1 and 5)

The grant is no longer a separate ceremony, and the agent no longer chooses it. The model follows
the code:

* The **gateway** builds `g = ⟨'grant', U, t, r, a⟩` from the descriptor `e = ⟨t, r, a⟩`
  (`build_grant_request`) when it offers a grant. The human ticks "allow similar" on the card, and the
  digest `h(g)` goes **inside the approval challenge** (`grant_digest`). Only an assertion over
  `⟨tag, h(e), aid, h(g)⟩` activates the grant (`Gateway_Verify_Grant` ↔ `store.mark_approved`, which
  accepts a grant only when the receipt covers its JCS digest).
* The **field-by-field matching** at execution is `Eq(t2,t)`, `Eq(r2,r)` and `LeqNat(a2, cap)`
  (natural numbers), mirroring `grant_matches`:
  * `t` stands for the equality-checked context (tool, effect_class, principal/session/agent/origin);
  * `r` stands for **all bound arguments**, including target, recipients, accounts, paths and URLs, which
    are never free;
  * `a` is the single free amount, bounded by the approved amount (`max_amount`).
* max_uses = 2 is modelled by two linear use tokens (`try_use_grant` takes the minimum of the row and
  signed `max_uses`).
* The old L5 conjunct `c2 = c` compared the executed effect with the rule's own input pattern, so it
  was a tautology. It has been dropped. L5 now relates the executed effect to what the **human**
  approved.

## Not modelled (verified by tests only, or not at all)

* **Expiry (P3).** There is no time. An `Expire(aid)` rule would only restate linearity. Expiry is
  enforced in `store.mark_approved`/`consume` and covered by unit tests. We removed it from the model
  and say so here.
* **Nonce.** It is removed from the modelled challenge. It is inert because `aid` is fresh (critique
  mutant M6). Dropping a field from the signed tuple only makes signatures reusable in more contexts,
  which over-approximates the adversary.
* **Sessions and A11.** Approval ids are not bound to sessions in the model. The code binds them in
  `_execute_approved` (`cross_session`), and tests check it.
* **Free text grant arguments** (`free_args` of type text). The grant lemma does not claim them.
* **Amount aggregation.** `max_total_amount` and threshold splitting are not modelled. Only the per-use
  bound and the use count are.
* **WebAuthn details.** clientDataJSON, origin and rpIdHash, UP/UV flags, sign counters and attestation
  are not modelled. `verify_receipt` checks them.
* **Receipt re-verification at execute** (`reverify_receipts`) and **re-canonicalisation of `raw_args`**
  are not modelled. The model's gateway is honest, so neither changes a verdict.
* **Flood control (P7), fatigue, policy-allowed effects.** L1 covers only executions *via an approval*
  (`Execute`) and *via a grant* (`ExecuteGrant`). Effects that policy allows without a challenge are
  outside every lemma.
* **Grant use without receipt re-verification.** The code trusts the grant row on the grant path, which
  is equivalent to the model only under an honest gateway and database.

## Model ↔ code correspondence

Line numbers come from the 2026-10-13 snapshot and will drift. The **symbol** is authoritative, and
`tests/test_formal_models.py::test_correspondence_table_symbols_exist` checks that each listed symbol
still exists.

| Code check | file:line (symbol) | Model rule / element |
|---|---|---|
| v2 challenge object, JCS-encoded | `asu/authn/receipt.py:113` (`challenge_message`), `:136` (`compute_challenge`), `:145` (`approval_challenge`) | `⟨'ASU-APPROVAL-v2', h(e), aid, gd⟩` in `Origin_Ceremony*`, `Gateway_Verify*`, `Judge_Accept` (A-Enc) |
| JCS canonicalisation | `asu/jcs.py:152` (`canonicalize`) | free tuple / `h` (A-Enc) |
| descriptor digest h(Δ) | `asu/descriptor.py:538` (`digest`) | `h(e)` |
| card with trusted fields and an untrusted explanation box | `asu/descriptor.py:916` (`render_card`), `:977` (`agent_explanation_untrusted`) | card `⟨aid, render(e), render(g), expl⟩`; `Human_DecidesOnTrustedFields` / `Human_DecidesOnExplanation` (H1, A-Render) |
| narrated card (baseline) | `asu/descriptor.py:985` (`render_narrated_card`) | V2 `Human_ReadsCard` |
| enrollment gate (token unless dev_mode) | `asu/authn/routes.py:284` (`register_options`) | `Register_Device`; `Open_Enrollment` + `Agent_Enrolls` (H2) |
| gateway serves the challenge to the approval page | `asu/authn/routes.py:552` (`approval_options`, `approval_challenge(ap, with_grant=…)` at :572) | `Origin_Ceremony`, `Origin_Ceremony_WithGrant` (honest, H3) / `Origin_Controls_Ceremony` |
| assertion verification at approval | `asu/authn/routes.py:592` (`approval_verify`) | `Gateway_Verify`, `Gateway_Verify_Grant` (`verify(s, …, pkU)`) |
| grant accepted only if covered by the receipt | `asu/store.py:423` (`mark_approved`) | `Gateway_Verify_Grant` (challenge with `h(g)`) |
| grant built by the gateway from Δ | `asu/grants.py:39` (`build_grant_request`) | `Gateway_ToolCall_OfferGrant` (`g = ⟨'grant',U,t,r,a⟩`) |
| grant digest | `asu/authn/receipt.py:89` (`grant_digest`) | `h(g)` |
| grant field matching: context equality, bound args, amount ≤ max | `asu/grants.py:98` (`grant_matches`; `grant_bound_arg_mismatch` :119, `grant_amount_over` :127/:141) | `Gateway_ExecuteUnderGrant`: `Eq(t2,t)`, `Eq(r2,r)`, `LeqNat(a2,cap)` |
| grant use cap | `asu/grants.py:145` (`try_use_grant`, `min(max_uses)` :161) | two linear `GrantUse` tokens (L5b) |
| digest re-check of resubmitted args | `asu/gateway.py:244` (`_execute_approved`, `resubmitted_args` :282) | `Gateway_Execute` `Eq(h(e2), h(e))` |
| atomic consume | `asu/store.py:486` (`consume`), called at `asu/gateway.py:298` | linear `ApprovedSt` (L2) |
| execute the **stored** descriptor | `asu/gateway.py:301` (`_run(ap["descriptor"], …, via="approval")`) | `Gateway_Execute` emits `Execute(U, aid, e)` for stored e |
| offline receipt verification | `asu/authn/receipt.py:258` (`verify_receipt`) | `Judge_Accept` (L4, L4c) |
| unbound baseline + run_approved | `asu/gateway.py:303` (`_execute_unbound`), `unbound_session` :196 | V1 `Gateway_Execute`, `Gateway_RunApproved_Execute` |
| TOTP baseline (relay and in-call) | `asu/gateway.py:228` (`_check_totp`), `totp_code` :199; `asu/authn/routes.py:740` (`totp_verify`) | V4a `Gateway_Verify`, `Gateway_ToolCall_WithCode`, `TotpStepOnce` |
| chat-confirm baseline | `asu/gateway.py:409` (`chat_confirm`) | V4b `Gateway_Verify` |
| session/user binding of approval ids | `asu/gateway.py:250` (`cross_session`) | **not modelled** |
| re-canonicalisation of `raw_args` | `asu/gateway.py:291` (`resolution_changed`) | **not modelled** |
| receipt re-verification at execute | `asu/gateway.py:294` (`reverify_receipts`) | **not modelled** (honest gateway) |

## Caveats

* Tamarin 1.10.0 reports the system Maude 3.2 as "unsupported" (it wants 3.2.1 or later). The verdicts
  were obtained with Maude 3.2, and `results.json.caveats` records this. Re-run with Maude ≥ 3.2.1 to
  remove the caveat.
* The binary's provenance is recorded in D-003 (release 1.10.0, sha256 `cdccc3c0…`).

## Legacy Maude

`maude/*.maude` encodes the **revision-1** rules: a v1 challenge with nonce, a separate grant ceremony
whose constraint the agent chooses, and no explanation box, enrollment adversary or ceremony control.
It runs a bounded `search` with at most 3 approvals. It is kept only as a bounded cross-check of the
core binding and consumption rules: `formal/run_all.sh --only maude --out /tmp/maude.json`, and the
property, mutation and quick-run tests in `tests/test_formal_models.py`. It does **not** contribute
to `results.json` and must not be cited for revision-2 claims.
