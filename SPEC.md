# SPEC — Agent Step-Up (ASU): Multi-Factor Authentication for AI Agent Actions

This file is the shared contract for every builder and critic. If code and this
spec disagree, fix one of them explicitly and record it in `docs/DECISIONS.md`.

Working paper title: **"Factors the Agent Cannot Reach: Multi-Factor
Authentication for AI Agent Actions"**. Author: Sai Varun Kodathala.
This is new work. It does NOT reuse aiAuthZ code; aiAuthZ (arXiv 2607.05518)
is cited as prior work by the same author.

## 1. Thesis

A factor protects an agent action only if compromising the agent cannot
produce it. Under that criterion most deployed "approvals" for agents are
single-factor: the approval is rendered by, readable by, answerable by, or
substitutable by the agent. We (C1) define the property, (C2) measure how
often it is missing in real runtimes, (C3) give a protocol (ASU) that has it,
(C4) verify the protocol formally, (C5) implement and evaluate it including
new attacks on the approval process itself, and (C6) provide a user-study
design.

## 2. Mapping human MFA to agents

| Human MFA | Agent analogue in ASU |
|---|---|
| knowledge / possession / inherence factors in independent places | factors held in trust domains the agent cannot reach (user's phone authenticator, gateway on another host) |
| step-up for risky transactions | risk policy returns `challenge` |
| dynamic linking (PSD2 SCA: approval bound to amount + payee) | approval signature covers the digest of the canonical effect descriptor |
| MFA fatigue / push bombing | approval flooding by a compromised agent |
| authenticator shows transaction details | card rendered by trusted code from the descriptor, never from agent text |

Factor types for agent actions:
- **Principal factor**: proof the human principal (not a speaker claiming to be them) is present — passkey on the user's device.
- **Effect factor**: the human approved this exact effect — signature over descriptor digest.
- **Workload factor** (optional, out of core scope): attestation that the agent instance is the registered one.
- **Context factor**: risk signals deciding *when* to challenge (not a factor in the cryptographic sense; never sufficient alone).

## 3. Security properties (definitions used everywhere)

- **P1 Agent-independence.** The approval factor cannot be read, forged, auto-answered, overlaid or replayed from any position the agent controls (its process, context, tools, chat/terminal surface).
- **P2 Effect-binding (WYSIWYS).** The approval authorizes only the complete canonical effect it was rendered from; any material difference between approved and executed effect is rejected.
- **P3 Freshness and single use.** An approval is bound to a nonce and expiry and is consumed atomically on execution; it cannot be replayed or reused.
- **P4 Trusted rendering.** Everything the human is shown about the effect is derived by trusted code from the descriptor. Agent-supplied text may appear only in a clearly labelled "agent's explanation (untrusted)" box.
- **P5 Non-repudiation.** A third party holding only the user's public key can verify which descriptor digest was approved, without trusting the gateway.
- **P6 Scope integrity.** A delegated grant ("allow similar for 1h, max N") cannot be stretched beyond the constraints signed into it.
- **P7 Flood resistance.** A compromised agent cannot obtain approval by volume (rate limits, one pending approval per session, lockout after repeated denials, de-duplication).

Threat model: the agent (model, context, tools, runtime, its host) is fully adversarial. The gateway host, the user's authenticator device and the WebAuthn authenticator are trusted. The human may be inattentive (modelled by approver oracles). Out of scope: a human who knowingly instructs the harmful action; read-only information leakage; kernel/sandbox escape that bypasses the gateway; compromise of the user's phone.

## 4. Protocol (ASU)

Actors: User U (with authenticator device D holding a passkey), Agent A (untrusted), Gateway G (trusted, separate host), Resource R.

1. **Enrollment.** U registers a WebAuthn passkey with G (RP ID from config; `localhost` in dev). G stores credential id + public key.
2. **Session.** U authenticates with the passkey to open an agent session; G issues A a session token bound to (user, session, agent_id, scopes, expiry). The session token alone never authorizes a challenged effect.
3. **Tool call.** A sends `(session_token, tool, args, origin, explanation?)` to G.
4. **Canonicalize.** G computes descriptor Δ (section 5) and `h = SHA-256(JCS(Δ))`.
5. **Decide.** Policy returns allow | deny | challenge (+ reasons, risk score). A matching unexpired grant can turn challenge into allow, within its signed caps.
6. **Challenge.** G stores approval `ap = (id, h, Δ, nonce, expires, status=pending)` and returns 202 `{approval_id, status}` to A. A learns nothing else (no codes, no card text).
7. **Approve.** U opens the authenticator page (served by G, on U's browser/phone, never via A). G renders the card from Δ. WebAuthn challenge `c = SHA-256("ASU-APPROVAL-v1" || h || ap.id || ap.nonce)`. U's passkey signs; G verifies assertion, stores `(authenticatorData, clientDataJSON, signature, credential_id)` as the receipt, sets status=approved. U may also tick "grant similar", producing a grant whose constraints are part of what is signed (grant descriptor digest included in `c` as `h_grant`).
8. **Execute.** A retries with `approval_id` (args optional). G recomputes Δ' from any resubmitted args; if `h' != h` → reject `effect_mismatch`. G atomically consumes the approval (`approved → consumed`) and executes **Δ** (not the agent's copy) via the executor, or, in token mode, returns a short-lived Ed25519-signed authorization token `{h, aud, exp, jti}` that R verifies (single-use jti) before acting.
9. **Audit.** Every step is appended to a SHA-256 hash-chained audit log. Receipts are exportable and verifiable offline (`asu verify-receipt`).

Baselines implemented for comparison (flag `--approval-mode`):
- `none` — no step-up (allow by policy).
- `chat-confirm` — agent asks "may I?" in its own channel and a yes in that channel approves (P1 fails).
- `narrated-card` — out-of-band card but text supplied by the agent (P4 fails).
- `unbound` — out-of-band passkey approval of a run/session, not bound to h (P2 fails).
- `totp` — out-of-band but approval is a TOTP code, which carries no effect binding (P2/P5 fail; code can be relayed).
- `asu` — full protocol.

## 5. Canonical effect descriptor Δ (v1)

JSON object, canonicalized with RFC 8785 JCS (implement or use `jcs`/`rfc8785` package), fields:
```
{ "v": 1,
  "tool": str,                     # e.g. "send_email"
  "effect_class": str,             # read | write | delete | send | pay | exec | net | admin
  "args": {...},                   # normalized (below); every argument that can change the effect
  "target": str|null,              # resolved resource (abs path / host / recipient / account)
  "principal": user_id,
  "session_id": str,
  "agent_id": str,
  "origin": "user_turn"|"autonomous",
  "issued_at": int, "expires_at": int }
```
Normalization rules (must be tested): paths → absolute, `os.path.normpath`, resolved against the configured workspace root, symlinks resolved when the executor runs on the gateway host (record both `path` and `resolved_path`); URLs → scheme+lowercased host+port+path, reject userinfo; emails → lowercase, IDNA; amounts → decimal string, currency uppercase; shell → argv list (never a joined string), plus env and cwd; unknown args are included verbatim (never dropped). Agent free-text explanation is NOT part of Δ.

## 6. Repository layout and ownership

```
asu/                 gateway core (owner: GATEWAY builder)
  config.py  descriptor.py  policy.py  store.py  audit.py  executors.py
  tokens.py (Ed25519 authz tokens + verifier)  grants.py  ratelimit.py
  app.py (FastAPI app factory create_app(config)) mcp.py cli.py
asu/authn/           WebAuthn + TOTP + authenticator routes (owner: AUTHN builder)
web/                 authenticator PWA static files (owner: AUTHN builder)
formal/              Tamarin models + run script + results (owner: FORMAL)
audit/               runtime audit harness + matrix (owner: AUDIT)
experiments/         attack suite, oracles, AgentDojo, live-model runner (owner: EXPERIMENTS)
study/               user-study protocol + materials (owner: STUDY)
paper/               LaTeX paper (owner: PAPER)
tests/               shared tests; each builder adds tests/test_<area>_*.py
docs/                DECISIONS.md, RELATED_WORK_NOTES.md, CRITIQUE_*.md
```
Python ≥3.10 compatible (user's Mac and the cloud box run 3.10–3.13). Dependencies go in `pyproject.toml` (package name `asu-gateway`). Use `sqlite3` via the standard library or SQLAlchemy; no external DB or Redis required.

## 7. Internal interfaces (MUST match exactly)

`asu/store.py` (GATEWAY implements, AUTHN calls):
```
class Store:
    def __init__(self, path: str): ...
    # users / credentials
    def create_user(self, user_id: str, display_name: str) -> None
    def get_user(self, user_id: str) -> dict | None
    def add_credential(self, user_id: str, credential_id: bytes, public_key: bytes, sign_count: int, transports: list[str]) -> None
    def get_credentials(self, user_id: str) -> list[dict]      # dicts with credential_id, public_key, sign_count, transports
    def update_sign_count(self, credential_id: bytes, sign_count: int) -> None
    def set_totp_secret(self, user_id: str, secret: str) -> None
    def get_totp_secret(self, user_id: str) -> str | None
    # approvals
    def get_approval(self, approval_id: str) -> dict | None   # keys: id, user_id, session_id, digest, descriptor(dict), nonce, status, created_at, expires_at, receipt(dict|None), grant_request(dict|None)
    def list_pending(self, user_id: str) -> list[dict]
    def mark_approved(self, approval_id: str, receipt: dict, grant: dict | None = None) -> bool   # pending→approved only; False otherwise
    def mark_denied(self, approval_id: str) -> bool
    def consume(self, approval_id: str) -> bool                # approved→consumed atomically
```
`asu/descriptor.py`: `canonicalize(tool, args, ctx) -> dict`, `digest(desc) -> str (hex)`, `render_card(desc) -> dict` (title, effect_class, risk_lines[list[str]], fields[list[{label,value}]]).
`asu/authn/__init__.py` exports `router` (FastAPI APIRouter mounted at `/v1/authn`) and `approval_challenge(approval: dict) -> bytes` (the WebAuthn challenge bytes per section 4 step 7) and `verify_receipt(receipt: dict, public_key: bytes, expected_digest: str, approval_id: str, nonce: str) -> bool` (pure, offline).
`asu/app.py`: `create_app(config: Config) -> FastAPI`; it constructs `Store`, mounts `asu.authn.router`, serves `web/` at `/app`, exposes app.state.store, app.state.config.

## 8. HTTP API (agent-facing; agent never touches /v1/authn or /app)

- `POST /v1/sessions` (requires user-authenticated cookie from authenticator page) → `{session_token, expires_at}`. Dev helper `asu dev-session` for tests.
- `POST /v1/tools/call` body `{tool, args, origin?, explanation?, approval_id?}`, header `Authorization: Bearer <session_token>` →
  - `200 {status:"executed", result, receipt_id}` | `403 {status:"denied", reasons}` | `202 {status:"approval_required", approval_id}` | `409 {status:"effect_mismatch"}` | `429 {status:"rate_limited"}`.
- `GET /v1/approvals/{id}` (session token) → `{status}` only.
- `POST /mcp` JSON-RPC 2.0: `initialize`, `tools/list`, `tools/call`. Approval required → JSON-RPC error `{code:-32010, message:"approval_required", data:{approval_id}}`. Must work for plain JSON and `Accept: text/event-stream`.
User-facing (authenticator): `/app` PWA; `/v1/authn/register/options|verify`, `/v1/authn/login/options|verify`, `/v1/authn/pending`, `/v1/authn/approvals/{id}/options|verify|deny`, `/v1/authn/totp/*` (baseline only).

## 9. Policy file (YAML)

```
tools:            # tool -> effect_class and default outcome
  send_email: {class: send, default: challenge}
  read_file:  {class: read, default: allow}
step_up:          # extra triggers that turn allow into challenge
  first_time_recipient: true
  amount_over: 100
  autonomous_origin: true
  destructive_classes: [delete, pay, admin, exec]
  aggregate: {window_s: 600, max_effects: 5, max_amount: 200}   # anti-laundering
deny:
  path_globs: ["/etc/**", "**/.ssh/**"]
grants: {max_ttl_s: 3600, max_uses: 10}
flood: {max_pending_per_session: 1, max_requests_per_min: 6, deny_lockout: 3}
```

## 10. Executors

`mock_ledger` (default for experiments): appends the executed descriptor JSON to a ledger file; ground truth for scoring. `http_forward`: POST descriptor to a URL with credentials resolved on the gateway. `python:<module:fn>`. `token`: returns Ed25519 authz token; `asu/tokens.py` includes `verify_token(token, public_key, expected_digest, aud) -> bool` and a single-use jti cache.

## 11. Experiments contract (EXPERIMENTS)

Agents under test are modelled at three levels: (a) **fully compromised scripted agent** (emits attacker tool calls, forges explanations, retries, floods, splits effects, substitutes args after approval); (b) **AgentDojo ground-truth replay** (benign user-task calls for utility/fatigue; injection-task calls as compromised agent); (c) **live LLM agents** via OpenRouter (script runs on the user's machine; key from `.env` `OPENROUTER_API_KEY`). Approver oracles: `diligent` (denies iff card shows an effect not implied by the user's task), `careless(p)` (approves with prob p regardless), `fatigued` (approval probability rises with prompts per session), `narration_trusting` (decides from agent text when the mode shows it). Metrics: ASR (attack effect reached ledger), TCR (benign effect reached ledger), prompts per task, false-block rate, approval latency (gateway side), flood success. Every number in the paper must be regenerated by `python -m experiments.run_all` and written to `experiments/results/*.json`.

Attack catalogue (each a test + experiment): A1 forged-identity/non-owner; A2 injection under owner authority; A3 narration forgery (Lies-in-the-Loop); A4 post-approval substitution (TOCTOU / Loopjacking); A5 replay of approval / receipt; A6 approval flooding; A7 approval laundering (split into sub-threshold effects); A8 consent priming (agent text pre-frames the card); A9 grant stretching; A10 path/URL canonicalization tricks (`..`, symlink, host suffix, IDN homograph); A11 cross-session approval reuse; A12 autonomous/heartbeat action without a human turn; A13 Agents of Chaos case reconstructions (#1 owner destructive, #2, #3, #8, #10, #11).

## 12. Honesty rules

No fabricated numbers. Anything not run is labelled "not run". Live-model results are only reported if the user runs them. Claims of novelty must be checked against `docs/RELATED_WORK_NOTES.md`. Limitations are written, not hidden.

## Revision log

- 2026-10-14 (ATTACKS area, per D-004): Added `attacks/` — the approval-binding
  attack family (AB1–AB12) tested defensively and locally against real
  third-party designs/implementations (Google AP2 `e1ea56d`, Microsoft AGT
  ADR-0030 `47abed7`, MCP Python SDK 2.3.0 elicitation, OpenClaw 2026.10.3
  static, the in-process frameworks via the AUDIT matrix) with ASU as the
  reference defense. Outputs: `attacks/run_all.py` → `attacks/results/matrix.{json,md}`,
  `attacks/DISCLOSURE_DRAFTS.md`, tests under `tests/test_attacks_*.py`, notes in
  `docs/notes/attacks.md`. No SPEC §1–§11 contract changed; this records the new
  area in the repo layout (§6 lists `experiments/` as owner of the attack suite;
  the AB-family cross-target measurement lives in `attacks/`).

- 2026-10-13 (FORMAL area, per D-005 items 1, 7, 8 and docs/critique/formal.md
  F1–F12): Tamarin models revised to revision 2 (`formal/tamarin/*.spthy`,
  `formal/README.md`). Lemmas are now stated under explicit hypotheses
  H1 (human decides from trusted fields), H2 (closed enrollment) and H3 (honest
  rendering origin), each the negation of a marker emitted by an adversary rule
  inside the same theory; X1–X3 are the same lemmas with one hypothesis dropped
  (falsified). P5 is claimed formally at key level (`L4_non_repudiation`, needs
  only H2); the consent-level reading (`L4c`) holds only under H1–H3. The model's
  challenge is the v2 JCS object as a tuple (nonce omitted, documented); grants
  are built by the gateway and bound by `grant_digest` inside the approval
  challenge, with field-wise matching; expiry and session binding are not
  modelled (tests only). `formal/results.json` now carries Tamarin verdicts only
  (53 rows, 0 mismatches, 0 errors); the Maude encoding is legacy (revision 1).
  No SPEC §1–§11 contract changed by this entry.

## Revision log

### 2026-10-13 — defense revisions (D-005 items 1–7, 9; crypto and red-team critique fixes)
Applied by the defense fixer; sections above are unchanged text and are superseded where they differ:
- **§4 step 7 / §7 approval challenge (v2):** `c = SHA-256(JCS({"tag":"ASU-APPROVAL-v2","digest":h,"approval_id":id,"nonce":n,"grant_digest":g|null}))`, injective (CR-2). `g = SHA-256(JCS(grant))` of the grant the gateway built from the approved descriptor. Receipts carry `"v": 2` and the signed flag bits; v1 receipts are rejected.
- **§4 step 1 enrollment:** closed by default. First enrollment for any user needs a one-time token delivered out of band (`asu enroll-link --user U` prints a one-time URL `…/app/#enroll=<token>&user=U`; tokens are stored hashed, expire after `enrollment_ttl_s`, and are consumed atomically). Only `dev_mode: true` relaxes this, with a loud startup warning, and only for user ids that do not exist yet. `asu dev-session` refuses to mint agent tokens for a principal without a passkey unless `--force-insecure` is given.
- **UV:** `require_user_verification` defaults to true; all ceremonies request `userVerification: "required"`.
- **§5 descriptor v2:** adds `arg_types` (recipient | account | amount | currency | path | url | argv | text | flag | int | enum, plus env and json), `schema` ("declared" | "inferred") and `targets` (union of every recipient/account/url-host/path argument; `target` = that union joined by ","). At most one amount and one currency argument; amounts are never summed.
- **§9 policy:** each tool declares `args: {name: type}`; packaged schemas for every default, scenario and AgentDojo v1 tool live in `asu/policies/schemas.yaml` and are merged by `load_policy` (`schema_library: true`). A declared schema is closed (unknown argument → deny `unknown_argument:<name>`); tools without a schema get the `no_arg_schema` step-up (`untyped_tools`). New flood keys `max_pending_per_user`, `deny_lockout_per_user`, `lockout_window_s` (set in default.yaml). Deny path globs match case-insensitively.
- **P6 grants (v2):** bind every argument to its approved value except `free_args`: the single amount (≤ approved amount, same currency, running total cap) and `text` arguments (length-bounded). Recipients, accounts, paths and urls are never free; the argument names and types must be identical.
- **P4 card v2:** typed literals (strings quoted), characters outside a printable allow-list escaped as `\u{XXXX}` and flagged, runs of blank/repeated characters collapsed as `\[N× …]` (injective), values capped with an explicit expand and a risk line, gateway labels separate from agent-chosen argument names (`arg.<name>`, section "arguments"), explanation collapsed by default and labelled untrusted, any shell/interpreter with inline code (`sh/bash/zsh/python/node/perl/ruby/pwsh … -c/-e`) flagged.
- **P5 restated (D-005 item 7):** a third party holding pk_U can verify that U's authenticator signed digest h for approval id (key-level). Consent-level non-repudiation holds only under the assumption of an honest rendering origin (authenticators do not display the challenge). `asu verify-receipt` requires `--public-key` and `--rp-id`, reports the signed flags and grant digest, and fails if the signature covers a grant the bundle does not disclose.
- **§10 tokens:** audience per resource (`tools.<t>.audience`, default `<token_audience>:<tool>`), `iss`/`iat`/lifetime checked, `SqliteJtiStore` for a persistent single-use jti store at the resource.
- **Other:** logout revokes the server-side login; sign count is compare-and-set; the audit chain carries a per-entry HMAC with a gateway key (`<db>.auditkey`, 0600); anti-framing headers on every response; one origin accessor (`Config.allowed_origins()`); dependency upper bounds in pyproject.toml. Terminology: A7 is "threshold splitting".

- 2026-10-13 (LLM_APPROVER area, per D-002 (a) and docs/critique/experiments.md EXP-10): Added the C6'
  machine-approver experiment `experiments/live/llm_approver.py` (`make-stimuli`, `run [--dry-run]`),
  generated stimuli `experiments/live/stimuli_llm_approver.json` (23 attacks in 8 approval-binding families
  + 11 benign near misses, placeholder data, card views from `asu.descriptor.render_card`), config
  `experiments/live/llm_approver.example.yaml`, tests `tests/test_experiments_llm_approver.py`, notes
  `docs/notes/llm_approver.md`. Conditions narrated / card / card_no_expl; outputs
  `experiments/results/live_llm_approver_*.{json,md}`. Not run (OpenRouter blocked here); no results claimed.
  No SPEC §1–§11 contract changed.

- 2026-10-13 (EXPERIMENTS area, v3 fixer; docs/critique/experiments.md EXP-1..EXP-11): §11 experiment
  methodology revised. No gateway contract changed.
  - The harness runs the deployed gateway configuration: `dev_mode` off, enrollment with a one-time token,
    UV required, closed schemas and per-user flood caps.
  - New approver oracle `perceptual` (salient visible fields, hand-written expectations, assumed miss
    probabilities). `diligent` is reported as "exact-compare (upper bound)".
  - Harness-side baselines `host-confirm` and `txn-sign`, and the `asu-no-expl` ablation. chat-confirm is
    reported as definitional.
  - Statistics: no CI on deterministic cells; common random numbers with paired McNemar tests;
    cluster-bootstrap CIs over AgentDojo injection tasks.
  - The fatigue sweep uses sessions in which fatigue persists, with a (slope, cap) sensitivity grid.
  - AgentDojo `security()` is reported alongside the project predicate, with adapter-sensitivity variants.
  - Benign near-miss tasks; ASR is split into "allowed by policy" vs "approval bypass".
  - The manifest records the git commit and dirty flag.
  - Not done: an adaptive best-response attacker and scenarios for the approval-binding attack family
    (EXP-2). See docs/notes/experiments.md.
- 2026-10-14 (EXPERIMENTS, measurement fixes after docs/critique/experiments_anomalies.md): section 11
  oracle semantics refined; no gateway contract changed.
  - Oracles read cards in a workspace-relative display (the trial's workspace root is shown as `/workspace`);
    results no longer depend on the machine's temporary-path length (D1).
  - `perceptual` also reads the Target row and the "actually resolves to" risk line; draws once per prompt
    against the closest outstanding expectation; grades text-only views (narrated card, chat, TOTP relay)
    with the same miss model.
  - Approving with "grant similar" delegates up to `max_uses` covered expectations; effects executed through a
    grant consume expectations.
  - `narration_trusting` with no agent text behaves like `perceptual` (was: `diligent`); it is no longer
    treated as a deterministic oracle.
  - The fatigue sweep uses one gateway and agent session per user session.
