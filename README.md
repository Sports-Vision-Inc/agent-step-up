# Agent Step-Up (ASU)

**Before an AI agent sends money, deletes files or emails someone new, it asks you. This project makes sure
that "yes" means yes to exactly that action, and nothing else.**

This is the code, data and proofs behind the paper
*Approve What, Exactly? Effect Binding and Trusted Rendering for Agent Step-Up Authorization*
(Sai Varun Kodathala, Prashanth Pollishetty, Jaylen Cargill, SportsVision AI). The PDF is in `paper/`.

---

## The problem in one minute

Many agents already pause and ask for approval. That pause is usually treated like a second factor, the way a
code on your phone protects your bank login. But it often isn't one:

- **The agent writes the question.** If the card says "Email the report to your boss", you approve the
  description. The real call might also blind-copy the report to someone else.
- **The approval doesn't name the action.** If the approval only says "allowed", the agent can change the
  amount or the recipient after you tap.
- **The agent can answer for you.** If the "are you sure?" happens in the agent's own chat, anyone who can
  write in that chat can say yes.

## What ASU does

```
 agent ──call──▶ gateway ──card──▶ your phone
                    │                  │  you read the card and approve with your passkey
                    ◀────── signature over the exact call
                    │
                    └──▶ runs the exact call you approved, once
```

1. The agent never runs risky tools itself. It asks a **gateway** on another machine.
2. The gateway turns the call into a fixed, canonical form and computes its fingerprint (a SHA-256 digest).
3. Your **phone** shows a card built from that exact call, not from the agent's words, and your passkey signs
   the fingerprint.
4. The gateway runs **the stored call**, once. If the agent tries to change anything, it gets
   `409 effect_mismatch` and nothing runs.

## What it guarantees

| | Property | In plain words |
|---|---|---|
| P1 | Agent independence | The agent can't see, fake or answer the approval. It only gets an approval id. |
| P2 | Effect binding | What runs is exactly what you approved. Any change in arguments is refused. |
| P3 | Single use | One approval runs one action, once, before it expires. |
| P4 | Trusted card | Everything on the card comes from the real call. The agent's own text is boxed and marked untrusted. Hidden characters and padding are shown, not hidden. |
| P5 | Verifiable receipt | Anyone with your public key can check later which action your device signed. |
| P6 | Safe "allow similar" | A grant keeps every recipient, account and path fixed; only the amount (up to a cap) and free text may vary, for a limited number of uses. |
| P7 | No approval spam | Rate limits, one pending card at a time, and a lockout after repeated denials. |

These are proven in Tamarin under three stated assumptions (see `formal/README.md`), and tested against the
live gateway (`tests/`).

**What it does not do:** it can't stop you from approving something harmful that is shown truthfully, it
doesn't help with actions your policy allows without asking, and approval flooding still works some of the
time against a tired person. The paper reports these honestly.

---

## Try it

Needs Python 3.10 or newer.

```bash
git clone https://github.com/Sports-Vision-Inc/agent-step-up
cd agent-step-up
python3 -m venv .venv && source .venv/bin/activate
pip install -e . -r requirements-experiments.txt
```

**Run the tests** (about 3 minutes):

```bash
python -m pytest -q tests
```

**Run the gateway** on your own computer:

```bash
asu serve                         # gateway at http://localhost:8000, approval page at /app
asu enroll-link --user alice      # prints a one-time link: open it and add a passkey
asu dev-session --user alice      # prints a token for your agent
```

Point your agent at `POST /v1/tools/call` (or the MCP endpoint `POST /mcp`) with that token. When a call needs
approval, it appears on the approval page, and the agent retries with the approval id once you approve. The
policy lives in `asu/policies/default.yaml`.

To use a phone, serve the gateway over HTTPS on an address the phone can reach and set `rp_id` and `origin` in
the config.

## Reproduce the paper

| What | Command | Where the results go |
|---|---|---|
| Scripted attacks, AgentDojo replay, fatigue, latency | `python -m experiments.run_all` | `experiments/results/` |
| Language models as approvers (needs an OpenRouter key) | `python -m experiments.live.llm_approver run --config experiments/live/llm_approver.example.yaml` | `experiments/results/live_llm_approver_*` |
| Formal proofs (Tamarin 1.10.0) | `formal/install.sh && formal/run_all.sh` | `formal/results.json` |
| Runtime audit | `python audit/run_all.py` | `audit/results/` |
| Attack matrix (needs the AP2 and AGT clones, see `attacks/targets.py`) | `python attacks/run_all.py` | `attacks/results/` |
| The paper, with every figure and number | `cd paper && make` | `paper/build/main.pdf` |

The results used in the paper are already committed, so `cd paper && make` works without rerunning anything.
Every number in the paper text comes from `paper/scripts/make_figures.py`, which reads those results.

## What's in the repo

```
asu/          the gateway: canonical descriptor, policy, grants, WebAuthn approval, receipts, audit log, MCP
web/          the approval page your phone opens
formal/       Tamarin models of ASU and the baselines, and the proof results
experiments/  attack scenarios, AgentDojo replay, simulated approvers, language-model approvers
audit/        probes for ten agent runtimes and their results
attacks/      the twelve approval-path attacks (AB1 to AB12) and their results
tests/        unit, red-team and live-gateway tests
paper/        LaTeX source, figures, data and the built PDF
```

## Citing

```bibtex
@misc{kodathala2026approve,
  title  = {Approve What, Exactly? Effect Binding and Trusted Rendering for Agent Step-Up Authorization},
  author = {Kodathala, Sai Varun and Pollishetty, Prashanth and Cargill, Jaylen},
  year   = {2026}
}
```

This work builds on [aiAuthZ](https://github.com/Sports-Vision-Inc/aiAuthZ)
([arXiv:2607.05518](https://arxiv.org/abs/2607.05518)).

Questions: varun@sportsvision.ai
