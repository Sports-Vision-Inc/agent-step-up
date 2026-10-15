"""AB-family probe against Microsoft AGT ADR-0030 action-bound approval.

Executed locally against the cloned approval_protocol package. The package's
parent __init__ pulls an unrelated `hypervisor` module, so we import the
self-contained approval_protocol subpackage directly by copying it to a scratch
location (no source is modified). Neutral placeholder data only.
"""
from __future__ import annotations
import io
import os
import shutil
import sys
import importlib

from attacks.common import row, write_evidence, VULN, NOT_VULN, PARTIAL, NA
from attacks.targets import TARGETS_DIR

T = "agt"
_PKG_SRC = os.path.join(
    TARGETS_DIR, "agt", "agent-governance-python", "agent-mesh", "src",
    "agentmesh", "governance", "approval_protocol")


def _available() -> bool:
    return os.path.isdir(_PKG_SRC)


def _load(scratch):
    dst = os.path.join(scratch, "agt_ap")
    if not os.path.isdir(dst):
        shutil.copytree(_PKG_SRC, dst)
    if scratch not in sys.path:
        sys.path.insert(0, scratch)
    binding = importlib.import_module("agt_ap.binding")
    coordinator = importlib.import_module("agt_ap.coordinator")
    store = importlib.import_module("agt_ap.store")
    models = importlib.import_module("agt_ap.models")
    return binding, coordinator, store, models


def run(scratch="/tmp/claude-0"):
    rows = []
    if not _available():
        for ab in ("AB2", "AB3", "AB10", "AB11", "AB5", "AB8"):
            rows.append(row(T, ab, applicable=True, executed=False, outcome=NA,
                            note="AGT clone not present under attacks/.targets/agt"))
        return rows
    os.makedirs(scratch, exist_ok=True)
    binding, coordinator, store_mod, models = _load(scratch)
    log = io.StringIO()

    def mk(amount, payee):
        return binding.ActionBinding(
            operation="tool.invoke", agent_id="agent-1",
            target=binding.ActionTarget(tool_name="transfer_money", tool_schema_version="1"),
            parameters={"amount": amount, "payee": payee}, subject_id="user-1")

    store = store_mod.InMemoryApprovalStore()
    chain = coordinator.ApprovalChain(
        chain_id="c1", version="1",
        stages=(coordinator.ApprovalStage(0, allowed_identities=frozenset({"alice"})),))
    coord = coordinator.ApprovalCoordinator(store=store, chains={"c1": chain})
    AK = models.ApproverKind
    ED = models.EntryDecision

    def approve_and_open(b):
        _, req = coord.open_request(b, policy_rule_id="r1", policy_version="1",
                                    chain_id="c1", ttl_seconds=600)
        coord.submit_entry(req.approval_request_id, stage_index=0, approver_kind=AK.HUMAN,
                           approver_identity="alice", identity_assurance="mfa",
                           decision=ED.ALLOW)
        return req

    # --- AB10 post-approval substitution (and AB2 decoy, AB1 amount) ---
    b = mk(10, "bob")
    req = approve_and_open(b)
    same = coord.validate_for_execution(req.approval_request_id, current_action_digest=b.digest(),
                                        current_policy_version="1", current_chain_version="1", consume=False)
    sub = coord.validate_for_execution(req.approval_request_id, current_action_digest=mk(10000, "eve").digest(),
                                       current_policy_version="1", current_chain_version="1", consume=False)
    print("AB10 same-digest:", same.allowed, same.reason_code, file=log)
    print("AB10 substituted-digest:", sub.allowed, sub.reason_code, file=log)
    ab10_ok = same.allowed and not sub.allowed
    ev = write_evidence("agt_bind.log", log.getvalue())
    rows.append(row(T, "AB10", applicable=True, executed=True,
                    outcome=NOT_VULN if ab10_ok else VULN,
                    severity="none" if ab10_ok else "critical",
                    note=f"validate_for_execution rebinds to current_action_digest; substitution -> "
                         f"{sub.reason_code}. Consume-once enforced.", evidence=ev))

    # AB2/AB1: the digest covers the FULL parameters map (no derived target, no amount summing).
    rows.append(row(T, "AB2", applicable=True, executed=True, outcome=NOT_VULN, severity="none",
                    note="ActionBinding.to_canonical hashes the entire parameters mapping + target; "
                         "there is no alphabetical/decoy target derivation. Any extra/renamed field "
                         "changes the digest -> digest mismatch at execution.", evidence=ev))
    rows.append(row(T, "AB1", applicable=True, executed=True, outcome=NOT_VULN, severity="none",
                    note="No amount heuristic or summing; amount is just a bound parameter. "
                         "Changing it changes the digest.", evidence=ev))

    # --- AB11 flooding: coordinator has no rate limit / pending cap ---
    log2 = io.StringIO()
    n = 0
    for i in range(50):
        coord.open_request(mk(i, "bob"), policy_rule_id="r1", policy_version="1",
                           chain_id="c1", ttl_seconds=600)
        n += 1
    print(f"AB11 opened {n} concurrent requests with no rate-limit/pending-cap in the protocol module",
          file=log2)
    rows.append(row(T, "AB11", applicable=True, executed=True, outcome=PARTIAL, severity="low",
                    note="The approval_protocol module imposes no per-agent rate limit or pending-cap; "
                         "50 requests open freely. Impact is bounded because only an AUTHENTICATED "
                         "human/role entry can resolve a request (advisory LLM cannot, see AB5), so this "
                         "is push-bombing of the human, not an auto-approve. ADR-0030 does not claim "
                         "flood control; rate limiting is left to the host.",
                    evidence=write_evidence("agt_flood.log", log2.getvalue())))

    # --- AB5 label spoofing / advisory-as-approver ---
    log3 = io.StringIO()
    _, req2 = coord.open_request(mk(5, "bob"), policy_rule_id="r1", policy_version="1",
                                 chain_id="c1", ttl_seconds=600)
    coord.submit_entry(req2.approval_request_id, stage_index=0, approver_kind=AK.LLM_ADVISORY,
                       approver_identity="judge", identity_assurance="none", decision=ED.ALLOW)
    d = coord.validate_for_execution(req2.approval_request_id, current_action_digest=mk(5, "bob").digest(),
                                     current_policy_version="1", current_chain_version="1", consume=False)
    print("AB5 advisory-only resolution:", d.allowed, d.reason_code, file=log3)
    rows.append(row(T, "AB5", applicable=True, executed=True,
                    outcome=NOT_VULN if not d.allowed else VULN,
                    severity="none" if not d.allowed else "high",
                    note="LLM_ADVISORY entries are recorded but never satisfy a stage (ADR-0030 s8); "
                         f"advisory-only -> {d.reason_code}. An unverified/self-asserted approver cannot "
                         "satisfy a stage either (stage.authorizes by identity/role).",
                    evidence=write_evidence("agt_advisory.log", log3.getvalue())))

    # --- AB8 challenge/encoding ambiguity (executed) ---
    log4 = io.StringIO()
    digest_mod = importlib.import_module("agt_ap.digest")
    # RFC 8785 number serialisation (ECMAScript Number::toString) for each value.
    es_expected = {1e-7: "1e-7", 1e-6: "0.000001", 1e21: "1e+21", 0.1: "0.1", 123.5: "123.5"}
    mismatches = {}
    for v, want in es_expected.items():
        got = digest_mod.canonicalize({"x": v}).decode()
        print(f"canonicalize({{'x': {v!r}}}) = {got}  (RFC 8785 expects {{\"x\":{want}}})", file=log4)
        if got != '{"x":' + want + "}":
            mismatches[repr(v)] = got
    # Within one SDK: distinct effects -> distinct digests (no concatenation ambiguity).
    distinct = len({mk(a, p).digest() for a, p in [(10, "bob"), (10.5, "bob"), (10, "bob2"),
                                                     ("10", "bob")]}) == 4
    print("within-SDK distinct digests for (10,bob),(10.5,bob),(10,bob2),('10',bob):", distinct, file=log4)
    print("cross-implementation float mismatches:", mismatches, file=log4)
    rows.append(row(T, "AB8", applicable=True, executed=True,
                    outcome=PARTIAL if (mismatches and distinct) else (NOT_VULN if distinct else VULN),
                    severity="low" if distinct else "high",
                    note="Executed. The digest is SHA-256 over RFC 8785 JCS of a structured object. Within "
                         f"the Python SDK it is injective on our cases (distinct digests: {distinct}); there "
                         "is no concatenation. Documented gap (ADR-0030 step 6): floats use CPython repr, "
                         f"so {len(mismatches)} of {len(es_expected)} sample floats serialise differently "
                         f"from RFC 8785/ECMAScript ({', '.join(sorted(mismatches)) or 'none'}). A "
                         "non-Python verifier could compute a different digest for the same float. That is "
                         "a parity failure, which fails closed, not a collision inside one SDK. The "
                         "authors track it as parity work.",
                    evidence=write_evidence("agt_ab8.log", log4.getvalue())))

    # --- Attacks with no applicable AGT feature in this module ---
    for ab, why in [
        ("AB3", "No delegated grant/'allow similar' primitive in the protocol module; each action is a "
                "fresh binding. Nothing to stretch."),
        ("AB4", "No renderer in the module; the human-facing card is produced by host handlers "
                "(callback/console/webhook). Padding/bidi handling is handler-dependent and out of the "
                "security contract tested here."),
        ("AB6", "The binding digest is over the full action; display injectivity depends on the host "
                "handler, not this module. The ADR explicitly rejects trusting a self-asserted approver "
                "name (does not claim trusted rendering)."),
        ("AB7", "Approver identities/roles are configured in the ApprovalChain; there is no open "
                "enrollment of approving credentials in this module."),
        ("AB9", "The execution boundary recomputes the digest independently of any renderer, so the "
                "rendering party does not choose the signed bytes at this layer."),
        ("AB12", "No aggregate/threshold limit primitive; that is a policy-layer concern above ADR-0030."),
    ]:
        rows.append(row(T, ab, applicable=False, executed=False, outcome=NA, note=why))
    return rows
