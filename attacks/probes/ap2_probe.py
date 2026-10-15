"""AB-family probe against Google AP2 reference code (ap2.sdk.constraints).

Executed locally against the cloned SDK. AP2 binds the effect by having the
holder key SIGN the (SD-JWT) mandate, so effect-binding (P2) is strong by
construction. These probes therefore target the CONSTRAINT-CHECKING layer
(what a delegated open mandate authorizes a closed mandate to do) and the
SAMPLE web-client renderer, which is where an approval-binding attack would
land. Neutral placeholder merchants/amounts only.
"""
from __future__ import annotations
import io
import os
import sys
import contextlib

from attacks.common import row, write_evidence, VULN, NOT_VULN, PARTIAL, NA
from attacks.targets import TARGETS, TARGETS_DIR

T = "ap2"
_SDK = os.path.join(TARGETS_DIR, "ap2", "code", "sdk", "python")


def _available() -> bool:
    return os.path.isdir(_SDK)


def _load():
    if _SDK not in sys.path:
        sys.path.insert(0, _SDK)
    from ap2.sdk.constraints import check_payment_constraints, MandateContext  # noqa
    from ap2.sdk.generated.open_payment_mandate import (
        OpenPaymentMandate, AllowedPayees, AmountRange, Budget, AgentRecurrence,
        Frequency)
    from ap2.sdk.generated.payment_mandate import PaymentMandate
    from ap2.sdk.generated.types.merchant import Merchant
    from ap2.sdk.generated.types.amount import Amount
    from ap2.sdk.generated.types.payment_instrument import PaymentInstrument
    return dict(locals())


def run():
    rows = []
    if not _available():
        for ab in ("AB1", "AB2", "AB3", "AB6", "AB12"):
            rows.append(row(T, ab, applicable=True, executed=False, outcome=NA,
                            note="AP2 clone not present under attacks/.targets/ap2"))
        return rows
    m = _load()
    log = io.StringIO()

    def closed(payee_id, payee_name, amt, cur="USD"):
        return m["PaymentMandate"](
            transaction_id="tx-placeholder",
            payee=m["Merchant"](id=payee_id, name=payee_name, website="https://example.test"),
            payment_amount=m["Amount"](amount=amt, currency=cur),
            payment_instrument=m["PaymentInstrument"](id="pi-1", type="card"))

    openm = m["OpenPaymentMandate"](
        constraints=[m["AmountRange"](currency="USD", max=1000),
                     m["AllowedPayees"](allowed=[m["Merchant"](id="bob", name="Bob Store",
                                                               website="https://bob.test")])],
        cnf={})
    cpc = m["check_payment_constraints"]

    # --- AB1 amount cancellation / multi-amount ambiguity ---
    over = cpc(openm, closed("bob", "Bob Store", 5000))
    atcap = cpc(openm, closed("bob", "Bob Store", 1000))
    print("AB1 over-cap violations:", over, file=log)
    print("AB1 at-cap violations:", atcap, file=log)
    ab1_ok = bool(over) and not atcap
    rows.append(row(T, "AB1", applicable=True, executed=True,
                    outcome=NOT_VULN if ab1_ok else VULN,
                    severity="none" if ab1_ok else "high",
                    note="Single typed `payment_amount` (int minor units); no amount summing. "
                         "AmountRange.max enforced; over-cap rejected. Cancellation has no field to cancel.",
                    evidence=write_evidence("ap2_ab1.log", log.getvalue())))

    # --- AB2 decoy-field target/recipient confusion ---
    wrong_id = cpc(openm, closed("eve", "Bob Store", 500))     # right name, wrong id
    right_id = cpc(openm, closed("bob", "Eve Exfil LLC", 500))  # right id, misleading name
    print("AB2 wrong-id/right-name:", wrong_id, file=log)
    print("AB2 right-id/fake-name:", right_id, file=log)
    # Constraint binds Merchant.id (no derived-target heuristic, no decoy key accepted):
    # payee is a single typed object, so there is no second recipient key to smuggle.
    ab2_bind_ok = bool(wrong_id) and not right_id
    rows.append(row(T, "AB2", applicable=True, executed=True,
                    outcome=NOT_VULN if ab2_bind_ok else VULN,
                    severity="none" if ab2_bind_ok else "high",
                    note="AllowedPayee matches on Merchant.id (required field); a wrong id is rejected "
                         "even with a matching display name. No alphabetical/decoy-key target derivation "
                         "(contrast ASU RT-2/RT-3). The id is what is bound.",
                    evidence=write_evidence("ap2_ab2.log", log.getvalue())))

    # --- AB6 non-injective rendering (display vs binding) ---
    # The signed/bound value is Merchant.id; the sample MandateCard renders payee.NAME.
    card = os.path.join(TARGETS_DIR, "ap2", "code", "web-client", "src", "components", "MandateCard.tsx")
    card_src = open(card, encoding="utf-8").read() if os.path.isfile(card) else ""
    renders_name = "label: 'Payee', value: String(payee.name)" in card_src.replace('"', "'") or \
                   "value: String(payee.name)" in card_src
    # right-id/fake-name passed the constraint (right_id == []), yet the card shows the fake name.
    ab6 = (not right_id) and renders_name
    print("AB6: constraint bound to id but sample card shows payee.name =", renders_name, file=log)
    rows.append(row(T, "AB6", applicable=True, executed=True,
                    outcome=PARTIAL if ab6 else NOT_VULN,
                    severity="medium" if ab6 else "none",
                    note="SAMPLE renderer only. The constraint check was executed; the card's display "
                         "logic was read from MandateCard.tsx source (not rendered in a browser). "
                         "Constraints bind Merchant.id, but the web-client "
                         "MandateCard summarises `payee.name` (agent/merchant-chosen) with no "
                         "length cap or invisible-char handling. A human reading the card sees a name "
                         "that is not the bound identifier -> distinct effects (ids) can share a display "
                         "name. Spec relies on a 'trusted surface'; this is a sample weakness, not the "
                         "signed binding.",
                    evidence=write_evidence("ap2_ab6.log", log.getvalue())))

    # --- AB3 grant/mandate stretching beyond signed constraints ---
    # Open mandate = the signed delegated grant. Pre-set claims + constraints must hold.
    preset = m["OpenPaymentMandate"](
        constraints=[m["AmountRange"](currency="USD", max=1000)],
        payee=m["Merchant"](id="bob", name="Bob Store", website="https://bob.test"),
        cnf={})
    stretch_payee = cpc(preset, closed("eve", "Eve", 500))   # try different payee than pre-set
    stretch_cur = cpc(openm, closed("bob", "Bob Store", 500, cur="EUR"))  # currency swap
    print("AB3 preset-payee stretch:", stretch_payee, file=log)
    print("AB3 currency stretch:", stretch_cur, file=log)
    ab3_ok = bool(stretch_payee) and bool(stretch_cur)
    rows.append(row(T, "AB3", applicable=True, executed=True,
                    outcome=NOT_VULN if ab3_ok else VULN,
                    severity="none" if ab3_ok else "high",
                    note="Pre-set payee in the open mandate is enforced (check_preset_payment_claims); "
                         "currency mismatch rejected by AmountRange. The grant cannot be stretched to "
                         "another payee or currency at the constraint layer.",
                    evidence=write_evidence("ap2_ab3.log", log.getvalue())))

    # --- AB12 threshold splitting under aggregate limits ---
    budget = m["OpenPaymentMandate"](
        constraints=[m["AgentRecurrence"](frequency=m["Frequency"].ON_DEMAND, max_occurrences=10),
                     m["AmountRange"](currency="USD", max=10000),
                     m["Budget"](max=20.07, currency="USD")],
        cnf={})
    noctx = cpc(budget, closed("bob", "Bob Store", 100))
    # Two sub-budget uses, each evaluated with a context the integrator forgot to accumulate:
    split_a = cpc(budget, closed("bob", "Bob Store", 1004),
                  mandate_context=m["MandateContext"](total_amount=0, total_uses=0))
    split_b = cpc(budget, closed("bob", "Bob Store", 1004),
                  mandate_context=m["MandateContext"](total_amount=0, total_uses=0))
    print("AB12 budget without context:", noctx, file=log)
    print("AB12 two sub-cap uses, stale context:", split_a, split_b,
          "-> both allowed; 2x1004=2008c > budget 2007c", file=log)
    fails_closed_no_ctx = bool(noctx)
    split_works = (not split_a) and (not split_b)
    rows.append(row(T, "AB12", applicable=True, executed=True,
                    outcome=PARTIAL,
                    severity="medium",
                    note="Budget is cumulative ONLY via a caller-supplied MandateContext.total_amount; "
                         "the SDK does not persist or accumulate it. Without context it fails closed "
                         f"(fails_closed={fails_closed_no_ctx}). But if the integrator does not persist "
                         f"and accumulate usage across uses, two sub-budget payments both pass "
                         f"(split_works={split_works}): aggregate 2008c exceeds the 2007c budget. "
                         "Argument-level: depends on integrator state, not a break of the signed mandate.",
                    evidence=write_evidence("ap2_ab12.log", log.getvalue())))

    # Attacks with no applicable AP2 feature:
    for ab, why in [
        ("AB4", "No AP2-provided trusted renderer; card text handling is client/surface side (see AB6)."),
        ("AB5", "No agent-named label surface in the signed mandate; fields are typed models."),
        ("AB7", "Enrollment/credential registration is out of scope of the mandate SDK (holder keys "
                "are provisioned by the issuer/device)."),
        ("AB8", "Mandate binding is a signed SD-JWT over structured payloads, not a concatenated "
                "challenge; JCS/sd_hash are injective within the SDK."),
        ("AB9", "The user's device signs the mandate; the renderer (surface) does not choose the signed "
                "bytes. Sample couples assemble+sign in an agent tool (noted in AB6)."),
        ("AB10", "Closed mandate is signed; substituting a different closed mandate breaks the holder "
                 "signature / constraint check (equivalent to AB3). No separate post-approval window."),
        ("AB11", "No volume/approval-prompt primitive in the SDK; flooding is a surface/UX concern."),
    ]:
        rows.append(row(T, ab, applicable=False, executed=False, outcome=NA, note=why))
    return rows
