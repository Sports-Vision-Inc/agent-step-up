"""Gateway-side latency microbenchmarks (EXP-11).

These are IN-PROCESS microbenchmarks of gateway work only. They exclude the
network, TLS, the browser WebAuthn ceremony and, above all, human reading and
deciding time. They must not be quoted as approval latency.

Measured on the machine that runs ``python -m experiments.run_all`` (recorded
in the output). All timings are wall-clock ``perf_counter_ns`` of in-process
calls; HTTP rows go through FastAPI's TestClient (ASGI in-process, no network
socket), so they include request parsing/serialisation but not network RTT.

Rows:
  canonicalize_digest      descriptor canonicalization + JCS + SHA-256
  policy_decide            risk policy decision (sqlite reads for aggregates)
  gateway_challenge        Gateway.call -> 202 (decision + approval row write)
  gateway_allow_execute    Gateway.call -> 200 for an allowed effect (mock ledger append + fsync)
  approval_verify_offline  asu.authn.verify_receipt (ES256 WebAuthn assertion)
  http_tool_call_202       POST /v1/tools/call -> 202
  http_approve_passkey     POST options + soft-authenticator sign + POST verify (user side, gateway work)
  http_execute_approved    POST /v1/tools/call {approval_id} -> 200 (re-verify receipt, consume, ledger)
"""
from __future__ import annotations

import os
import platform
import statistics
import sys
import time
from typing import Any, Callable, Dict, List

from asu import descriptor as D
from asu.policy import decide

from .harness import Trial
from .policies import flood_off_policy


def _stats(ns: List[int]) -> Dict[str, Any]:
    xs = sorted(ns)
    n = len(xs)
    us = [x / 1000.0 for x in xs]
    return {"n": n, "median_us": round(statistics.median(us), 1), "p95_us": round(us[min(n - 1, int(0.95 * n))], 1),
            "mean_us": round(statistics.fmean(us), 1), "min_us": round(us[0], 1), "max_us": round(us[-1], 1)}


def _bench(fn: Callable[[int], Any], n: int, warmup: int = 5) -> Dict[str, Any]:
    for i in range(warmup):
        fn(-1 - i)
    out = []
    for i in range(n):
        t0 = time.perf_counter_ns()
        fn(i)
        out.append(time.perf_counter_ns() - t0)
    return _stats(out)


def machine_info() -> Dict[str, Any]:
    return {"python": sys.version.split()[0], "platform": platform.platform(), "machine": platform.machine(),
            "processor": platform.processor() or None, "cpu_count": os.cpu_count()}


def run_latency(n: int = 200, tmp_root: str = None) -> Dict[str, Any]:
    res: Dict[str, Any] = {"machine": machine_info(), "n": n, "rows": {},
                           "label": "in-process microbenchmarks; exclude network/TLS/browser and human time"}
    trial = Trial("asu", flood_off_policy(), tmp_root=tmp_root)
    try:
        gw = trial.app.state.gateway
        store = trial.store
        api = trial.new_agent()
        sess = store.get_session_by_token(api.token)
        ctx = gw._ctx(sess, "send_email", "user_turn", int(time.time()))

        def canon(i: int) -> None:
            d = D.canonicalize("send_email", {"to": f"user{i % 50}@example.test", "subject": "s", "body": "b"}, ctx)
            D.digest(d)

        res["rows"]["canonicalize_digest"] = _bench(canon, n)

        desc = D.canonicalize("send_email", {"to": "boss@example.test", "subject": "s", "body": "b"}, ctx)
        res["rows"]["policy_decide"] = _bench(
            lambda i: decide(desc, gw.policy, store, sess["user_id"], int(time.time()), gw.config.workspace_root), n)

        def challenge(i: int) -> None:
            code, body = gw.call(sess, {"tool": "send_email", "origin": "user_turn",
                                        "args": {"to": f"c{i}@example.test", "subject": f"s{i}", "body": "b"}})
            assert code == 202, (code, body)

        res["rows"]["gateway_challenge"] = _bench(challenge, n)

        def allow(i: int) -> None:
            code, body = gw.call(sess, {"tool": "read_file", "origin": "user_turn", "args": {"path": "report.txt"}})
            assert code == 200, (code, body)

        res["rows"]["gateway_allow_execute"] = _bench(allow, n)

        # Fresh session for the HTTP rows (pending approvals above stay pending).
        api2 = trial.new_agent("agent-bench")
        approvals: List[str] = []

        def http_call(i: int) -> None:
            r = api2.call("send_email", {"to": f"h{i}@example.test", "subject": f"s{i}", "body": "b"})
            assert r.code == 202, r
            approvals.append(r.body["approval_id"])

        res["rows"]["http_tool_call_202"] = _bench(http_call, n)

        it = iter(list(approvals))

        def http_approve(i: int) -> None:
            ok = trial.human.approve(next(it))
            assert ok

        res["rows"]["http_approve_passkey"] = _bench(http_approve, n, warmup=0)
        approved = [a for a in approvals if store.get_approval(a)["status"] == "approved"]

        from asu.authn import verify_receipt

        pub = store.get_credentials(trial.user_id)[0]["public_key"]
        aps = [store.get_approval(a) for a in approved[: n]]
        origins = [trial.config.origin]

        def offline(i: int) -> None:
            ap = aps[i % len(aps)]
            assert verify_receipt(ap["receipt"], pub, ap["digest"], ap["id"], ap["nonce"],
                                  expected_origins=origins, expected_rp_id="localhost")

        res["rows"]["approval_verify_offline"] = _bench(offline, n)

        it2 = iter(approved)

        def http_exec(i: int) -> None:
            r = api2.execute(next(it2))
            assert r.code == 200, r

        res["rows"]["http_execute_approved"] = _bench(http_exec, len(approved), warmup=0)
    finally:
        trial.close()
    return res
