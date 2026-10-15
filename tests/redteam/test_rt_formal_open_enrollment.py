"""Formal-lens red team: the Tamarin models only let the honest device
register a key for U (Register_Device); the agent can never bind a key it
knows to a principal. Adding one rule that lets the agent register a key for a
not-yet-enrolled user falsifies L1, L1_sig, L3, L4 and L5 (see
docs/critique/formal.md, experiment X3). With the DEFAULT Config (rp_id
"localhost", no enrollment_token, dev_mode False) the code permits exactly
that: anything that can reach the gateway -- including the agent, which runs on
the same localhost in the evaluated setup -- can enroll the first passkey for
any unused user id, receive the authenticator cookie, and approve its own
challenges for that principal.

Secure behaviour asserted: without an enrollment token (and without an explicit
dev_mode opt-in) first enrollment is refused.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from asu.app import create_app
from asu.config import Config

ORIGIN = "http://localhost:8000"


def test_default_config_refuses_unauthenticated_first_enrollment(tmp_path):
    cfg = Config(db_path=str(tmp_path / "asu.db"), ledger_path=str(tmp_path / "ledger.jsonl"),
                 token_key_path=str(tmp_path / "k.pem"), workspace_root=str(tmp_path))
    assert cfg.dev_mode is False
    client = TestClient(create_app(cfg), base_url=ORIGIN)
    r = client.post("/v1/authn/register/options", json={"user_id": "agent-chosen-principal"},
                    headers={"Origin": ORIGIN})
    assert r.status_code == 403, r.text
