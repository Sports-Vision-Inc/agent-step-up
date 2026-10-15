"""ASU evaluation harness (SPEC section 11).

Everything here drives the real gateway (``asu.app.create_app``) over its HTTP
API with FastAPI's in-process TestClient. Every "attack" is a tool call with
placeholder arguments that can only reach the ``mock_ledger`` executor (a local
JSON-lines file); ASR/TCR are scored from that ledger only.
"""

__all__ = ["__version__"]
__version__ = "0.1.0"
