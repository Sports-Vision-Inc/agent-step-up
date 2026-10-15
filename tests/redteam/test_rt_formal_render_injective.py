"""Formal-lens red team: every Tamarin model renders the card as the effect
term itself (ToDevice(U, aid, n, e) -> HumanApproves(U, aid, e)), i.e. it
assumes render_card is injective: two different descriptors never produce the
same card. L1 ("the human approved a card showing e") only transfers to the
code if that holds. asu.descriptor.display() renders JSON scalars and strings
identically (0 vs "0", true vs "true", null vs "null"), so two descriptors with
different digests -- and different executor semantics (a Python executor
treats "0" as truthy) -- produce byte-identical cards.

Secure behaviour asserted: descriptors with different digests yield different
cards (trusted fields), i.e. the human can distinguish what will execute.
"""
from __future__ import annotations

from asu import descriptor as D

CTX = {"principal": "alice", "session_id": "ses_1", "agent_id": "agent-1", "origin": "user_turn",
       "issued_at": 1700000000, "expires_at": 1700000300, "effect_class": "delete",
       "workspace_root": "/tmp", "resolve_symlinks": False}


def _visible(card):
    return (card["title"], card["effect_class"], tuple(card["risk_lines"]),
            tuple((f["label"], f["value"]) for f in card["fields"]))


def test_distinct_effects_render_distinct_cards():
    a = D.canonicalize("delete_file", {"path": "/tmp/w/report.txt", "force": 0}, CTX)
    b = D.canonicalize("delete_file", {"path": "/tmp/w/report.txt", "force": "0"}, CTX)
    assert D.digest(a) != D.digest(b)          # different effects to the executor
    assert _visible(D.render_card(a)) != _visible(D.render_card(b))


def test_bool_vs_string_render_distinct_cards():
    a = D.canonicalize("delete_file", {"path": "/tmp/w/x", "dry_run": True}, CTX)
    b = D.canonicalize("delete_file", {"path": "/tmp/w/x", "dry_run": "true"}, CTX)
    assert D.digest(a) != D.digest(b)
    assert _visible(D.render_card(a)) != _visible(D.render_card(b))
