# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Tier M moderation: deterministic rules always enforce; declared categories
require a backend and fail closed without one; findings never carry text."""
from __future__ import annotations

import pytest

from loomground_lock import tier_m as TM
from loomground_lock.core import lock_text


@pytest.mark.parametrize("rules", [None, {}])
def test_no_rules_is_a_noop(rules):
    assert TM.tier_m_check_moderation("anything at all", rules=rules) == []
    assert lock_text("perfectly benign words", moderation_rules=rules).action == "allow"


def test_requires_real_backend_only_for_categories():
    assert TM.tier_m_requires_real_backend({"banned_terms": ["x"]}) is False
    assert TM.tier_m_requires_real_backend({"categories": ["hate"]}) is True
    assert TM.tier_m_requires_real_backend(None) is False


def test_banned_term_match_refuses():
    rules = {"banned_terms": ["forbidden-token"]}
    findings = TM.tier_m_check_moderation("see the forbidden-token here", rules=rules)
    assert len(findings) == 1 and findings[0].severity == "high"
    assert findings[0].type == "moderation_match" and findings[0].tier == "M"
    assert lock_text("see the forbidden-token here", moderation_rules=rules).action == "refuse"


def test_banned_term_is_case_insensitive():
    assert TM.tier_m_check_moderation("a secretword slipped in", rules={"banned_terms": ["SECRETWORD"]})


def test_clean_text_with_rules_is_allowed():
    rules = {"banned_terms": ["nope"]}
    assert TM.tier_m_check_moderation("nothing matches here", rules=rules) == []
    assert lock_text("nothing matches here", moderation_rules=rules).action == "allow"


def test_banned_pattern_match_refuses():
    rules = {"banned_patterns": [r"\bproject[- ]nimbus\b"]}
    assert TM.tier_m_check_moderation("re: project-nimbus rollout", rules=rules)
    assert lock_text("re: project-nimbus rollout", moderation_rules=rules).action == "refuse"


@pytest.mark.parametrize("rules", [
    {"banned_terms": "not-a-list"},
    {"banned_patterns": {"oops": 1}},
])
def test_malformed_rule_shape_fails_closed(rules):
    findings = TM.tier_m_check_moderation("benign", rules=rules)
    assert any(f.type == "tier_m_unavailable" for f in findings)
    assert lock_text("benign", moderation_rules=rules).action == "refuse"


def test_tier_m_composes_with_tier_b_strictest_wins():
    rules = {"banned_terms": ["contraband"]}
    assert lock_text("ship the contraband", moderation_rules=rules).action == "refuse"
    assert lock_text("mail ceo\x40corp.example about the contraband", moderation_rules=rules).action == "refuse"


def test_invalid_regex_fails_closed():
    findings = TM.tier_m_check_moderation("benign", rules={"banned_patterns": ["("]})
    assert len(findings) == 1 and findings[0].type == "tier_m_unavailable"
    assert findings[0].severity == "high"
    assert lock_text("benign", moderation_rules={"banned_patterns": ["("]}).action == "refuse"


class _Flags:
    def __init__(self, flagged): self._f = flagged
    def is_available(self): return True
    def classify(self, text, categories): return {"flagged": self._f}


class _Unavail:
    def is_available(self): return False
    def classify(self, text, categories): return {"flagged": []}


class _Boom:
    def is_available(self): return True
    def classify(self, text, categories): raise RuntimeError("classifier crashed")


def test_categories_with_no_backend_fail_closed():
    rules = {"categories": ["hate"]}
    assert any(f.type == "tier_m_unavailable" for f in TM.tier_m_check_moderation("some text", rules=rules))
    assert lock_text("some text", moderation_rules=rules).action == "refuse"


def test_categories_backend_unavailable_fails_closed(monkeypatch):
    monkeypatch.setattr(TM, "make_moderation_backend", lambda spec: _Unavail())
    findings = TM.tier_m_check_moderation("text", rules={"categories": ["hate"], "backend": "classifier:v2"})
    assert [f.type for f in findings] == ["tier_m_unavailable"]


def test_categories_backend_crash_fails_closed(monkeypatch):
    monkeypatch.setattr(TM, "make_moderation_backend", lambda spec: _Boom())
    findings = TM.tier_m_check_moderation("text", rules={"categories": ["hate"], "backend": "classifier:v2"})
    assert [f.type for f in findings] == ["tier_m_unavailable"]


def test_categories_malformed_result_fails_closed(monkeypatch):
    class _Malformed:
        def is_available(self): return True
        def classify(self, text, categories): return {"oops": True}
    monkeypatch.setattr(TM, "make_moderation_backend", lambda spec: _Malformed())
    findings = TM.tier_m_check_moderation("text", rules={"categories": ["hate"], "backend": "classifier:v2"})
    assert [f.type for f in findings] == ["tier_m_unavailable"]


def test_categories_backend_flags_category_refuses(monkeypatch):
    monkeypatch.setattr(TM, "make_moderation_backend", lambda spec: _Flags(["hate"]))
    rules = {"categories": ["hate", "violence"], "backend": "classifier:v2"}
    findings = TM.tier_m_check_moderation("text", rules=rules)
    assert len(findings) == 1 and findings[0].type == "moderation_match"
    assert lock_text("text", moderation_rules=rules).action == "refuse"


def test_categories_backend_clean_allows(monkeypatch):
    monkeypatch.setattr(TM, "make_moderation_backend", lambda spec: _Flags([]))
    rules = {"categories": ["hate"], "backend": "classifier:v2"}
    assert TM.tier_m_check_moderation("text", rules=rules) == []
    assert lock_text("text", moderation_rules=rules).action == "allow"


def test_backend_flagging_unwanted_category_is_ignored(monkeypatch):
    monkeypatch.setattr(TM, "make_moderation_backend", lambda spec: _Flags(["spam"]))
    assert TM.tier_m_check_moderation("text", rules={"categories": ["hate"], "backend": "classifier:v2"}) == []


def test_finding_detail_never_leaks_scanned_text():
    secret = "alice\x40example.com plans for project-nimbus"
    findings = TM.tier_m_check_moderation(f"memo: {secret}", rules={"banned_terms": ["project-nimbus"]})
    assert findings and all(secret not in f.detail and "alice\x40example.com" not in f.detail for f in findings)


def test_classify_exception_detail_carries_no_message(monkeypatch):
    secret = "/secret/model.bin and ceo\x40corp.example"

    class _Leaky:
        def is_available(self): return True
        def classify(self, text, categories): raise RuntimeError(secret)
    monkeypatch.setattr(TM, "make_moderation_backend", lambda spec: _Leaky())
    findings = TM.tier_m_check_moderation("hello", rules={"categories": ["x"], "backend": "c:1"})
    assert findings and secret not in findings[0].detail
    assert "RuntimeError" in findings[0].detail


def test_backend_spec_never_appears_in_finding_detail():
    spec = "https://mod.example/v1?key=SUPERSECRET"
    findings = TM.tier_m_check_moderation("text", rules={"categories": ["x"], "backend": spec})
    assert findings and all("SUPERSECRET" not in f.detail and spec not in f.detail for f in findings)
