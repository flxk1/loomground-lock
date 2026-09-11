# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Tier C with nothing wired, and Tier C that cannot run, fail closed.

The measured baseline is the source host at bac579b with its documented default
backend (``AGENT_TOOL_LOCK_LLM_BACKEND`` unset → ``mock``). An unwired package
must reach the same verdict on each string below; a Tier C that cannot run must
refuse rather than allow.
"""
from __future__ import annotations

import pytest

from loomground_lock import host_deps, tier_c_default
from loomground_lock.core import Finding, lock_text

# (text, action the source reaches with its default backend, Tier-C severity)
HOST_DEFAULT_BASELINE = [
    ("patient recovering well", "refuse", "high"),
    ("Maria Schmidt owes a loan", "refuse", "high"),
    ("the salary is high", "refuse", "high"),
    ("chemo starts Monday", "refuse", "high"),
    ("Maria Schmidt called", "minimise", "medium"),
]


@pytest.mark.parametrize("text,action,severity", HOST_DEFAULT_BASELINE)
def test_unwired_reaches_the_host_default_verdict(text, action, severity):
    assert host_deps.tier_c_check_semantic is None
    assert host_deps.wired() == {name: False for name in host_deps.HOOKS}
    decision = lock_text(text)
    assert decision.action == action
    assert [(f.tier, f.severity) for f in decision.findings] == [("C", severity)]


def test_unwired_still_allows_text_with_nothing_to_find():
    assert lock_text("the build is green").action == "allow"
    assert lock_text("").action == "allow"


def test_requires_predicate_is_consulted_with_no_semantic_hook():
    """(i) A host that promises a real backend and wires no semantic hook has a
    Tier C that cannot run — every text refuses, clean text included."""
    host_deps.register(tier_c_requires_real_backend=lambda: True)
    assert host_deps.tier_c_check_semantic is None

    clean = lock_text("the build is green")
    assert clean.action == "refuse"
    assert [f.type for f in clean.findings] == ["tier_c_unavailable"]
    assert "no tier_c_check_semantic hook is wired" in clean.findings[0].detail

    flagged = lock_text("patient recovering well")
    assert flagged.action == "refuse"
    assert {f.type for f in flagged.findings} == {"pii_in_argument", "tier_c_unavailable"}


def test_requires_predicate_that_raises_counts_as_a_promise():
    host_deps.register(tier_c_requires_real_backend=lambda: (_ for _ in ()).throw(OSError()))
    assert lock_text("the build is green").action == "refuse"


def test_raising_wiring_provider_surfaces_and_fails_closed():
    """(ii) A provider that raises leaves what it wired unknown. ``ensure_wired``
    stays total, the failure is recorded, and Tier C is unavailable."""
    host_deps.set_wiring_provider(
        lambda: (_ for _ in ()).throw(RuntimeError("/models/secret.gguf")))
    host_deps.ensure_wired()  # total — raises nothing

    assert host_deps.wiring_error() == "RuntimeError"

    clean = lock_text("the build is green")
    assert clean.action == "refuse"
    assert [f.type for f in clean.findings] == ["tier_c_unavailable"]
    detail = clean.findings[0].detail
    assert "RuntimeError" in detail and "/models/secret.gguf" not in detail

    assert lock_text("patient recovering well").action == "refuse"


def test_recorded_wiring_failure_is_reset_by_rewiring():
    host_deps.set_wiring_provider(lambda: (_ for _ in ()).throw(ValueError()))
    host_deps.ensure_wired()
    assert host_deps.wiring_error() == "ValueError"
    host_deps.set_wiring_provider(lambda: None)
    assert host_deps.wiring_error() is None
    assert lock_text("the build is green").action == "allow"
    host_deps.set_wiring_provider(lambda: (_ for _ in ()).throw(ValueError()))
    host_deps.ensure_wired()
    host_deps.clear()
    assert host_deps.wiring_error() is None


def test_a_working_hook_replaces_the_default_tier():
    host_deps.register(tier_c_check_semantic=lambda text, context="": [])
    assert lock_text("chemo starts Monday").action == "allow"


def test_a_failed_hook_falls_back_to_the_default_tier():
    """The default tier is the floor: a hook that crashes or hands back an
    unusable result leaves detection at least where an unwired package had it."""
    for hook in (lambda text, context="": (_ for _ in ()).throw(RuntimeError()),
                 lambda text, context="": "not a list"):
        host_deps.clear()
        host_deps.register(tier_c_check_semantic=hook,
                           tier_c_requires_real_backend=lambda: False)
        assert lock_text("chemo starts Monday").action == "refuse"
        assert lock_text("Maria Schmidt called").action == "minimise"
        assert lock_text("the build is green").action == "allow"

        host_deps.register(tier_c_requires_real_backend=lambda: True)
        decision = lock_text("the build is green")
        assert decision.action == "refuse"
        assert [f.type for f in decision.findings] == ["tier_c_unavailable"]
        assert "RuntimeError" in decision.findings[0].detail or \
               "TypeError" in decision.findings[0].detail


def test_context_terms_and_the_default_tier_compose():
    decision = lock_text("the project atlas plan", context="- project atlas")
    assert decision.action == "refuse"
    assert any("confidential" in f.detail for f in decision.findings)


def test_the_refusal_reason_names_a_detector_the_package_has():
    decision = lock_text("chemo starts Monday")
    assert decision.reason == (
        "high-severity finding (PII regex match, confidential term, or special-category)")
    assert tier_c_default.classify("chemo starts Monday")[0] == "health"


def test_default_tier_classification():
    assert tier_c_default.classify("") is None
    assert tier_c_default.classify("   ") is None
    assert tier_c_default.classify("the build is green") is None
    assert tier_c_default.classify("patient recovering well")[:2] == ("health", "high")
    assert tier_c_default.classify("the salary is high")[:2] == ("financial", "high")
    assert tier_c_default.classify("Maria Schmidt called")[:2] == ("name", "medium")
    # health takes precedence over a name pair in the same text
    assert tier_c_default.classify("Maria Schmidt starts chemo")[0] == "health"
    assert tier_c_default.tier_c_default_check("the build is green") == []
    finding = tier_c_default.tier_c_default_check("chemo starts Monday")[0]
    assert isinstance(finding, Finding)
    assert (finding.tier, finding.type, finding.severity) == ("C", "pii_in_argument", "high")
