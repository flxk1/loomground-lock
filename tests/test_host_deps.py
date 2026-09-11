# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""The port declaration: hooks are module attributes; wiring is register() or a
provider; an unwired Tier C degrades without allowing what it refused."""
from __future__ import annotations

import pytest

from loomground_lock import host_deps
from loomground_lock.core import Finding, lock_text, tier_b_scan_text, tier_c_semantic_check


def test_hooks_are_declared_module_attributes():
    for name in ("tier_c_check_semantic", "tier_c_requires_real_backend", "models_for_role",
                 "llm_classify", "key_root_dir", "govern_egress", "verify_agent_identity"):
        assert name in host_deps.HOOKS
        assert getattr(host_deps, name) is None
    assert callable(host_deps.set_wiring_provider) and callable(host_deps.register)


def test_register_validates_names_and_callables():
    with pytest.raises(ValueError, match="unknown host hooks"):
        host_deps.register(no_such_hook=lambda: None)
    with pytest.raises(TypeError):
        host_deps.register(llm_classify="not callable")
    host_deps.register(llm_classify=lambda **kw: {"ok": True, "category": "pii_no"})
    assert host_deps.wired()["llm_classify"] is True
    host_deps.register(llm_classify=None)
    assert host_deps.wired()["llm_classify"] is False


def test_wiring_provider_runs_once_on_first_use():
    calls = []

    def provider():
        calls.append(1)
        host_deps.register(tier_c_requires_real_backend=lambda: False)

    host_deps.set_wiring_provider(provider)
    host_deps.ensure_wired(); host_deps.ensure_wired()
    assert calls == [1]
    assert host_deps.tier_c_requires_real_backend() is False
    host_deps.set_wiring_provider(lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    host_deps.ensure_wired()  # a failing provider degrades, never raises


def test_unwired_tier_c_still_refuses_confidential_terms_and_allows_clean():
    assert host_deps.tier_c_check_semantic is None
    refused = lock_text("the project atlas plan", context="- project atlas")
    assert refused.action == "refuse"
    assert any(f.tier == "C" and f.severity == "high" for f in refused.findings)
    assert lock_text("the build is green", context="- project atlas").action == "allow"
    assert lock_text("the build is green").action == "allow"


def test_registered_semantic_hook_is_invoked_and_composes():
    seen = []

    def semantic(text, context=""):
        seen.append((text, context))
        return [Finding(tier="C", type="pii_in_argument", severity="high", field=None,
                        detail="semantic classifier flagged health: keyword")]

    host_deps.register(tier_c_check_semantic=semantic)
    decision = lock_text("patient recovering well", context="- x")
    assert seen == [("patient recovering well", "- x")]
    assert decision.action == "refuse"
    assert any("health" in f.detail for f in decision.findings)


def test_crashing_hook_fails_closed_only_when_a_real_backend_is_required():
    def boom(text, context=""):
        raise RuntimeError("/model/path leaked?")

    host_deps.register(tier_c_check_semantic=boom, tier_c_requires_real_backend=lambda: False)
    assert lock_text("clean words").action == "allow"

    host_deps.register(tier_c_requires_real_backend=lambda: True)
    decision = lock_text("clean words")
    assert decision.action == "refuse"
    unavailable = [f for f in decision.findings if f.type == "tier_c_unavailable"]
    assert unavailable and "RuntimeError" in unavailable[0].detail
    assert "/model/path" not in unavailable[0].detail

    host_deps.register(tier_c_requires_real_backend=lambda: (_ for _ in ()).throw(OSError()))
    assert lock_text("clean words").action == "refuse"


def test_non_list_hook_result_is_treated_as_a_crash():
    host_deps.register(tier_c_check_semantic=lambda text, context="": "yes",
                       tier_c_requires_real_backend=lambda: True)
    assert lock_text("clean words").action == "refuse"


def test_disable_lock_remediation_payload_comes_from_the_host():
    default = tier_b_scan_text("a\x40b.co")[0].remediation_actions[2].payload
    assert default == {"acknowledgement_required": True, "disclaimer_required": True}
    host_deps.register(disable_lock_remediation=lambda: {"cli": "host policy disable-lock", "disclaimer_url": "https://host.example/d"})
    hosted = tier_b_scan_text("a\x40b.co")[0].remediation_actions[2].payload
    assert hosted["cli"] == "host policy disable-lock"
    host_deps.register(disable_lock_remediation=lambda: (_ for _ in ()).throw(ValueError()))
    assert tier_b_scan_text("a\x40b.co")[0].remediation_actions[2].payload == default


def test_ensemble_check_uses_llm_classify_hook():
    assert tier_c_semantic_check("some named person") is None
    host_deps.register(llm_classify=lambda **kw: {"ok": True, "category": "pii_yes"},
                       models_for_role=lambda role: ("m1", "m2"))
    res = tier_c_semantic_check("some named person")
    assert res.label == "pii_yes" and set(res.per_model) == {"m1", "m2"}
    host_deps.register(llm_classify=lambda **kw: {"ok": True, "category": "pii_yes" if kw["model"] == "m1" else "pii_no"})
    assert tier_c_semantic_check("x", models=("m1", "m2")).label == "insufficient"
    host_deps.register(llm_classify=lambda **kw: {"ok": False})
    assert tier_c_semantic_check("x", models=("m1",)) is None
    assert tier_c_semantic_check("   ").label == "pii_no"
