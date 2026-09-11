# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""The six-level dial: strictest wins."""
from __future__ import annotations

from loomground_lock import PRIVACY_CLASS_DEFAULTS, OversightDecision, OversightLevel, effective_level
from loomground_lock.oversight import (
    MODE_TO_OVERSIGHT,
    asks_user_per_finding,
    asks_user_per_plan,
    notifies_user_post_execution,
    waits_for_review_after_execution,
)


def test_effective_level_is_the_strictest():
    assert effective_level(user_default=OversightLevel.AUTONOMOUS) == OversightLevel.AUTONOMOUS
    assert effective_level(user_default=OversightLevel.AUTONOMOUS, op_floor=OversightLevel.APPROVE) == OversightLevel.APPROVE
    assert effective_level(user_default=OversightLevel.NOTIFY, privacy_class="regulated") == OversightLevel.SUPERVISED
    assert effective_level(user_default=OversightLevel.MANUAL, op_floor=OversightLevel.NOTIFY, privacy_class="public") == OversightLevel.MANUAL
    assert effective_level(user_default=OversightLevel.REVIEW, privacy_class="unknown") == OversightLevel.REVIEW


def test_labels_descriptions_and_defaults():
    assert [l.label for l in OversightLevel] == ["autonomous", "notify", "review", "approve", "supervised", "manual"]
    assert all(l.description for l in OversightLevel)
    assert PRIVACY_CLASS_DEFAULTS["sensitive"] == OversightLevel.APPROVE
    assert MODE_TO_OVERSIGHT["strict"] == OversightLevel.SUPERVISED


def test_interaction_predicates():
    assert {l for l in OversightLevel if asks_user_per_finding(l)} == {OversightLevel.SUPERVISED, OversightLevel.MANUAL}
    assert {l for l in OversightLevel if asks_user_per_plan(l)} == {OversightLevel.APPROVE, OversightLevel.SUPERVISED, OversightLevel.MANUAL}
    assert [l for l in OversightLevel if waits_for_review_after_execution(l)] == [OversightLevel.REVIEW]
    assert [l for l in OversightLevel if notifies_user_post_execution(l)] == [OversightLevel.NOTIFY]


def test_oversight_decision_points_at_a_content_derived_finding_id():
    from loomground_lock.core import Finding
    f = Finding(tier="B", type="pii_in_argument", severity="high", field=None, detail="regex matched pattern: email")
    g = Finding(tier="B", type="pii_in_argument", severity="high", field=None, detail="regex matched pattern: email")
    assert f.finding_id == g.finding_id and len(f.finding_id) == 16
    d = OversightDecision(finding_id=f.finding_id, user_action="accept")
    assert d.finding_id == g.finding_id and d.reason == "" and d.elapsed_ms == 0
