# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Tier C's built-in default semantic tier — deterministic, model-free.

The package ships its own default so Tier C runs with nothing wired. It is the
in-package equivalent of the source host's default backend (spec ``mock``, the
documented default of ``AGENT_TOOL_LOCK_LLM_BACKEND``): the same special-category
keyword sets and capitalised-pair heuristic, the same finding types, severities
and confidences. An unwired package therefore refuses and minimises what the
host refused and minimised out of the box.

A host that wires ``host_deps.tier_c_check_semantic`` replaces this default, the
way a real backend spec replaces the host's default one. Where the wired hook is
absent, crashes, or hands back something unusable, this default runs again as the
floor — see ``core._tier_c``.
"""
from __future__ import annotations

import re

from .core import Finding

_HEALTH = re.compile(
    r"\b(chemo|diagnosis|surgery|prescribed|illness|patient|hospitalized|hospital(?:ised|isation)?|"
    r"medication|condition|cancer|diabetes|depression|anxiety|therapy)\b",
    re.IGNORECASE,
)
_FINANCIAL = re.compile(
    r"\b(salary|wage|debt|mortgage|bankruptcy|insolvent|loan|owes?)\b",
    re.IGNORECASE,
)
_NAME = re.compile(r"\b[A-Z][a-z]+ [A-Z][a-z]+\b")

# kind -> (severity, confidence, reason). health/financial are Art. 9-shaped
# special categories and block; a bare name pair is medium and minimises.
_KINDS: tuple[tuple[str, re.Pattern[str], str, float, str], ...] = (
    ("health", _HEALTH, "high", 0.85, "matched health keyword"),
    ("financial", _FINANCIAL, "high", 0.80, "matched financial keyword"),
    ("name", _NAME, "medium", 0.75, "matched capitalised-pair name pattern"),
)


def classify(text: str) -> tuple[str, str, float, str] | None:
    """``(kind, severity, confidence, reason)`` for the first kind ``text`` trips,
    else ``None``. Precedence is health, financial, name."""
    if not text or not text.strip():
        return None
    for kind, pattern, severity, confidence, reason in _KINDS:
        if pattern.search(text):
            return kind, severity, confidence, reason
    return None


def tier_c_default_check(text: str, context: str = "") -> list[Finding]:
    """The default semantic tier over ``text``. ``context`` is accepted for hook
    signature parity; confidential terms are handled by
    ``core.tier_c_context_terms_check``, which runs alongside this."""
    hit = classify(text)
    if hit is None:
        return []
    kind, severity, confidence, reason = hit
    return [Finding(
        tier="C",
        type="pii_in_argument",
        severity=severity,
        field=None,
        detail=f"semantic classifier flagged {kind}: built-in default tier {reason}",
        confidence=confidence,
    )]
