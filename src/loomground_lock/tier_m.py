# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Tier M — moderation detective beside Tier B/C in ``lock_text``.

Driven by a policy's ``moderation_rules`` (a no-op when absent):

  - ``banned_terms``    — case-insensitive substring matches (deterministic).
  - ``banned_patterns`` — regex matches (deterministic). A pattern that will
                          not compile is a rule that cannot be enforced → fail
                          closed, never skipped.
  - ``categories``      — semantic categories judged by a classifier backend.
                          Declared categories REQUIRE a backend; absent /
                          unavailable / erroring → fail closed.

Every Tier-M finding is high severity → the decision layer refuses. Findings
carry the rule index or category label and, on failure, the exception class
name — never the matched or scanned text.
"""
from __future__ import annotations

import re
from typing import Any

from .core import Finding


class ModerationBackendError(Exception):
    """A configured moderation classifier backend could not be constructed."""


def make_moderation_backend(spec: str) -> Any:
    """Hook for a classifier backend. The default always raises, so declared
    ``categories`` fail closed until a host overrides this. A backend exposes
    ``is_available() -> bool`` and ``classify(text, categories) -> {"flagged": [...]}``."""
    raise ModerationBackendError(f"no moderation backend for spec {spec!r}")


def tier_m_requires_real_backend(rules: dict | None) -> bool:
    return bool(isinstance(rules, dict) and rules.get("categories"))


def tier_m_unavailable_finding(detail: str) -> Finding:
    return Finding(
        tier="M",
        type="tier_m_unavailable",
        severity="high",
        field=None,
        detail=f"Tier-M moderation check could not run — failing closed: {detail}",
        confidence=1.0,
    )


def _match_finding(detail: str) -> Finding:
    return Finding(tier="M", type="moderation_match", severity="high",
                   field=None, detail=detail, confidence=1.0)


def tier_m_check_moderation(text: str, *, rules: dict | None) -> list[Finding]:
    """Detective moderation over ``text`` driven by ``rules``. Never raises;
    never leaks the matched text into a Finding."""
    if not text.strip() or not isinstance(rules, dict) or not rules:
        return []

    findings: list[Finding] = []
    low = text.lower()

    terms = rules.get("banned_terms")
    if terms is not None and not isinstance(terms, (list, tuple)):
        findings.append(tier_m_unavailable_finding("banned_terms must be a list"))
    elif isinstance(terms, (list, tuple)):
        for i, term in enumerate(terms):
            t = str(term).strip().lower()
            if t and t in low:
                findings.append(_match_finding(f"banned term rule #{i} matched"))

    # Python `re` has no execution timeout: a pathological author-supplied
    # pattern is a known footgun (patterns are policy-author-trusted).
    patterns = rules.get("banned_patterns")
    if patterns is not None and not isinstance(patterns, (list, tuple)):
        findings.append(tier_m_unavailable_finding("banned_patterns must be a list"))
    elif isinstance(patterns, (list, tuple)):
        for i, pat in enumerate(patterns):
            try:
                rx = re.compile(str(pat))
            except re.error as e:
                findings.append(tier_m_unavailable_finding(
                    f"banned_patterns rule #{i} is not a valid regex ({type(e).__name__})"))
                continue
            try:
                if rx.search(text):
                    findings.append(_match_finding(f"banned pattern rule #{i} matched"))
            except Exception as e:  # noqa: BLE001
                findings.append(tier_m_unavailable_finding(
                    f"banned_patterns rule #{i} failed to evaluate ({type(e).__name__})"))

    categories = rules.get("categories") or []
    if categories:
        spec = str(rules.get("backend", "")).strip()
        try:
            backend = make_moderation_backend(spec)
        except Exception as e:  # noqa: BLE001
            return findings + [tier_m_unavailable_finding(
                f"moderation backend unavailable ({type(e).__name__})")]
        try:
            available = bool(backend.is_available())
        except Exception as e:  # noqa: BLE001
            return findings + [tier_m_unavailable_finding(
                f"moderation backend availability check failed ({type(e).__name__})")]
        if not available:
            return findings + [tier_m_unavailable_finding(
                "moderation backend is not available")]
        try:
            result = backend.classify(text, list(categories))
        except Exception as e:  # noqa: BLE001
            return findings + [tier_m_unavailable_finding(
                f"moderation backend classify failed ({type(e).__name__})")]
        if not isinstance(result, dict) or "flagged" not in result:
            return findings + [tier_m_unavailable_finding(
                "classifier backend returned a malformed result")]
        wanted = {str(c) for c in categories}
        for cat in (result.get("flagged") or []):
            label = str(cat)
            if label in wanted:
                findings.append(_match_finding(
                    f"moderation classifier flagged category {label!r}"))

    return findings
