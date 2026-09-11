# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Tier B+ confusable-Unicode bypass detection and the capture redactor."""
from __future__ import annotations

from loomground_lock.core import (
    Mode,
    _ascii_fold,
    _detect_confusable_bypass,
    lock_text,
    redact_for_capture,
    tier_b_scan_text,
)

CYRILLIC_A = "а"


def test_ascii_email_caught_by_tier_b():
    assert tier_b_scan_text("Contact admin\x40example.com for access.")


def test_homoglyph_email_bypasses_tier_b_but_b_plus_catches():
    assert CYRILLIC_A != "a"
    bypass_email = f"{CYRILLIC_A}dmin@ex{CYRILLIC_A}mple.com"
    b_plus = _detect_confusable_bypass(bypass_email)
    assert b_plus
    assert b_plus[0].tier == "B+"
    assert b_plus[0].type == "confusable_bypass"
    assert b_plus[0].severity == "high"
    assert CYRILLIC_A not in b_plus[0].remediation_actions[0].payload["redacted_text"]


def test_legitimate_international_text_does_not_trip_b_plus():
    assert _detect_confusable_bypass("Visited the café in München with José last week.") == []


def test_lock_text_integrates_b_plus_findings():
    decision = lock_text(f"Send to {CYRILLIC_A}dmin@ex{CYRILLIC_A}mple.com please", mode=Mode.STANDARD)
    assert decision.action == "refuse"
    assert any(f.tier == "B+" and f.type == "confusable_bypass" for f in decision.findings)


def test_ascii_fold_handles_zero_width_and_greek():
    assert _ascii_fold("ad​min") == "admin"
    assert _ascii_fold("αdmin") == "admin"


def test_redact_for_capture_covers_credentials_and_pii():
    text = ("password=hunter22 token: abcd1234ef Bearer zzzzzzzzzz "
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig_sig_sig "
            "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----"
            " mail alex\x40example.com")
    out = redact_for_capture(text)
    for leak in ("hunter22", "abcd1234ef", "zzzzzzzzzz", "eyJhbGci", "MIIE", "alex\x40example.com"):
        assert leak not in out
    assert "[REDACTED-PRIVATE-KEY]" in out and "[REDACTED-JWT]" in out
    assert redact_for_capture("") == ""
