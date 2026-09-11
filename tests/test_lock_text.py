# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""lock_text() — the document/triple approval entry point (Tier B + B+ + C)."""
from __future__ import annotations

import json

from loomground_lock import AuditLog, Mode, lock_text
from loomground_lock.core import _redact_text_with_regex


def test_lock_text_allows_clear_info():
    decision = lock_text("the build pipeline finishes in twelve minutes.")
    assert decision.action == "allow"
    assert decision.findings == []
    assert decision.redacted_text is None


def test_lock_text_refuses_email_in_standard_mode():
    decision = lock_text("contact me at alex\x40example.com about it")
    assert decision.action == "refuse"
    assert any(f.tier == "B" for f in decision.findings)
    assert "high-severity" in decision.reason.lower()


def test_lock_text_refuses_iban_in_standard_mode():
    decision = lock_text("transfer to DE89370400440532013000 today.")
    assert decision.action == "refuse"
    assert any(f.tier == "B" and "iban" in f.detail for f in decision.findings)


def test_lock_text_refuses_when_confidential_term_present():
    decision = lock_text(
        "the project atlas architecture ships phase 3 in june.",
        context="- acme corp\n- project atlas\n- northwind",
    )
    assert decision.action == "refuse"
    assert any(f.tier == "C" and "confidential" in f.detail.lower() for f in decision.findings)


def test_lock_text_no_refuse_when_confidential_term_absent():
    decision = lock_text(
        "the build pipeline finishes in twelve minutes.",
        context="- acme corp\n- brand",
    )
    assert decision.action == "allow"


def test_lock_text_audit_only_never_refuses():
    decision = lock_text("contact me at alex\x40example.com", mode=Mode.AUDIT_ONLY)
    assert decision.action == "allow"
    assert any(f.tier == "B" for f in decision.findings)
    assert "audit-only" in decision.reason.lower()


def test_lock_text_permissive_never_refuses():
    decision = lock_text("contact me at alex\x40example.com", mode=Mode.PERMISSIVE)
    assert decision.action == "allow"
    assert any(f.tier == "B" for f in decision.findings)


def test_lock_text_strict_refuses_any_finding():
    decision = lock_text("contact me at alex\x40example.com", mode=Mode.STRICT)
    assert decision.action == "refuse"


def test_lock_text_source_tag_default():
    assert lock_text("clean text").source == "document"


def test_lock_text_source_tag_triple():
    decision = lock_text("(workspaceversum, ships, phase3)", source="triple", context="workspaceversum")
    assert decision.source == "triple"
    assert decision.action == "refuse"


def test_lock_text_writes_audit_entry(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    audit = AuditLog(audit_path)
    lock_text("contact me at alex\x40example.com", audit=audit, source="document")
    lines = audit_path.read_text().strip().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["kind"] == "text"
    assert entry["source"] == "document"
    assert entry["action"] == "refuse"
    assert entry["findings_count"] >= 1
    assert "alex\x40example.com" not in lines[0]
    assert entry["text_length"] > 0


def test_lock_text_audit_includes_task_id(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    lock_text("clean text", audit=AuditLog(audit_path), task_id="task-42")
    assert json.loads(audit_path.read_text().strip())["task_id"] == "task-42"


def test_lock_text_redaction_helper_strips_emails():
    out = _redact_text_with_regex("write to alice\x40example.com or bob\x40example.org")
    assert "alice\x40example.com" not in out
    assert "bob\x40example.org" not in out
    assert "[REDACTED-EMAIL]" in out


def test_lock_text_redaction_helper_strips_iban():
    out = _redact_text_with_regex("IBAN DE89370400440532013000 needs processing")
    assert "DE89370400440532013000" not in out
    assert "[REDACTED-IBAN-FULL]" in out


def test_lock_text_redaction_helper_covers_full_tier_b_set():
    out = _redact_text_with_regex(
        "SSN 078-05-1120, key sk-abc123DEF456ghi789, card 4111 1111 1111 1111")
    assert "078-05-1120" not in out
    assert "sk-abc123DEF456ghi789" not in out
    assert "4111 1111 1111 1111" not in out
    assert "[REDACTED-US-SSN]" in out
    assert "[REDACTED-API-KEY]" in out
    assert "[REDACTED-CREDIT-CARD]" in out


def test_lock_text_redaction_helper_credit_card_stays_luhn_gated():
    out = _redact_text_with_regex("order ref 1234 5678 9012 3456")
    assert "[REDACTED-CREDIT-CARD]" not in out


def test_lock_text_handles_empty_string():
    decision = lock_text("")
    assert decision.action == "allow"
    assert decision.findings == []


def test_lock_text_handles_unicode():
    assert lock_text("café résumé naïve façade — multi-byte text").action == "allow"


def test_lock_text_moderation_rules_none_is_noop():
    assert lock_text("perfectly benign words", moderation_rules=None).action == "allow"
