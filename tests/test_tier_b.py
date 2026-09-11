# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Tier B regex coverage: the 12 PII shapes plus the Luhn gate and negatives."""
from __future__ import annotations

from loomground_lock.core import _luhn_ok, tier_b_scan_text


def _kinds(text: str) -> set[str]:
    return {f.detail.split(":")[-1].strip() for f in tier_b_scan_text(text)}


def test_email():
    assert "email" in _kinds("contact alex\x40example.com today")


def test_iban_de():
    assert "iban" in _kinds("account: DE89370400440532013000 owner xyz")


def test_us_ssn():
    assert "us_ssn" in _kinds("SSN 123-45-6789 on file")


def test_uk_nino():
    assert "uk_nino" in _kinds("NINO AB123456C verified")


def test_de_personalausweis():
    assert "de_personnummer" in _kinds("ID C9X8T7R6Q issued 2024")


def test_url_with_creds():
    assert "url_with_creds" in _kinds("clone https://alice:pw123\x40gitlab.example.com/r.git")


def test_bearer_token():
    assert "bearer_token" in _kinds("Authorization: Bearer abcd1234efgh5678ijkl9012")


def test_api_key_aws():
    assert "api_key" in _kinds("aws creds " "AKIA" "IOSFODNN7EXAMPLE rotated last week")


def test_api_key_stripe():
    assert "api_key" in _kinds("stripe " "sk_" "live_abc123def456ghi789jkl")


def test_api_key_github():
    assert "api_key" in _kinds("ghp_" "abcdefghijklmnopqrstuvwxyz1234")


def test_api_key_google():
    assert "api_key" in _kinds("AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")


def test_ipv4():
    assert "ipv4" in _kinds("client connected from 192.168.1.42")


def test_ipv6():
    assert "ipv6" in _kinds("ipv6 2001:0db8:85a3:0000:0000:8a2e:0370:7334")


def test_credit_card_valid_visa():
    assert "credit_card" in _kinds("card 4111 1111 1111 1111 expires 12/30")


def test_credit_card_valid_mastercard():
    assert "credit_card" in _kinds("MC 5555555555554444 charged")


def test_credit_card_invalid_luhn_rejected():
    kinds = _kinds("order 1234567890123456 placed")
    assert "credit_card" not in kinds, f"Luhn-invalid digit string falsely matched: {kinds}"


def test_phone_simple():
    assert "phone" in _kinds("call +49 30 1234 5678 anytime")


def test_luhn_known_valid():
    assert _luhn_ok("4111111111111111") is True
    assert _luhn_ok("5555555555554444") is True
    assert _luhn_ok("378282246310005") is True


def test_luhn_known_invalid():
    assert _luhn_ok("4111111111111112") is False
    assert _luhn_ok("1234567890123456") is False
    assert _luhn_ok("12345") is False


def test_negative_plain_prose():
    assert _kinds("The quick brown fox jumped over the lazy dog.") == set()


def test_negative_short_digits():
    assert _kinds("only 42 left in stock") == set()


def test_negative_arbitrary_long_digits():
    assert "credit_card" not in _kinds("event timestamp 1739012345678901")


def test_multiple_kinds_one_text():
    text = (
        "Hi alex\x40example.com — your IBAN DE89370400440532013000 is on file. "
        "SSN 123-45-6789. Card 4111111111111111. Bearer abcdefghijklmnopqrst "
        "calls from 192.168.1.42."
    )
    expected = {"email", "iban", "us_ssn", "credit_card", "bearer_token", "ipv4"}
    missing = expected - _kinds(text)
    assert not missing, f"missing kinds: {missing}"


def test_findings_carry_remediation_block_in_stable_order():
    f = tier_b_scan_text("mail alex\x40example.com")[0]
    kinds = [a.kind for a in f.remediation_actions]
    assert kinds == ["redact_and_retry", "bypass_once", "disable_lock"]
    assert "alex\x40example.com" not in f.remediation_actions[0].payload["redacted_text"]
    assert f.remediation_actions[1].payload == {"acknowledgement_required": True}
