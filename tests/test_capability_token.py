# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Capability tokens: semantic validation always; strict Ed25519 verification on demand."""
from __future__ import annotations

import json
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from loomground_lock.core import CapabilityToken, ToolCall, validate_token


def _token(private_key=None, **over):
    now = int(time.time())
    kw = dict(iss="issuer.example", sub="agent:test", aud="hr.get_employee",
              iat=now, exp=now + 60, scope={"fields": ["employee_id"]},
              controller="controller.example", task_id="task-1")
    kw.update(over)
    token = CapabilityToken(**kw)
    if private_key is not None:
        token.sign(private_key)
    return token


def _trust_store(tmp_path, issuer, public_key):
    pem = public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    path = tmp_path / "capability-issuers.json"
    path.write_text(json.dumps({issuer: pem}), encoding="utf-8")
    return path


def _validate(token):
    return validate_token(token, ToolCall("hr.get_employee", {"employee_id": "E-1"}, token))


def test_strict_mode_accepts_trusted_signed_token(tmp_path, monkeypatch):
    pk = Ed25519PrivateKey.generate()
    token = _token(pk)
    monkeypatch.setenv("LOCK_BETA_STRICT_TOKEN_SIG", "1")
    monkeypatch.setenv("LOCK_CAPABILITY_TRUST_STORE", str(_trust_store(tmp_path, token.iss, pk.public_key())))
    assert _validate(token).valid


def test_strict_mode_rejects_unsigned_token(tmp_path, monkeypatch):
    pk = Ed25519PrivateKey.generate()
    token = _token()
    monkeypatch.setenv("LOCK_BETA_STRICT_TOKEN_SIG", "1")
    monkeypatch.setenv("LOCK_CAPABILITY_TRUST_STORE", str(_trust_store(tmp_path, token.iss, pk.public_key())))
    result = _validate(token)
    assert not result.valid
    assert any(f.severity == "high" and "strict-token-sig" in f.detail for f in result.findings)


def test_strict_mode_rejects_tampered_claim(tmp_path, monkeypatch):
    pk = Ed25519PrivateKey.generate()
    token = _token(pk)
    token.aud = "payroll.export"
    monkeypatch.setenv("LOCK_BETA_STRICT_TOKEN_SIG", "1")
    monkeypatch.setenv("LOCK_CAPABILITY_TRUST_STORE", str(_trust_store(tmp_path, token.iss, pk.public_key())))
    result = _validate(token)
    assert not result.valid
    assert any("signature is invalid" in f.detail for f in result.findings)


def test_strict_mode_rejects_unknown_issuer(tmp_path, monkeypatch):
    pk = Ed25519PrivateKey.generate()
    token = _token(pk)
    monkeypatch.setenv("LOCK_BETA_STRICT_TOKEN_SIG", "1")
    monkeypatch.setenv("LOCK_CAPABILITY_TRUST_STORE", str(_trust_store(tmp_path, "other.example", pk.public_key())))
    assert not _validate(token).valid


def test_strict_mode_without_trust_store_refuses(monkeypatch):
    monkeypatch.setenv("LOCK_BETA_STRICT_TOKEN_SIG", "1")
    monkeypatch.delenv("LOCK_CAPABILITY_TRUST_STORE", raising=False)
    result = _validate(_token(Ed25519PrivateKey.generate()))
    assert not result.valid
    assert any("LOCK_CAPABILITY_TRUST_STORE" in f.detail for f in result.findings)


def test_default_mode_remains_semantic_only(monkeypatch):
    monkeypatch.delenv("LOCK_BETA_STRICT_TOKEN_SIG", raising=False)
    assert _validate(_token()).valid


def test_no_token_is_low_severity_invalid():
    result = validate_token(None, ToolCall("hr.get_employee", {"employee_id": "1"}))
    assert not result.valid
    assert all(f.severity == "low" for f in result.findings)


def test_expired_and_wrong_audience_are_high_severity():
    expired = _validate(_token(exp=int(time.time()) - 1))
    assert not expired.valid and expired.findings[0].severity == "high"
    wrong = _validate(_token(aud="other.tool"))
    assert not wrong.valid and "audience" in wrong.findings[0].detail


def test_from_dict_round_trip_and_signed_bytes_exclude_signature():
    token = _token(Ed25519PrivateKey.generate())
    again = CapabilityToken.from_dict({**token.__dict__})
    assert again == token
    assert b"signature" not in token.signed_bytes()
