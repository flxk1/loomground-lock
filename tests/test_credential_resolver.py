# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Credential references resolve fail-closed; the secret is never described."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from loomground_lock import credential_resolver as C, host_deps


@pytest.mark.parametrize("ref,expect", [
    ("env:JIRA_TOKEN", ("env", "JIRA_TOKEN")),
    ("keydir:github/pat", ("keydir", "github/pat")),
    ("oidc:legal-sso", ("oidc", "legal-sso")),
    ("spiffe://cluster/agent", ("spiffe", "//cluster/agent")),
    ("  env:X  ", ("env", "X")),
])
def test_parse_ref_valid(ref, expect):
    assert C.parse_ref(ref) == expect
    assert C.is_valid_ref(ref)


@pytest.mark.parametrize("ref", [None, "", "   ", "no-colon", "env:", ":locator", "vault:secret", "RAWSECRET", 123])
def test_parse_ref_rejects_malformed_or_unknown(ref):
    assert C.parse_ref(ref) is None
    assert not C.is_valid_ref(ref)


def test_env_resolves_when_present(monkeypatch):
    monkeypatch.setenv("MY_EGRESS_TOK", "s3cr3t")
    assert C.resolve_secret("env:MY_EGRESS_TOK") == "s3cr3t"
    assert C.arm_status("env:MY_EGRESS_TOK") == C.ARMED


def test_env_fail_closed_when_absent(monkeypatch):
    monkeypatch.delenv("MISSING_TOK", raising=False)
    assert C.resolve_secret("env:MISSING_TOK") is None
    assert C.arm_status("env:MISSING_TOK") == C.UNPLUGGED


def test_keydir_resolves_only_when_0600(tmp_path, monkeypatch):
    monkeypatch.setenv("WORKSPACE_KEY_DIR", str(tmp_path))
    secret = tmp_path / "github" / "pat"
    secret.parent.mkdir(parents=True)
    secret.write_text("ghp_abc\n")
    os.chmod(secret, 0o600)
    assert C.resolve_secret("keydir:github/pat") == "ghp_abc"
    os.chmod(secret, 0o644)
    assert C.resolve_secret("keydir:github/pat") is None
    assert C.arm_status("keydir:github/pat") == C.UNPLUGGED


def test_keydir_missing_and_escape_are_unplugged(tmp_path, monkeypatch):
    monkeypatch.setenv("WORKSPACE_KEY_DIR", str(tmp_path / "keys"))
    (tmp_path / "keys").mkdir()
    outside = tmp_path / "outside"
    outside.write_text("nope"); os.chmod(outside, 0o600)
    assert C.resolve_secret("keydir:nope") is None
    assert C.resolve_secret("keydir:../outside") is None


def test_keydir_prefers_host_key_root_hook(tmp_path, monkeypatch):
    monkeypatch.setenv("WORKSPACE_KEY_DIR", str(tmp_path / "env-root"))
    hook_root = tmp_path / "hook-root"; hook_root.mkdir()
    (hook_root / "tok").write_text("from-hook"); os.chmod(hook_root / "tok", 0o600)
    host_deps.register(key_root_dir=lambda: Path(hook_root))
    assert C.resolve_secret("keydir:tok") == "from-hook"
    monkeypatch.delenv("WORKSPACE_KEY_DIR")
    host_deps.clear()
    assert C.resolve_secret("keydir:tok") is None


def test_oidc_spiffe_and_no_cable():
    assert C.resolve_secret("oidc:legal-sso") is None
    assert C.arm_status("oidc:legal-sso") == C.UNPLUGGED
    assert C.arm_status("spiffe://x") == C.UNPLUGGED
    assert C.arm_status(None) == C.NO_CABLE
    assert C.arm_status("") == C.NO_CABLE
    assert C.arm_status("bogus") == C.UNPLUGGED


def test_describe_never_leaks_secret(monkeypatch):
    monkeypatch.setenv("TOK", "leak-me")
    d = C.describe("env:TOK")
    assert d == {"credential_ref": "env:TOK", "scheme": "env", "status": C.ARMED, "enforceable": True}
    assert "leak-me" not in repr(d)
    assert C.describe("oidc:sso")["enforceable"] is False
    assert C.describe(None) == {"credential_ref": None, "scheme": None, "status": C.NO_CABLE, "enforceable": False}
