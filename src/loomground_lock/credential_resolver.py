# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Resolve an egress track's credential *reference* to the secret, at call
time, fail-closed. A record stores only the reference (``env:JIRA_TOKEN``);
the secret is resolved here for immediate injection and is never persisted,
logged, or returned by any status path — only ``resolve_secret`` returns it.

Schemes::

    env:NAME        the process environment
    keydir:relpath  a regular file under the key root, mode 0600
    oidc:realm      an IdP adapter (no adapter yet → unplugged)
    spiffe://…      workload identity (no adapter yet → unplugged)

Arm status, never the secret::

    no_cable   no reference at all
    armed      the reference resolves to a present secret
    unplugged  a reference is set but does not resolve

Invariants: a malformed or unknown-scheme ref is never armed; ``keydir:``
refuses a group/world-readable file; ``resolve_secret`` returns ``None``
whenever the status is not ``armed``.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Optional

from . import host_deps

# Compatibility constant — the key-root override a host may already set.
ENV_KEY_DIR = "WORKSPACE_KEY_DIR"

SCHEMES = ("env", "keydir", "oidc", "spiffe")
LOCAL_SCHEMES = ("env", "keydir")

NO_CABLE = "no_cable"
ARMED = "armed"
UNPLUGGED = "unplugged"


def parse_ref(ref: Optional[str]) -> Optional[tuple[str, str]]:
    """``scheme:locator`` → ``(scheme, locator)``; ``None`` if malformed or unknown."""
    if not ref or not isinstance(ref, str):
        return None
    s = ref.strip()
    if ":" not in s:
        return None
    scheme, locator = s.split(":", 1)
    scheme = scheme.strip().lower()
    locator = locator.strip()
    if scheme not in SCHEMES or not locator:
        return None
    return (scheme, locator)


def is_valid_ref(ref: Optional[str]) -> bool:
    return parse_ref(ref) is not None


def _key_root() -> Optional[Path]:
    """The base for ``keydir:`` refs — the host's key root hook, else
    ``WORKSPACE_KEY_DIR``; ``None`` → keydir refs are unresolvable."""
    try:
        host_deps.ensure_wired()
        if host_deps.key_root_dir is None:
            raise LookupError("key-root hook not wired")
        return host_deps.key_root_dir()
    except Exception:
        override = os.environ.get(ENV_KEY_DIR)
        return Path(override).expanduser() if override else None


def _resolve_keydir(locator: str) -> Optional[str]:
    root = _key_root()
    if root is None:
        return None
    root = root.resolve()
    target = (root / locator).resolve()
    try:
        target.relative_to(root)
    except ValueError:
        return None
    if not target.is_file():
        return None
    mode = stat.S_IMODE(target.stat().st_mode)
    if mode & 0o077:
        return None
    try:
        return target.read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


def resolve_secret(ref: Optional[str]) -> Optional[str]:
    """The secret for immediate injection, or ``None`` (fail-closed). NEVER log it."""
    parsed = parse_ref(ref)
    if parsed is None:
        return None
    scheme, locator = parsed
    if scheme == "env":
        val = os.environ.get(locator)
        return val if val else None
    if scheme == "keydir":
        return _resolve_keydir(locator)
    return None


def arm_status(ref: Optional[str]) -> str:
    if not (ref or "").strip():
        return NO_CABLE
    if parse_ref(ref) is None:
        return UNPLUGGED
    return ARMED if resolve_secret(ref) is not None else UNPLUGGED


def describe(ref: Optional[str]) -> dict:
    """A secret-free description: reference, scheme, arm status, and whether a
    local broker can inject it (vs merely attest it)."""
    parsed = parse_ref(ref)
    return {
        "credential_ref": (ref or "").strip() or None,
        "scheme": parsed[0] if parsed else None,
        "status": arm_status(ref),
        "enforceable": bool(parsed and parsed[0] in LOCAL_SCHEMES),
    }
