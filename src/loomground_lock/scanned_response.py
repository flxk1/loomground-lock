# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Cleartext / ScannedResponse — type-disciplined egress invariant.

A transport handler at a trust boundary accepts only ``ScannedResponse``:

- ``Cleartext[T]``       — pre-lock data. The type-checker and the runtime
                            guard both refuse it at egress.
- ``ScannedResponse[T]`` — post-lock data, carrying a short audit record of
                            what the lock did. ``to_payload()`` yields the dict
                            the transport serialises; that call is the only
                            sanctioned exit.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar


T = TypeVar("T")


class CleartextEgressError(RuntimeError):
    """Something other than a ScannedResponse reached an egress boundary."""


@dataclass(frozen=True)
class Cleartext(Generic[T]):
    """Data that has NOT yet been through the lock."""

    value: T

    def unwrap_for_lock(self) -> T:
        """Explicit unwrap for code operating pre-lock (the lock itself)."""
        return self.value


@dataclass(frozen=True)
class LockAudit:
    """What the lock did: tier, finding count, refusals, minimisations."""

    tier: str = "A"                # "A" | "B" | "C" | "ingest-cached"
    total_findings: int = 0
    refused: int = 0
    minimised: int = 0
    notes: str = ""


@dataclass(frozen=True)
class ScannedResponse(Generic[T]):
    """Data that HAS been through the lock — the only type that may cross an
    egress boundary."""

    value: T
    audit: LockAudit = field(default_factory=LockAudit)

    def to_payload(self) -> dict[str, Any]:
        """Render to the transport dict: the value's fields plus the audit record
        (merged into an existing ``lock`` block, else under ``_lock_egress``).
        A non-dict value is wrapped under ``value``."""
        if isinstance(self.value, dict):
            out: dict[str, Any] = dict(self.value)
        else:
            out = {"value": self.value}
        existing = out.get("lock")
        if isinstance(existing, dict):
            existing.setdefault("egress_tier", self.audit.tier)
            existing.setdefault("egress_total_findings", self.audit.total_findings)
        else:
            out["_lock_egress"] = {
                "tier":            self.audit.tier,
                "total_findings":  self.audit.total_findings,
                "refused":         self.audit.refused,
                "minimised":       self.audit.minimised,
                "notes":           self.audit.notes,
            }
        return out

    # Compatibility name kept for existing hosts (documented in docs/seam.md).
    to_mcp_payload = to_payload


def assert_scanned(obj: Any) -> None:
    """Runtime guard at the egress boundary, just before serialising."""
    if isinstance(obj, Cleartext):
        raise CleartextEgressError(
            "Cleartext crossed an egress boundary. Wrap in ScannedResponse "
            "after running lock, or use scanned.to_payload() to "
            "exit the trust boundary."
        )
    if not isinstance(obj, ScannedResponse):
        raise CleartextEgressError(
            f"egress boundary expected ScannedResponse, got {type(obj).__name__}. "
            "Wrap your response in ScannedResponse and call to_payload()."
        )


def scan_payload(value: T, audit: LockAudit | None = None) -> ScannedResponse[T]:
    """Wrap a value the lock has already run over; pass the real ``LockAudit``."""
    return ScannedResponse(value=value, audit=audit or LockAudit())
