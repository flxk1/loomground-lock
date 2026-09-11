# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Cleartext / ScannedResponse type discipline and the runtime egress guard."""
from __future__ import annotations

import pytest

from loomground_lock.scanned_response import (
    Cleartext,
    CleartextEgressError,
    LockAudit,
    ScannedResponse,
    assert_scanned,
    scan_payload,
)


def test_to_payload_dict_value():
    out = ScannedResponse(value={"folder": "/foo", "count": 3}, audit=LockAudit(tier="A", total_findings=2)).to_payload()
    assert out["folder"] == "/foo" and out["count"] == 3
    assert out["_lock_egress"]["tier"] == "A" and out["_lock_egress"]["total_findings"] == 2


def test_to_payload_scalar_value_and_compat_alias():
    sr = ScannedResponse(value=42, audit=LockAudit())
    assert sr.to_payload()["value"] == 42
    assert sr.to_mcp_payload() == sr.to_payload()


def test_preserves_existing_lock_block():
    out = ScannedResponse(value={"lock": {"existing_field": "kept"}, "data": 1},
                          audit=LockAudit(tier="A", total_findings=5)).to_payload()
    assert out["lock"]["existing_field"] == "kept"
    assert out["lock"]["egress_tier"] == "A" and out["lock"]["egress_total_findings"] == 5
    assert "_lock_egress" not in out


def test_assert_scanned_accepts_scanned_response():
    assert_scanned(ScannedResponse(value={"ok": True}))


@pytest.mark.parametrize("obj,msg", [
    (Cleartext(value={"pii": "alex\x40example.com"}), "Cleartext crossed an egress boundary"),
    ({"plain": "dict"}, "expected ScannedResponse"),
    ("just a string", "expected ScannedResponse"),
    (None, "expected ScannedResponse"),
])
def test_assert_scanned_refuses_everything_else(obj, msg):
    with pytest.raises(CleartextEgressError, match=msg):
        assert_scanned(obj)


def test_cleartext_unwrap_for_lock():
    assert Cleartext(value={"raw": "data"}).unwrap_for_lock() == {"raw": "data"}


def test_scan_payload_factory():
    sr = scan_payload({"hello": "world"})
    assert isinstance(sr, ScannedResponse) and sr.audit.tier == "A" and sr.audit.total_findings == 0
    custom = scan_payload({"x": 1}, audit=LockAudit(tier="C", total_findings=7, refused=1))
    assert custom.to_payload()["_lock_egress"]["refused"] == 1
