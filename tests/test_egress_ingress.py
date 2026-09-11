# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""egress()/ingress() orchestration and the ingress field invariant."""
from __future__ import annotations

import json

from loomground_lock import AuditLog, Mode, ToolCall, ToolResponse, egress, ingress
from loomground_lock.core import tier_a_check_response, tier_b_scan_dict


def test_ingress_findings_always_carry_a_field():
    """A high-severity finding with field=None would redact nothing and fall
    through to allow; every ingress producer must set a field."""
    payload = {"email": "a@b.com", "note": "call 555-867-5309",
               "nested": {"ssn": "123-45-6789"},
               "items": ["x@y.com", {"phone": "555-0100"}]}
    findings = list(tier_a_check_response(payload, task_scope={"note"}))
    findings += list(tier_b_scan_dict(payload))
    assert findings
    assert not [f for f in findings if f.field is None]


def test_egress_standard_strips_over_collection(tmp_path):
    audit = AuditLog(tmp_path / "a.jsonl")
    call = ToolCall("hr.get_employee", {"employee_id": "E-1", "salary": "x"})
    d = egress(call, task_scope={"employee_id"}, audit=audit)
    assert d.action == "strip"
    assert d.stripped_fields == ["salary"]
    assert d.modified_call.arguments == {"employee_id": "E-1"}
    entry = json.loads((tmp_path / "a.jsonl").read_text())
    assert entry["kind"] == "egress" and entry["action"] == "strip"
    assert "E-1" not in (tmp_path / "a.jsonl").read_text()


def test_egress_strict_refuses_pii_in_arguments():
    call = ToolCall("crm.note", {"note": "mail alex\x40example.com"})
    assert egress(call, task_scope={"note"}, mode=Mode.STRICT).action == "refuse"


def test_egress_permissive_and_audit_only_allow():
    call = ToolCall("crm.note", {"note": "mail alex\x40example.com", "extra": 1})
    assert egress(call, task_scope={"note"}, mode=Mode.PERMISSIVE).action == "allow"
    assert egress(call, task_scope={"note"}, mode=Mode.AUDIT_ONLY).action == "allow"


def test_ingress_redacts_over_return_and_pii():
    resp = ToolResponse({"name": "ok", "email": "a\x40b.com", "extra": "y"})
    d = ingress(resp, task_scope={"name", "email"})
    assert d.action == "redact"
    assert d.redacted_payload["email"] == "[REDACTED]"
    assert d.redacted_payload["extra"] == "[REDACTED]"
    assert d.redacted_payload["name"] == "ok"
    assert all(f.type != "pii_in_argument" for f in d.findings if f.tier == "B")


def test_ingress_clean_allows(tmp_path):
    audit = AuditLog(tmp_path / "a.jsonl")
    d = ingress(ToolResponse({"name": "ok"}), task_scope={"name"}, audit=audit, task_id="t9")
    assert d.action == "allow"
    assert json.loads((tmp_path / "a.jsonl").read_text())["task_id"] == "t9"
