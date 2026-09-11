# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""DecisionsStore — persisted user approvals: scope precedence, block wins, TTL, redacted previews."""
from __future__ import annotations

import json

import pytest

from loomground_lock import DecisionsStore
from loomground_lock.decisions import _DEFAULT_PATH


def test_empty_store_recall_returns_none(tmp_path):
    assert DecisionsStore(tmp_path / "d.jsonl").recall("anything") is None


def test_remember_and_recall_always(tmp_path):
    store = DecisionsStore(tmp_path / "d.jsonl")
    store.remember("Workspaceversum ships in June", "allow", scope="always", actor="tester", reason="ok by policy")
    assert store.recall("Workspaceversum ships in June") == "allow"


def test_anonymous_always_clearance_is_rejected(tmp_path):
    store = DecisionsStore(tmp_path / "d.jsonl")
    with pytest.raises(ValueError):
        store.remember("silence me forever", "allow", scope="always")
    assert store.recall("silence me forever") is None
    assert store.remember("ok pattern", "allow", scope="always", actor="alice").actor == "alice"
    store.remember("ephemeral", "allow", scope="once")


def test_recall_is_case_whitespace_and_nfc_insensitive(tmp_path):
    store = DecisionsStore(tmp_path / "d.jsonl")
    store.remember("café ships in June", "block", scope="always", actor="t")
    assert store.recall("  CAFÉ SHIPS IN JUNE  ") == "block"
    assert store.recall("café ships in june") == "block"


def test_block_decision_recalls_as_block(tmp_path):
    store = DecisionsStore(tmp_path / "d.jsonl")
    store.remember("sensitive text", "block", scope="always", actor="tester")
    assert store.recall("sensitive text") == "block"


def test_once_scope_is_not_durable(tmp_path):
    store = DecisionsStore(tmp_path / "d.jsonl")
    store.remember("ephemeral text", "allow", scope="once")
    assert store.recall("ephemeral text") is None


def test_session_scope_within_and_across_sessions(tmp_path):
    path = tmp_path / "d.jsonl"
    a = DecisionsStore(path, session_id="session-A")
    a.remember("session text", "allow", scope="session")
    assert a.recall("session text") == "allow"
    assert DecisionsStore(path, session_id="session-B").recall("session text") is None


def test_always_outranks_session(tmp_path):
    store = DecisionsStore(tmp_path / "d.jsonl", session_id="s1")
    store.remember("X", "block", scope="session")
    store.remember("X", "allow", scope="always", actor="tester")
    assert store.recall("X") == "allow"


def test_block_precedence_within_scope(tmp_path):
    store = DecisionsStore(tmp_path / "d.jsonl")
    store.remember("X", "block", scope="always", actor="tester")
    store.remember("X", "allow", scope="always", actor="tester")
    assert store.recall("X") == "block"


def test_persists_across_instances(tmp_path):
    path = tmp_path / "d.jsonl"
    DecisionsStore(path).remember("durable text", "allow", scope="always", actor="tester")
    assert DecisionsStore(path).recall("durable text") == "allow"


def test_invalid_values_raise(tmp_path):
    store = DecisionsStore(tmp_path / "d.jsonl")
    with pytest.raises(ValueError):
        store.remember("X", "maybe", scope="always", actor="tester")
    with pytest.raises(ValueError):
        store.remember("X", "allow", scope="permanent")


def test_jsonl_format_and_redacted_preview(tmp_path):
    path = tmp_path / "d.jsonl"
    store = DecisionsStore(path)
    long_multiline = "mail alex\x40example.com\nline two " + ("x" * 200)
    rec = store.remember(long_multiline, "allow", scope="always", actor="tester", reason="user said ok")
    lines = path.read_text().strip().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["decision"] == "allow" and entry["scope"] == "always"
    assert entry["pattern_hash"].startswith("sha256:")
    assert entry["reason"] == "user said ok" and "ts" in entry
    assert "\n" not in rec.pattern_preview and len(rec.pattern_preview) <= 80
    assert "alex\x40example.com" not in path.read_text()


def test_corrupt_line_is_skipped(tmp_path):
    path = tmp_path / "d.jsonl"
    path.write_text("not-valid-json\n" + json.dumps({
        "ts": 1.0, "pattern_hash": "sha256:abc", "pattern_preview": "x",
        "decision": "allow", "scope": "always", "reason": ""}) + "\n")
    assert len(DecisionsStore(path).all_decisions()) == 1


def test_allow_expires_block_never(tmp_path):
    store = DecisionsStore(tmp_path / "d.jsonl", ttl_seconds=10)
    store.remember("A", "allow", scope="always", actor="t")
    store.remember("B", "block", scope="always", actor="t")
    import time
    later = time.time() + 11
    assert store.recall("A", now=later) is None
    assert store.recall("B", now=later) == "block"
    assert DecisionsStore(tmp_path / "e.jsonl", ttl_seconds=0).ttl_seconds == 0


def test_ttl_env_and_session_env_are_read(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_TOOL_LOCK_DECISION_TTL_SECONDS", "42")
    monkeypatch.setenv("AGENT_TOOL_LOCK_SESSION_ID", "env-session")
    store = DecisionsStore(tmp_path / "d.jsonl")
    assert store.ttl_seconds == 42 and store.session_id == "env-session"
    monkeypatch.setenv("AGENT_TOOL_LOCK_DECISION_TTL_SECONDS", "nonsense")
    assert DecisionsStore(tmp_path / "d.jsonl").ttl_seconds == DecisionsStore._DEFAULT_TTL_SECONDS


def test_erase_and_erase_subject_blank_previews_keep_hashes(tmp_path):
    path = tmp_path / "d.jsonl"
    path.write_text("garbage line\n")
    store = DecisionsStore(path)
    store.remember("project nimbus memo", "block", scope="always", actor="t")
    store.remember("other text", "allow", scope="always", actor="t")
    assert store.erase_subject("NIMBUS") == 1
    assert store.erase_subject("") == 0
    assert store.erase() == 2
    lines = path.read_text().splitlines()
    assert lines[0] == "garbage line"
    assert all(json.loads(l)["pattern_preview"] == "" for l in lines[1:])
    assert DecisionsStore(path).recall("project nimbus memo") == "block"


def test_default_path_lives_under_redirected_home():
    import os
    assert str(_DEFAULT_PATH).startswith(os.environ["HOME"])
