# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Ingest-time classification: lock + clean blocks, input left unchanged."""
from __future__ import annotations

import copy

from loomground_lock import host_deps
from loomground_lock.lock_classify import (
    LOCK_DISCLAIMER_VERSION,
    _lock_string,
    lock_classify_pair,
    reclassify_all_pairs,
)

PAIR = {
    "id": "sha256:p1",
    "problem": {"id": "p1", "scope": "s", "type": "rule", "kind": "norm",
                "summary": "Reach alex\x40example.com for the atlas rollout",
                "facets": {"domain": "law", "subject": "alex\x40example.com", "language": "en"},
                "context": {"regulation": "GDPR", "domains": ["privacy"]},
                "source_document": "/docs/contract.pdf"},
    "solution": {"id": "sha256:p1", "problem_id": "p1", "body": "call 555-867-5309",
                 "authority_tier": 1, "confidence": 0.9, "body_format": "prose",
                 "term": "controller", "defined_as": "the entity deciding purposes"},
}


def test_lock_string_shapes():
    assert _lock_string("") == {"action": "allow", "text": "", "findings": 0}
    assert _lock_string("plain words")["action"] == "allow"
    refused = _lock_string("mail alex\x40example.com")
    assert refused["action"] == "refuse" and refused["text"] == "[LOCK-REFUSED]"
    assert refused["findings"] >= 1


def test_classify_leaves_input_unchanged_and_adds_blocks():
    before = copy.deepcopy(PAIR)
    out = lock_classify_pair(PAIR, "/ws")
    assert PAIR == before
    assert set(out) == set(PAIR) | {"lock", "clean"}
    assert out["lock"]["disclaimer_version"] == LOCK_DISCLAIMER_VERSION
    assert out["lock"]["total_findings"] >= 3


def test_clean_side_carries_no_raw_pii():
    out = lock_classify_pair(PAIR, "/ws")
    flat = repr(out["clean"])
    assert "alex\x40example.com" not in flat
    assert "555-867-5309" not in flat
    assert out["clean"]["fingerprint"]["summary"] == "[LOCK-REFUSED]"
    assert "subject" not in out["clean"]["fingerprint"]["facets"]
    assert out["lock"]["facets_dropped"] == 1
    assert out["lock"]["audit_body"]["action"] == "refuse"


def test_clean_triples_keep_structure_and_apply_context_terms():
    out = lock_classify_pair(PAIR, "/ws", context="- atlas")
    preds = {t[1] for t in out["clean"]["triples"]}
    assert {"kind", "scope", "type", "domain", "regulation", "domains_includes", "term", "defined_as"} <= preds
    assert ["sha256:p1", "regulation", "GDPR"] in out["clean"]["triples"]
    assert out["lock"]["triples_dropped"] >= 1


def test_doc_token_falls_back_without_host_and_uses_hook_when_wired():
    unwired = lock_classify_pair(PAIR, "/ws")
    tokens = [t[2] for t in unwired["clean"]["triples"] if t[1] == "source_document"]
    assert tokens == ["<DOC_unknown>"]
    host_deps.register(opaque_doc_token=lambda src, folder: f"<DOC_{len(src)}_{folder}>")
    wired = lock_classify_pair(PAIR, "/ws")
    tokens = [t[2] for t in wired["clean"]["triples"] if t[1] == "source_document"]
    assert tokens == ["<DOC_18_/ws>"]
    assert "/docs/contract.pdf" not in repr(wired["clean"])


def test_document_ingest_summary_is_a_token():
    pair = copy.deepcopy(PAIR)
    pair["problem"]["type"] = "document_ingest"
    out = lock_classify_pair(pair, "/ws")
    assert out["clean"]["fingerprint"]["summary"] == "document <DOC_unknown>"


class _Memory:
    def __init__(self, pairs): self.pairs = pairs; self.written = []
    def all_pairs(self): return self.pairs
    def remember(self, pair, **kw): self.written.append((pair, kw))


def test_reclassify_skips_current_and_rewrites_stale():
    current = lock_classify_pair(PAIR, "/ws")
    stale = copy.deepcopy(PAIR); stale["id"] = "sha256:p2"; stale["lock"] = {"disclaimer_version": "v0"}
    mem = _Memory([current, stale])
    res = reclassify_all_pairs("/ws", memory=mem)
    assert res == {"ok": True, "folder_context": "/ws", "pairs_total": 2,
                   "pairs_reclassified": 1, "pairs_already_current": 1,
                   "disclaimer_version": LOCK_DISCLAIMER_VERSION}
    assert mem.written[0][1] == {"channel": "system", "source_hash": "p2"}


def test_reclassify_without_memory_port_raises():
    import pytest
    with pytest.raises(RuntimeError):
        reclassify_all_pairs("/ws")
    host_deps.register(workspace_memory=lambda fc, log_root, actor: _Memory([]))
    assert reclassify_all_pairs("/ws")["pairs_total"] == 0
