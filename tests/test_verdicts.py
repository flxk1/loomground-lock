# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Lock actions land inside the .lg verdict alphabet read from loomground-governance."""
from __future__ import annotations

import inspect
import re

import pytest
from loomground_governance import vocabulary

from loomground_lock import OversightLevel, verdicts


def test_codomain_is_a_subset_of_the_vocabulary_alphabet():
    alphabet = set(vocabulary("verdicts")["alphabet"])
    assert set(verdicts.action_verdicts().values()) <= alphabet
    assert set(verdicts.oversight_verdicts().values()) <= alphabet
    assert verdicts.alphabet() == tuple(vocabulary("verdicts")["alphabet"])


def test_alphabet_is_read_at_runtime_not_redeclared():
    src = inspect.getsource(verdicts)
    assert 'vocabulary("verdicts")' in src
    assert not re.search(r'"prohibited"|"reserved"', src)
    assert "releases_at_master" in src


def test_action_mapping_shape():
    voc = vocabulary("verdicts")
    releasing = [k for k, v in voc["releases_at_master"].items() if v][0]
    m = verdicts.action_verdicts()
    assert m["allow"] == m["minimise"] == m["strip"] == m["redact"] == releasing
    assert m["refuse"] != releasing and m["ask_user"] != releasing
    assert verdicts.verdict_for_action("REFUSE ") == m["refuse"]
    assert verdicts.verdict_for_action("unknown-thing") == m["ask_user"]
    assert verdicts.verdict_for_action(None) == m["ask_user"]


def test_oversight_mapping_shape():
    m = verdicts.oversight_verdicts()
    voc = vocabulary("verdicts")
    order = voc["restrictiveness_order"]
    assert order.index(m[OversightLevel.AUTONOMOUS]) < order.index(m[OversightLevel.APPROVE])
    assert m[OversightLevel.NOTIFY] == m[OversightLevel.AUTONOMOUS]
    assert len({m[l] for l in (OversightLevel.REVIEW, OversightLevel.APPROVE, OversightLevel.SUPERVISED, OversightLevel.MANUAL)}) == 1
    assert verdicts.verdict_for_oversight(6) == m[OversightLevel.MANUAL]


def test_vocabulary_drift_surfaces_as_lookup_error(monkeypatch):
    monkeypatch.setattr(verdicts, "vocabulary", lambda name: {
        "alphabet": ["go", "stop"], "releases_at_master": {"go": True, "stop": False}})
    with pytest.raises(LookupError):
        verdicts.action_verdicts()
    monkeypatch.setattr(verdicts, "vocabulary", lambda name: {
        "alphabet": ["human", "refused"], "releases_at_master": {"human": False, "refused": False}})
    with pytest.raises(LookupError):
        verdicts.action_verdicts()
