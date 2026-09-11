# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Lock decisions in the .lg verdict alphabet.

The alphabet is read at call time from ``loomground_governance.vocabulary("verdicts")``
and never re-declared here: the releasing member is derived from
``releases_at_master``; the two other members this module names are checked
against the alphabet on every call, so a vocabulary change surfaces as a
``LookupError`` instead of a silent drift.
"""
from __future__ import annotations

from loomground_governance import vocabulary

from .oversight import OversightLevel


def alphabet() -> tuple[str, ...]:
    return tuple(vocabulary("verdicts")["alphabet"])


def _releasing() -> str:
    """The one member that releases at master (proceeds without a person)."""
    voc = vocabulary("verdicts")
    members = [k for k, v in voc["releases_at_master"].items() if v is True]
    if len(members) != 1 or members[0] not in voc["alphabet"]:
        raise LookupError("verdict vocabulary has no single releasing member")
    return members[0]


def _member(name: str) -> str:
    if name not in alphabet():
        raise LookupError(f"{name!r} is not in the verdict alphabet")
    return name


def _held() -> str:
    return _member("human")


def _refused() -> str:
    return _member("refused")


def action_verdicts() -> dict[str, str]:
    """Lock decision action → verdict. ``allow``, ``minimise``, ``strip`` and
    ``redact`` proceed (acted, possibly with redaction); ``ask_user`` waits for
    a person; ``refuse`` is refused."""
    auto, human, refused = _releasing(), _held(), _refused()
    return {
        "allow": auto,
        "minimise": auto,
        "strip": auto,
        "redact": auto,
        "ask_user": human,
        "refuse": refused,
    }


def verdict_for_action(action: str | None) -> str:
    """An unrecognised action is held for a person (fail-safe), never released."""
    return action_verdicts().get((action or "").strip().lower(), _held())


def oversight_verdicts() -> dict[OversightLevel, str]:
    """Oversight level → verdict: the two silent levels release; every level
    that asks or waits for a person is held."""
    auto, human = _releasing(), _held()
    return {
        OversightLevel.AUTONOMOUS: auto,
        OversightLevel.NOTIFY: auto,
        OversightLevel.REVIEW: human,
        OversightLevel.APPROVE: human,
        OversightLevel.SUPERVISED: human,
        OversightLevel.MANUAL: human,
    }


def verdict_for_oversight(level: OversightLevel) -> str:
    return oversight_verdicts()[OversightLevel(level)]
