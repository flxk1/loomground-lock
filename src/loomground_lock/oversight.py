# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Six-level oversight dial. Effective level = strictest of (user default,
operation floor, privacy-class default).

| # | Level      | Behaviour                          | When the person is asked |
|---|------------|------------------------------------|--------------------------|
| 1 | autonomous | plans + executes silently          | never                    |
| 2 | notify     | executes; surfaces a summary       | post-execution           |
| 3 | review     | executes; waits before final       | before authoritative     |
| 4 | approve    | halts before a side-effect op      | before execution         |
| 5 | supervised | step-by-step at every node         | at every node            |
| 6 | manual     | suggests; the person executes      | always                   |
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class OversightLevel(IntEnum):
    """Lower = more autonomous, higher = more person-in-the-loop."""

    AUTONOMOUS = 1
    NOTIFY = 2
    REVIEW = 3
    APPROVE = 4
    SUPERVISED = 5
    MANUAL = 6

    @property
    def label(self) -> str:
        return self.name.lower()

    @property
    def description(self) -> str:
        return _DESCRIPTIONS[self]


_DESCRIPTIONS = {
    OversightLevel.AUTONOMOUS: "Plans + executes silently; user sees result only",
    OversightLevel.NOTIFY: "Executes; surfaces a notification with summary",
    OversightLevel.REVIEW: "Executes; waits before result is final until user reviews",
    OversightLevel.APPROVE: "Halts before any side-effect op; resumes on approval",
    OversightLevel.SUPERVISED: "Step-by-step; user confirms at every finding/decision",
    OversightLevel.MANUAL: "Suggests, user executes manually; the agent does not execute",
}


PRIVACY_CLASS_DEFAULTS = {
    "public": OversightLevel.NOTIFY,
    "pseudonymous": OversightLevel.REVIEW,
    "sensitive": OversightLevel.APPROVE,
    "regulated": OversightLevel.SUPERVISED,
}


# Lock Mode → oversight level (rough correspondence; the two coexist).
MODE_TO_OVERSIGHT = {
    "audit_only": OversightLevel.NOTIFY,
    "permissive": OversightLevel.NOTIFY,
    "standard": OversightLevel.APPROVE,
    "strict": OversightLevel.SUPERVISED,
}


@dataclass
class OversightDecision:
    """One user decision on one finding under the dial."""

    finding_id: str
    user_action: str  # "accept" | "reject" | "edit" | "waive" | "skip"
    reason: str = ""
    elapsed_ms: int = 0


def effective_level(
    *,
    user_default: OversightLevel,
    op_floor: OversightLevel | None = None,
    privacy_class: str | None = None,
) -> OversightLevel:
    """STRICTEST wins: a user may tighten, never loosen below the operation
    floor or the privacy class default."""
    candidates = [user_default]
    if op_floor is not None:
        candidates.append(op_floor)
    if privacy_class in PRIVACY_CLASS_DEFAULTS:
        candidates.append(PRIVACY_CLASS_DEFAULTS[privacy_class])
    return max(candidates)


def asks_user_per_finding(level: OversightLevel) -> bool:
    return level in (OversightLevel.SUPERVISED, OversightLevel.MANUAL)


def asks_user_per_plan(level: OversightLevel) -> bool:
    return level in (OversightLevel.APPROVE, OversightLevel.SUPERVISED, OversightLevel.MANUAL)


def waits_for_review_after_execution(level: OversightLevel) -> bool:
    return level == OversightLevel.REVIEW


def notifies_user_post_execution(level: OversightLevel) -> bool:
    return level == OversightLevel.NOTIFY
