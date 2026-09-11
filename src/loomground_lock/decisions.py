# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Persisted user-approval store.

When the lock refuses a piece of outgoing text and a person approves it, the
decision is persisted here so the next occurrence does not prompt again.

Schema (JSONL, default ``~/.config/agent-tool-lock/decisions.jsonl``)::

    {"ts": 1716130000, "pattern_hash": "sha256:...", "pattern_preview": "...",
     "decision": "allow" | "block", "scope": "once" | "session" | "always",
     "reason": "...", "session_id": "...", "actor": "..."}

Only ``pattern_hash`` is load-bearing; the preview is redacted, truncated to
80 chars, and never the full text. Local-only.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import unicodedata
import uuid
from dataclasses import dataclass
from pathlib import Path

# Compatibility constants — environment names a host may already rely on.
ENV_SESSION_ID = "AGENT_TOOL_LOCK_SESSION_ID"
ENV_DECISION_TTL_SECONDS = "AGENT_TOOL_LOCK_DECISION_TTL_SECONDS"

_DEFAULT_PATH = Path.home() / ".config" / "agent-tool-lock" / "decisions.jsonl"


def _hash_text(text: str) -> str:
    """SHA-256 of the NFC-normalised, stripped, lower-cased text. NFC keeps a
    decomposed variant of an approved string from bypassing an ``always`` block."""
    normalised = unicodedata.normalize("NFC", text).strip().lower().encode("utf-8")
    return "sha256:" + hashlib.sha256(normalised).hexdigest()


def _preview(text: str, n: int = 80) -> str:
    one_line = " ".join(text.split())
    return one_line[:n]


def _safe_preview(text: str, n: int = 80) -> str:
    """Redact the FULL text, then truncate — truncating first could split a
    secret into a fragment the redactor no longer matches. If redaction is
    unavailable, drop the preview (fail-closed)."""
    try:
        from .core import redact_for_capture
        redacted = redact_for_capture(text)
    except Exception:
        return ""
    return " ".join(redacted.split())[:n]


@dataclass
class StoredDecision:
    """One persisted user decision."""

    ts: float
    pattern_hash: str
    pattern_preview: str
    decision: str          # "allow" | "block"
    scope: str             # "once" | "session" | "always"
    reason: str
    session_id: str = ""
    actor: str = ""        # who recorded this clearance

    def to_jsonl(self) -> str:
        return json.dumps(
            {
                "ts": self.ts,
                "pattern_hash": self.pattern_hash,
                "pattern_preview": self.pattern_preview,
                "decision": self.decision,
                "scope": self.scope,
                "reason": self.reason,
                "session_id": self.session_id,
                "actor": self.actor,
            },
            ensure_ascii=False,
        )

    @classmethod
    def from_dict(cls, d: dict) -> "StoredDecision":
        return cls(
            ts=float(d.get("ts", 0.0)),
            pattern_hash=str(d.get("pattern_hash", "")),
            pattern_preview=str(d.get("pattern_preview", "")),
            decision=str(d.get("decision", "block")),
            scope=str(d.get("scope", "once")),
            reason=str(d.get("reason", "")),
            session_id=str(d.get("session_id", "")),
            actor=str(d.get("actor", "")),
        )


class DecisionsStore:
    """Append-only JSONL of user decisions, indexed in memory by ``pattern_hash``.

    Session-scoped decisions match only within the same ``session_id``.
    """

    #: ALLOW clearances expire after 90 days by default; BLOCK never expires
    #: (a lapsing block would fail open).
    _DEFAULT_TTL_SECONDS = 90 * 24 * 3600

    def __init__(
        self,
        path: str | Path | None = None,
        *,
        session_id: str | None = None,
        ttl_seconds: float | None = None,
    ):
        self.path = Path(path) if path else _DEFAULT_PATH
        self.session_id = session_id or os.environ.get(ENV_SESSION_ID) or str(uuid.uuid4())
        if ttl_seconds is None:
            env_ttl = os.environ.get(ENV_DECISION_TTL_SECONDS, "").strip()
            try:
                ttl_seconds = float(env_ttl) if env_ttl else self._DEFAULT_TTL_SECONDS
            except ValueError:
                ttl_seconds = self._DEFAULT_TTL_SECONDS
        self.ttl_seconds = ttl_seconds
        self._by_hash: dict[str, list[StoredDecision]] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            for raw in self.path.read_text(encoding="utf-8").splitlines():
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    obj = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                d = StoredDecision.from_dict(obj)
                self._by_hash.setdefault(d.pattern_hash, []).append(d)
        except OSError:
            return

    def _live(self, d: "StoredDecision", now: float) -> bool:
        if d.decision == "block":
            return True
        if self.ttl_seconds and self.ttl_seconds > 0 and (now - d.ts) > self.ttl_seconds:
            return False
        return True

    def recall(self, text: str, *, now: float | None = None) -> str | None:
        """``"allow"`` / ``"block"`` if a prior decision applies, else ``None``.

        ``always`` outranks ``session``; ``once`` is informational. Within the
        strongest matching scope, block wins over allow regardless of recency.
        Expired allows are ignored; blocks never expire.
        """
        candidates = self._by_hash.get(_hash_text(text))
        if not candidates:
            return None
        now = now if now is not None else time.time()

        always: list[StoredDecision] = []
        session: list[StoredDecision] = []
        for d in candidates:
            if not self._live(d, now):
                continue
            if d.scope == "always":
                always.append(d)
            elif d.scope == "session" and d.session_id == self.session_id:
                session.append(d)

        for tier in (always, session):
            if tier:
                if any(d.decision == "block" for d in tier):
                    return "block"
                return tier[-1].decision
        return None

    def remember(
        self,
        text: str,
        decision: str,
        *,
        scope: str = "once",
        reason: str = "",
        actor: str = "",
    ) -> StoredDecision:
        """Persist a decision. A durable ``always`` clearance needs a named
        ``actor`` (an anonymous "allow always" is rejected, fail-closed)."""
        if decision not in ("allow", "block"):
            raise ValueError(f"decision must be 'allow' or 'block', got: {decision!r}")
        if scope not in ("once", "session", "always"):
            raise ValueError(f"scope must be 'once'|'session'|'always', got: {scope!r}")
        if scope == "always" and not (actor or "").strip():
            raise ValueError("a persistent 'always' clearance needs a named actor")

        record = StoredDecision(
            ts=time.time(),
            pattern_hash=_hash_text(text),
            pattern_preview=_safe_preview(text),
            decision=decision,
            scope=scope,
            reason=reason,
            session_id=self.session_id if scope == "session" else "",
            actor=(actor or "").strip(),
        )

        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(record.to_jsonl() + "\n")

        self._by_hash.setdefault(record.pattern_hash, []).append(record)
        return record

    def all_decisions(self) -> list[StoredDecision]:
        out: list[StoredDecision] = []
        for records in self._by_hash.values():
            out.extend(records)
        return sorted(out, key=lambda d: d.ts)

    def _rewrite_previews(self, should_blank) -> int:
        """Blank ``pattern_preview`` where ``should_blank(obj)`` — in memory and
        on disk (tmp + replace). Unparseable lines are preserved verbatim."""
        matched = 0
        for records in self._by_hash.values():
            for d in records:
                if should_blank({"pattern_hash": d.pattern_hash,
                                 "pattern_preview": d.pattern_preview,
                                 "decision": d.decision, "scope": d.scope}):
                    d.pattern_preview = ""
                    matched += 1
        if not self.path.exists():
            return matched
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return matched
        out: list[str] = []
        for raw in lines:
            s = raw.strip()
            if not s:
                continue
            try:
                obj = json.loads(s)
            except json.JSONDecodeError:
                out.append(raw)
                continue
            if should_blank(obj):
                obj["pattern_preview"] = ""
            out.append(json.dumps(obj, ensure_ascii=False))
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        try:
            tmp.write_text(("\n".join(out) + "\n") if out else "", encoding="utf-8")
            tmp.replace(self.path)
        except OSError:
            try:
                if tmp.exists():
                    tmp.unlink()
            except OSError:
                pass
        return matched

    def erase(self, pattern_hash: str | None = None) -> int:
        """Blank the preview for one ``pattern_hash`` (or every record when None)."""
        return self._rewrite_previews(
            lambda o: pattern_hash is None or o.get("pattern_hash") == pattern_hash)

    def erase_subject(self, subject: str) -> int:
        """Blank any preview that still contains ``subject`` (case-insensitive)."""
        sub = (subject or "").strip().lower()
        if not sub:
            return 0
        return self._rewrite_previews(
            lambda o: sub in str(o.get("pattern_preview", "")).lower())
