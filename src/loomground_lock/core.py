# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Core middleware: modes, detectors, capability tokens, audit log, egress/ingress orchestration.

Tiers A (schema) and B (pattern) live here. Tier C (semantic) is a host hook on
:mod:`.host_deps`; Tier M (moderation) is :mod:`.tier_m`.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
import unicodedata
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Literal

from . import host_deps

# Compatibility constants — the environment names a host may already rely on.
ENV_STRICT_TOKEN_SIG = "LOCK_BETA_STRICT_TOKEN_SIG"
ENV_CAPABILITY_TRUST_STORE = "LOCK_CAPABILITY_TRUST_STORE"


# ===========================================================================
# Modes
# ===========================================================================


class Mode(Enum):
    STANDARD = "standard"      # strip + warn
    STRICT = "strict"           # block on violation
    PERMISSIVE = "permissive"   # detect only, never block or strip
    AUDIT_ONLY = "audit_only"   # record everything, mutate nothing


# ===========================================================================
# Data structures
# ===========================================================================


@dataclass
class CapabilityToken:
    """Capability claims plus an optional detached Ed25519 signature."""

    iss: str
    sub: str
    aud: str            # the tool this token authorises
    iat: int            # issued-at (unix seconds)
    exp: int            # expiry (unix seconds)
    scope: dict         # {regions, identifier_classes, retention_class, fields, purpose}
    controller: str
    task_id: str
    signature: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "CapabilityToken":
        claims = {k: d[k] for k in cls.__dataclass_fields__ if k != "signature"}
        return cls(**claims, signature=d.get("signature", ""))

    def signed_bytes(self) -> bytes:
        """Return the stable UTF-8 payload covered by ``signature``."""
        claims = asdict(self)
        claims.pop("signature", None)
        return json.dumps(
            claims, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")

    def sign(self, private_key: Any) -> None:
        """Attach a hex-encoded Ed25519 signature from an issuer key."""
        self.signature = private_key.sign(self.signed_bytes()).hex()


@dataclass
class ToolCall:
    tool: str
    arguments: dict
    capability_token: CapabilityToken | None = None


@dataclass
class ToolResponse:
    payload: dict


@dataclass
class RemediationAction:
    """A single user-actionable remediation attached to a Finding.

    ``kind`` is one of:
      - ``redact_and_retry``: payload carries a ``redacted_text`` the caller
        may re-submit in place of the original.
      - ``bypass_once``: payload sets ``acknowledgement_required = True`` so
        the surface knows to demand an explicit per-prompt ack before resend.
      - ``disable_lock``: payload is host-provided (``host_deps.disable_lock_remediation``):
        how the host lets a person opt out and where its disclaimer lives.
    """

    kind: Literal["redact_and_retry", "bypass_once", "disable_lock"]
    label: str
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    tier: str               # "A" | "B" | "B+" | "C" | "D" | "M"
    type: str               # "over_collection" | "pii_in_argument" | "pii_in_response" | "token_invalid" | ...
    severity: str           # "low" | "medium" | "high"
    field: str | None       # field name or None for whole-message findings
    detail: str
    confidence: float = 1.0
    remediation_actions: list[RemediationAction] = field(default_factory=list)

    @property
    def finding_id(self) -> str:
        """Stable identity, derived from what the finding says (so a decision
        recorded about one finding points at it across processes and reviews).
        ``remediation_actions`` is excluded: advice about the finding, not the finding."""
        parts = (self.tier, self.type, self.severity, self.field or "", self.detail)
        return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()[:16]


@dataclass
class EgressDecision:
    action: str             # "allow" | "strip" | "refuse"
    findings: list[Finding] = field(default_factory=list)
    modified_call: ToolCall | None = None
    stripped_fields: list[str] = field(default_factory=list)
    reason: str = ""


@dataclass
class IngressDecision:
    action: str             # "allow" | "redact"
    findings: list[Finding] = field(default_factory=list)
    redacted_payload: dict | None = None
    reason: str = ""


@dataclass
class TextDecision:
    """Approval decision for a single text/document/triple about to leave the local boundary.

    Action semantics:
        - "allow"    : pass as-is
        - "minimise" : pass `redacted_text` (pattern-matched spans replaced)
        - "refuse"   : do not send; caller must escalate to a person or abort
    """

    action: str             # "allow" | "minimise" | "refuse"
    findings: list[Finding] = field(default_factory=list)
    redacted_text: str | None = None
    reason: str = ""
    source: str = "document"   # "document" | "triple" | "freeform" — diagnostic only


# ===========================================================================
# Tier A — Schema-level minimisation
# ===========================================================================


def tier_a_check_arguments(arguments: dict, task_scope: set[str]) -> list[Finding]:
    """Tier A on egress — flag arguments that request fields not in the task scope."""
    findings: list[Finding] = []
    requested_fields = _flatten_argument_fields(arguments)
    over_collected = requested_fields - task_scope
    for f in sorted(over_collected):
        findings.append(
            Finding(
                tier="A",
                type="over_collection",
                severity="medium",
                field=f,
                detail=f"argument requests field '{f}' not in declared task scope",
            )
        )
    return findings


def tier_a_check_response(payload: dict, task_scope: set[str]) -> list[Finding]:
    """Tier A on ingress — flag response fields not in the task scope."""
    findings: list[Finding] = []
    returned_fields = set(payload.keys())
    over_returned = returned_fields - task_scope
    for f in sorted(over_returned):
        findings.append(
            Finding(
                tier="A",
                type="over_collection",
                severity="medium",
                field=f,
                detail=f"response field '{f}' not in declared task scope",
            )
        )
    return findings


def _flatten_argument_fields(arguments: dict, prefix: str = "") -> set[str]:
    """Return the set of dotted-path field names requested. Conservative: nested dicts expanded."""
    fields: set[str] = set()
    for k, v in arguments.items():
        path = f"{prefix}{k}" if not prefix else f"{prefix}.{k}"
        fields.add(path)
        if isinstance(v, dict):
            fields |= _flatten_argument_fields(v, path)
    return fields


# ===========================================================================
# Tier B — Regex / dictionary detection
# ===========================================================================


# Conservative regexes. Tuned for low false positives on workplace-agent data.
# Covers 12 PII shapes including Luhn-validated credit-card and high-entropy
# API keys / bearer tokens, plus the government-ID / medical groups below.

_EMAIL_RE   = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE_RE   = re.compile(r"(?:\+?\d{1,3}[\s.-]?)?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}")
_IBAN_RE    = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b")
_US_SSN_RE  = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
# Back-compat alias — older callers used _NATIONAL_ID_RE before the rename.
_NATIONAL_ID_RE = _US_SSN_RE

# URL with embedded credentials (scheme://user:pass@host).
_URL_CREDS_RE = re.compile(
    r"(?P<scheme>[a-z]{2,10})://[^/\s:@]+:[^/\s@]+@[^\s]+"
)

# Bearer tokens (after literal "Bearer " keyword).
_BEARER_RE = re.compile(
    r"(?<=\bBearer )[A-Za-z0-9._\-/+=]{16,}"
)

# Known API-key prefixes (Stripe, GitHub, OpenAI, AWS, Google, Slack, HF).
_API_KEY_RE = re.compile(
    r"\b(?:sk_(?:live|test)_|sk-|ghp_|github_pat_|xox[baprs]-|"
    r"AIza|AKIA|ASIA|EAA|hf_)[A-Za-z0-9_\-]{10,}\b"
)

# IP addresses.
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")

# UK NINO (National Insurance Number).
_UK_NINO_RE = re.compile(
    r"\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b"
)

# DE Personalausweis (ID-card serial; new format).
_DE_PERS_RE = re.compile(r"\b[CFGHJK]\w{8}\b")

# Credit-card candidate — accepted only if Luhn checksum validates.
_CC_CANDIDATE_RE = re.compile(r"\b(?:\d[ \-]?){13,19}\b")

# Names in possessive context — title + capitalised name + apostrophe-s.
_NAME_POSSESSIVE_RE = re.compile(
    r"\b(?:Mr|Mrs|Ms|Mx|Dr|Prof|Professor|Sir|Madam|Lady|Lord|Rev|Fr|"
    r"Herr|Frau|Sr|Sra|Sgt|Capt|Lt|Col|Gen|Hon)\.?\s+"
    r"(?:[A-ZÄÖÜÅÉÈÊÁÀÆØ][\w'’\-]+\s*){1,4}"
    r"[’']s\b"
)

# German Steuer-ID — 11 digits, optionally grouped.
_DE_STEUER_ID_RE = re.compile(r"\b\d{2}\s?\d{3}\s?\d{3}\s?\d{3}\b")

# German Personalausweis number (10-char layout).
_DE_PERSONALAUSWEIS_10_RE = re.compile(
    r"\b[CFGHJKLMNPRTVWXYZ][0-9A-Z]{9}\b"
)

# Spanish DNI / NIE.
_ES_DNI_NIE_RE = re.compile(
    r"\b(?:\d{8}|[XYZ]\d{7})[A-HJ-NP-TV-Z]\b"
)

# French INSEE / SSN — 15 digits with the documented structure.
_FR_SSN_RE = re.compile(
    r"\b[12]\s?\d{2}\s?(?:0\d|1[0-2])\s?\d{2}\s?\d{3}\s?\d{3}\s?\d{2}\b"
)

# Patient/case ID.
_PATIENT_CASE_ID_RE = re.compile(
    r"\b(?:patient|case|client)\s*(?:#|id|number|no\.?)\s*\d{3,10}\b",
    re.IGNORECASE,
)

# Medical Record Number.
_MRN_RE = re.compile(
    r"\bMRN\s*[:#-]?\s*[A-Z0-9-]{4,15}\b",
    re.IGNORECASE,
)

# ICD-10 codes — letter + 2 digits + optional .NN extension.
_ICD10_RE = re.compile(r"\b[A-TV-Z]\d{2}(?:\.\d{1,3})?\b")

# IBAN with per-country length (EBA structure).
_IBAN_FULL_RE = re.compile(
    r"\b(?:"
    r"AT\d{2}[0-9]{16}|"          # Austria
    r"BE\d{2}[0-9]{12}|"          # Belgium
    r"BG\d{2}[A-Z]{4}[0-9]{6}[A-Z0-9]{8}|"  # Bulgaria
    r"CH\d{2}[0-9]{5}[A-Z0-9]{12}|"          # Switzerland
    r"CZ\d{2}[0-9]{20}|"          # Czechia
    r"DE\d{2}[0-9]{18}|"          # Germany
    r"DK\d{2}[0-9]{14}|"          # Denmark
    r"ES\d{2}[0-9]{20}|"          # Spain
    r"FI\d{2}[0-9]{14}|"          # Finland
    r"FR\d{2}[0-9]{10}[A-Z0-9]{11}[0-9]{2}|"  # France
    r"GB\d{2}[A-Z]{4}[0-9]{14}|"  # United Kingdom
    r"IE\d{2}[A-Z]{4}[0-9]{14}|"  # Ireland
    r"IT\d{2}[A-Z][0-9]{10}[A-Z0-9]{12}|"     # Italy
    r"LU\d{2}[0-9]{3}[A-Z0-9]{13}|"            # Luxembourg
    r"NL\d{2}[A-Z]{4}[0-9]{10}|"  # Netherlands
    r"PL\d{2}[0-9]{24}|"          # Poland
    r"PT\d{2}[0-9]{21}|"          # Portugal
    r"SE\d{2}[0-9]{20}"           # Sweden
    r")\b"
)


def _luhn_ok(digits_only: str) -> bool:
    """Standard Luhn checksum. Gates credit_card matches so 13-19 digit
    strings that aren't card numbers (timestamps, order IDs) don't redact."""
    if not digits_only.isdigit() or not (13 <= len(digits_only) <= 19):
        return False
    total = 0
    parity = len(digits_only) % 2
    for i, ch in enumerate(digits_only):
        d = int(ch)
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _cc_search(text: str):
    """Find a credit-card candidate that passes Luhn. Returns the Match or None."""
    for m in _CC_CANDIDATE_RE.finditer(text):
        digits = re.sub(r"[ \-]", "", m.group(0))
        if _luhn_ok(digits):
            return m
    return None


# Pattern table — order = match priority. More specific patterns first.
_TIER_B_PATTERNS: list[tuple[str, "object", float]] = [
    ("url_with_creds",      _URL_CREDS_RE,            0.98),
    ("api_key",             _API_KEY_RE,              0.95),
    ("bearer_token",        _BEARER_RE,               0.92),
    ("email",               _EMAIL_RE,                0.90),
    ("us_ssn",              _US_SSN_RE,               0.95),
    ("uk_nino",             _UK_NINO_RE,              0.95),
    ("iban_full",           _IBAN_FULL_RE,            0.97),
    ("fr_ssn",              _FR_SSN_RE,               0.95),
    ("de_steuer_id",        _DE_STEUER_ID_RE,         0.90),
    ("es_dni_nie",          _ES_DNI_NIE_RE,           0.93),
    ("de_personalausweis_10", _DE_PERSONALAUSWEIS_10_RE, 0.85),
    ("de_personnummer",     _DE_PERS_RE,              0.85),
    ("iban",                _IBAN_RE,                 0.95),
    ("credit_card",         _cc_search,               0.95),   # callable, Luhn-gated
    ("ipv6",                _IPV6_RE,                 0.90),
    ("ipv4",                _IPV4_RE,                 0.85),
    ("mrn",                 _MRN_RE,                  0.92),
    ("patient_case_id",     _PATIENT_CASE_ID_RE,      0.85),
    ("icd10",               _ICD10_RE,                0.75),
    ("name_possessive",     _NAME_POSSESSIVE_RE,      0.80),
    ("phone",               _PHONE_RE,                0.85),
]

_LABEL_REGEX = {label: rx for label, rx, _ in _TIER_B_PATTERNS if hasattr(rx, "sub")}


def _redact_for_label(text: str, label: str, placeholder: str | None = None) -> str:
    """Replace matches of the named pattern with ``[REDACTED:<label>]`` (or ``placeholder``)."""
    if placeholder is None:
        placeholder = f"[REDACTED:{label}]"
    if label == "credit_card":
        out = text
        while True:
            m = _cc_search(out)
            if m is None:
                break
            out = out[:m.start()] + placeholder + out[m.end():]
        return out
    rx = _LABEL_REGEX.get(label)
    if rx is None:
        return text
    return rx.sub(placeholder, text)


def _disable_lock_payload() -> dict[str, Any]:
    host_deps.ensure_wired()
    hook = host_deps.disable_lock_remediation
    if hook is not None:
        try:
            payload = hook()
            if isinstance(payload, dict):
                return dict(payload)
        except Exception:
            pass
    return {"acknowledgement_required": True, "disclaimer_required": True}


def _build_remediation_actions(
    finding: Finding,
    original_text: str,
) -> list[RemediationAction]:
    """The canonical three-action remediation block, in stable order."""
    label = ""
    detail = finding.detail or ""
    marker = "regex matched pattern: "
    if marker in detail:
        label = detail.split(marker, 1)[1].strip()

    if label:
        redacted = _redact_for_label(original_text, label)
    else:
        redacted = _redact_text_with_regex(original_text)

    return [
        RemediationAction(
            kind="redact_and_retry",
            label="Redact this and try again",
            payload={"redacted_text": redacted},
        ),
        RemediationAction(
            kind="bypass_once",
            label="Send anyway (this one prompt, this session)",
            payload={"acknowledgement_required": True},
        ),
        RemediationAction(
            kind="disable_lock",
            label="Disable lock for this folder (requires disclaimer)",
            payload=_disable_lock_payload(),
        ),
    ]


def tier_b_scan_text(text: str) -> list[Finding]:
    """Tier B regex scan. Returns findings keyed by pattern type, each carrying
    a remediation block. Canonical-form only: obfuscated PII is escalated by
    Tier B+ rather than normalised away here."""
    findings: list[Finding] = []
    for label, matcher, conf in _TIER_B_PATTERNS:
        hit = matcher.search(text) if hasattr(matcher, "search") else matcher(text)
        if hit:
            f = Finding(
                tier="B",
                type="pii_in_argument",   # reused for both directions
                severity="high",
                field=None,
                detail=f"regex matched pattern: {label}",
                confidence=conf,
            )
            f.remediation_actions = _build_remediation_actions(f, text)
            findings.append(f)
    return findings


def tier_b_scan_dict(data: dict) -> list[Finding]:
    """Recursively scan free-text values in a dict."""
    findings: list[Finding] = []
    for key, value in data.items():
        if isinstance(value, str):
            for f in tier_b_scan_text(value):
                f.field = key
                findings.append(f)
        elif isinstance(value, dict):
            findings.extend(tier_b_scan_dict(value))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    findings.extend(tier_b_scan_dict(item))
                elif isinstance(item, str):
                    for f in tier_b_scan_text(item):
                        f.field = key
                        findings.append(f)
    return findings


# ===========================================================================
# Capability-token validation
# ===========================================================================


@dataclass
class TokenValidation:
    valid: bool
    findings: list[Finding] = field(default_factory=list)


def validate_token(token: CapabilityToken | None, call: ToolCall) -> TokenValidation:
    """Validate capability-token claims against the call.

    Semantic validation (exp, aud) is always enforced. When
    ``LOCK_BETA_STRICT_TOKEN_SIG=1``, the detached Ed25519 signature must
    verify against the issuer's key in ``LOCK_CAPABILITY_TRUST_STORE``.
    """
    findings: list[Finding] = []
    if token is None:
        findings.append(
            Finding(
                tier="A",
                type="token_invalid",
                severity="low",
                field=None,
                detail="no capability token attached; falling back to inferred scope",
            )
        )
        return TokenValidation(valid=False, findings=findings)

    if os.environ.get(ENV_STRICT_TOKEN_SIG) == "1":
        verified, reason = _verify_capability_signature(token)
        if not verified:
            findings.append(Finding(
                tier="A", type="token_invalid", severity="high", field=None,
                detail=f"strict-token-sig mode: {reason}",
            ))
            return TokenValidation(valid=False, findings=findings)

    now = int(time.time())
    if token.exp <= now:
        findings.append(
            Finding(
                tier="A",
                type="token_invalid",
                severity="high",
                field=None,
                detail=f"token expired at {token.exp}; now {now}",
            )
        )
        return TokenValidation(valid=False, findings=findings)

    if token.aud != call.tool:
        findings.append(
            Finding(
                tier="A",
                type="token_invalid",
                severity="high",
                field=None,
                detail=f"token audience '{token.aud}' does not match tool '{call.tool}'",
            )
        )
        return TokenValidation(valid=False, findings=findings)

    return TokenValidation(valid=True)


def _verify_capability_signature(token: CapabilityToken) -> tuple[bool, str]:
    """Verify a token using the operator-owned issuer trust store."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    store_path = os.environ.get(ENV_CAPABILITY_TRUST_STORE)
    if not store_path:
        return False, f"{ENV_CAPABILITY_TRUST_STORE} is not configured"
    try:
        store = json.loads(Path(store_path).read_text(encoding="utf-8"))
        pem = store[token.iss]
        if not isinstance(pem, str):
            raise TypeError("issuer key is not text")
        public_key = serialization.load_pem_public_key(pem.encode("utf-8"))
        if not isinstance(public_key, Ed25519PublicKey):
            return False, f"trusted key for issuer '{token.iss}' is not Ed25519"
        public_key.verify(bytes.fromhex(token.signature), token.signed_bytes())
        return True, ""
    except KeyError:
        return False, f"issuer '{token.iss}' is not trusted"
    except FileNotFoundError:
        return False, "capability trust store does not exist"
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        return False, "capability trust store or signature is malformed"
    except InvalidSignature:
        return False, "capability signature is invalid"


# ===========================================================================
# Audit log
# ===========================================================================


class AuditLog:
    """JSONL appender. Records schemas + decisions, NOT raw values."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _append(self, entry: dict) -> None:
        with self.path.open("a") as fh:
            fh.write(json.dumps(entry) + "\n")

    def write_egress(
        self,
        call: ToolCall,
        decision: EgressDecision,
        mode: Mode,
        task_id: str | None = None,
    ):
        self._append({
            "ts": time.time(),
            "kind": "egress",
            "tool": call.tool,
            "argument_schema": sorted(_flatten_argument_fields(call.arguments)),
            "action": decision.action,
            "findings_count": len(decision.findings),
            "findings": [_finding_summary(f) for f in decision.findings],
            "stripped_fields": decision.stripped_fields,
            "mode": mode.value,
            "task_id": task_id,
            "audit_id": str(uuid.uuid4()),
        })

    def write_ingress(
        self,
        response: ToolResponse,
        decision: IngressDecision,
        mode: Mode,
        task_id: str | None = None,
    ):
        self._append({
            "ts": time.time(),
            "kind": "ingress",
            "response_schema": sorted(response.payload.keys()),
            "action": decision.action,
            "findings_count": len(decision.findings),
            "findings": [_finding_summary(f) for f in decision.findings],
            "mode": mode.value,
            "task_id": task_id,
            "audit_id": str(uuid.uuid4()),
        })

    def write_text(
        self,
        text_length: int,
        decision: "TextDecision",
        mode: Mode,
        task_id: str | None = None,
    ):
        """Audit a lock_text() decision. Records length + decision, NEVER raw text."""
        self._append({
            "ts": time.time(),
            "kind": "text",
            "source": decision.source,
            "text_length": text_length,
            "action": decision.action,
            "findings_count": len(decision.findings),
            "findings": [_finding_summary(f) for f in decision.findings],
            "mode": mode.value,
            "task_id": task_id,
            "audit_id": str(uuid.uuid4()),
        })

    def write_bypass(
        self,
        would_have: str,
        decision: "TextDecision",
        *,
        oversight: Any = None,
        final_action: str = "",
        source: str = "document",
        reason: str = "",
        task_id: str | None = None,
    ):
        """Audit a lock-OFF bypass: what the gate would have done, the oversight
        level, and the final action. Off disables enforcement, never the audit
        trail. NEVER raw text."""
        if would_have not in ("refuse", "minimise"):
            raise ValueError(
                f"would_have must be 'refuse' or 'minimise', got: {would_have!r}")
        self._append({
            "ts": time.time(),
            "kind": "lock_bypass",
            "source": source,
            "would_have": would_have,
            "oversight": getattr(oversight, "label", None) or (
                str(oversight) if oversight is not None else ""),
            "final_action": final_action,
            "findings_count": len(decision.findings),
            "findings": [_finding_summary(f) for f in decision.findings],
            "reason": reason,
            "task_id": task_id,
            "audit_id": str(uuid.uuid4()),
        })


def _finding_summary(f: Finding) -> dict:
    return {
        "tier": f.tier,
        "type": f.type,
        "severity": f.severity,
        "field": f.field,
        "confidence": f.confidence,
    }


# ===========================================================================
# Egress / Ingress orchestration
# ===========================================================================


def egress(
    call: ToolCall,
    task_scope: set[str],
    tool_schema: dict | None = None,
    mode: Mode = Mode.STANDARD,
    audit: AuditLog | None = None,
) -> EgressDecision:
    """Pre-call middleware. Returns EgressDecision describing allow/strip/refuse + findings."""
    all_findings: list[Finding] = []

    tier_a = tier_a_check_arguments(call.arguments, task_scope)
    all_findings.extend(tier_a)

    tier_b = tier_b_scan_dict(call.arguments)
    all_findings.extend(tier_b)

    token_check = validate_token(call.capability_token, call)
    all_findings.extend(token_check.findings)

    decision = _decide_egress(call, task_scope, tier_a, all_findings, mode)

    if audit is not None:
        task_id = call.capability_token.task_id if call.capability_token else None
        audit.write_egress(call, decision, mode, task_id=task_id)

    return decision


def _decide_egress(
    call: ToolCall,
    task_scope: set[str],
    over_collection_findings: list[Finding],
    all_findings: list[Finding],
    mode: Mode,
) -> EgressDecision:
    has_high = any(f.severity == "high" for f in all_findings)
    has_over_collection = bool(over_collection_findings)

    if mode == Mode.AUDIT_ONLY:
        return EgressDecision(
            action="allow",
            findings=all_findings,
            modified_call=None,
            reason="audit-only mode: detect, do not mutate",
        )

    if mode == Mode.PERMISSIVE:
        return EgressDecision(
            action="allow",
            findings=all_findings,
            modified_call=None,
            reason="permissive mode: warn but allow",
        )

    if mode == Mode.STRICT:
        if has_high or has_over_collection:
            return EgressDecision(
                action="refuse",
                findings=all_findings,
                modified_call=None,
                reason=f"strict mode: {len(over_collection_findings)} over-collection findings; {sum(1 for f in all_findings if f.severity=='high')} high-severity findings",
            )
        return EgressDecision(action="allow", findings=all_findings)

    # STANDARD — strip over-collection, warn on the rest
    if has_over_collection:
        stripped_fields = [f.field for f in over_collection_findings if f.field is not None]
        modified_args = {k: v for k, v in call.arguments.items() if k not in stripped_fields}
        modified_call = ToolCall(
            tool=call.tool,
            arguments=modified_args,
            capability_token=call.capability_token,
        )
        return EgressDecision(
            action="strip",
            findings=all_findings,
            modified_call=modified_call,
            stripped_fields=stripped_fields,
            reason=f"standard mode: stripped {len(stripped_fields)} over-collected field(s)",
        )

    return EgressDecision(action="allow", findings=all_findings)


def ingress(
    response: ToolResponse,
    task_scope: set[str],
    tool_schema: dict | None = None,
    mode: Mode = Mode.STANDARD,
    audit: AuditLog | None = None,
    task_id: str | None = None,
) -> IngressDecision:
    """Post-call middleware. Returns IngressDecision with optional redacted_payload."""
    all_findings: list[Finding] = []

    tier_a = tier_a_check_response(response.payload, task_scope)
    all_findings.extend(tier_a)

    tier_b = tier_b_scan_dict(response.payload)
    for f in tier_b:
        f.type = "pii_in_response"
    all_findings.extend(tier_b)

    decision = _decide_ingress(response, task_scope, tier_a, all_findings, mode)

    if audit is not None:
        audit.write_ingress(response, decision, mode, task_id=task_id)

    return decision


def _decide_ingress(
    response: ToolResponse,
    task_scope: set[str],
    over_return_findings: list[Finding],
    all_findings: list[Finding],
    mode: Mode,
) -> IngressDecision:
    if mode == Mode.AUDIT_ONLY:
        return IngressDecision(action="allow", findings=all_findings, redacted_payload=None, reason="audit-only")

    if mode == Mode.PERMISSIVE:
        return IngressDecision(action="allow", findings=all_findings, redacted_payload=None, reason="permissive")

    # STANDARD and STRICT both redact over-returns + high-severity findings. This
    # captures every high-severity finding ONLY because every ingress finding
    # carries a field (tier_a_check_response sets it; tier_b_scan_dict sets
    # f.field = key). The ingress-invariant test pins that.
    redacted = dict(response.payload)
    fields_to_redact = {f.field for f in over_return_findings if f.field is not None}
    fields_to_redact |= {f.field for f in all_findings if f.severity == "high" and f.field is not None}

    if fields_to_redact:
        for f in fields_to_redact:
            if f in redacted:
                redacted[f] = "[REDACTED]"
        return IngressDecision(
            action="redact",
            findings=all_findings,
            redacted_payload=redacted,
            reason=f"redacted {len(fields_to_redact)} field(s)",
        )

    return IngressDecision(action="allow", findings=all_findings, redacted_payload=None)


# ===========================================================================
# lock_text — document / triple approval surface
# ===========================================================================

# Confusable code points folded to ASCII when no transliterator is installed.
# Cyrillic and Greek lookalikes, plus the fullwidth Latin block (handled by NFKC).
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
    "ј": "j", "ѕ": "s", "һ": "h", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ɡ": "g", "ⅼ": "l",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P",
    "С": "C", "Т": "T", "Х": "X", "Ѕ": "S", "І": "I", "Ј": "J", "Ү": "Y", "Ԛ": "Q",
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "τ": "t", "ι": "i", "κ": "k", "υ": "u",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M",
    "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    "​": "", "‌": "", "‍": "", "⁠": "", "﻿": "",
})


def _ascii_fold(text: str) -> str:
    """Fold ``text`` towards ASCII. Uses ``anyascii`` when installed; otherwise
    NFKC + confusable substitution + combining-mark stripping. Always runs, so
    the confusable control never depends on an optional package."""
    try:
        from anyascii import anyascii
        return anyascii(text)
    except ImportError:
        pass
    folded = unicodedata.normalize("NFKC", text).translate(_CONFUSABLES)
    folded = unicodedata.normalize("NFKD", folded)
    return "".join(ch for ch in folded if not unicodedata.combining(ch))


def _detect_confusable_bypass(text: str) -> list[Finding]:
    """Tier B+ — confusable-Unicode bypass detection.

    Runs Tier B against the ASCII-folded text too. A PII match present in the
    folded version but absent in the original is an attempted homoglyph bypass
    → one aggregate high-severity finding. Legitimate international text stays
    clean because the folded text is searched for PII patterns, not for the
    differing characters themselves.
    """
    folded = _ascii_fold(text)
    if folded == text:
        return []

    findings_original = set((f.type, f.detail) for f in tier_b_scan_text(text))
    findings_folded = tier_b_scan_text(folded)
    bypass_findings = [
        f for f in findings_folded
        if (f.type, f.detail) not in findings_original
    ]
    if not bypass_findings:
        return []

    f = Finding(
        tier="B+",
        type="confusable_bypass",
        severity="high",
        field="",
        detail=(f"Confusable-Unicode bypass detected: "
                f"{len(bypass_findings)} PII pattern(s) hidden behind "
                f"homoglyph substitution. Examples: "
                + ", ".join(sorted({f.type for f in bypass_findings})[:3])),
        confidence=0.95,
    )
    f.remediation_actions = _build_remediation_actions(f, text)
    # The safe retry is the folded text with spans replaced (neutralises the bypass).
    f.remediation_actions[0].payload["redacted_text"] = _redact_text_with_regex(folded)
    return [f]


def _context_terms(context: str) -> list[str]:
    terms: list[str] = []
    for line in (context or "").splitlines():
        term = line.strip().lstrip("-*•").strip()
        if term and len(term) >= 3:
            terms.append(term)
    return terms


def tier_c_unavailable_finding(detail: str) -> Finding:
    """High-severity, fail-closed: the configured semantic check could not run."""
    return Finding(
        tier="C",
        type="tier_c_unavailable",
        severity="high",
        field=None,
        detail=f"Tier-C semantic check could not run — failing closed: {detail}",
        confidence=1.0,
    )


def tier_c_context_terms_check(text: str, context: str = "") -> list[Finding]:
    """Deterministic Tier C: a confidential term supplied in ``context`` that
    appears in ``text`` is a high-severity finding. Runs on every path, wired or
    not, beside the semantic part (:mod:`loomground_lock.tier_c_default` or the
    host's hook)."""
    if not text.strip():
        return []
    low = text.lower()
    for term in _context_terms(context):
        if term.lower() in low:
            return [Finding(
                tier="C",
                type="pii_in_argument",
                severity="high",
                field=None,
                detail="semantic classifier flagged confidential: matched a confidential term from context",
                confidence=0.95,
            )]
    return []


def _tier_c_required() -> bool:
    """Whether the host has promised a real semantic backend, so a Tier C that
    cannot run must fail closed. Consulted on every path, not only when a
    semantic hook is wired. A predicate that raises counts as a promise."""
    requires = host_deps.tier_c_requires_real_backend
    if requires is None:
        return False
    try:
        return bool(requires())
    except Exception:  # noqa: BLE001
        return True


def _tier_c(text: str, context: str) -> list[Finding]:
    """Tier C composition, in three parts:

    1. ``tier_c_context_terms_check`` — confidential terms from ``context``.
    2. The host's ``tier_c_check_semantic`` hook when wired and usable; else the
       package's own :func:`tier_c_default.tier_c_default_check`, so the
       semantic tier runs with nothing wired rather than being skipped.
    3. When the semantic hook could not run and the host promised a real backend
       — or its wiring provider raised, leaving what it wired unknown — a
       high-severity ``tier_c_unavailable`` finding, which refuses.
    """
    findings = tier_c_context_terms_check(text, context)
    host_deps.ensure_wired()
    semantic = host_deps.tier_c_check_semantic
    broken_wiring = host_deps.wiring_error()

    unavailable: str | None = None
    if broken_wiring is not None:
        unavailable = f"host wiring provider raised ({broken_wiring})"
    elif semantic is None:
        unavailable = "no tier_c_check_semantic hook is wired"
    else:
        try:
            extra = semantic(text, context=context)
            if not isinstance(extra, list):
                raise TypeError("semantic hook returned a non-list")
            findings.extend(extra)
            return findings
        except Exception as e:  # noqa: BLE001
            # class name only — never str(e) (may carry paths/scanned text).
            unavailable = f"Tier-C layer crashed ({type(e).__name__})"

    from .tier_c_default import tier_c_default_check
    findings.extend(tier_c_default_check(text, context))
    if broken_wiring is not None or _tier_c_required():
        findings.append(tier_c_unavailable_finding(unavailable))
    return findings


def lock_text(
    text: str,
    *,
    context: str = "",
    mode: Mode = Mode.STANDARD,
    audit: AuditLog | None = None,
    source: str = "document",
    task_id: str | None = None,
    moderation_rules: dict | None = None,
) -> TextDecision:
    """Pre-egress middleware for arbitrary text/document/triple content.

    Runs Tier B (regex) + Tier B+ (confusable-bypass) + Tier C (context terms,
    then the host's semantic hook or the built-in default tier in its place) +
    Tier M (moderation, only when ``moderation_rules`` is supplied). Returns a
    TextDecision: allow as-is, minimise (pattern spans redacted), or refuse.

    ``mode``: STANDARD (high-severity refuses, medium minimises) | STRICT (any
    finding refuses) | PERMISSIVE / AUDIT_ONLY (findings recorded, never enforced).
    """
    findings: list[Finding] = []

    findings.extend(tier_b_scan_text(text))
    findings.extend(_detect_confusable_bypass(text))
    findings.extend(_tier_c(text, context))

    if moderation_rules:
        try:
            from .tier_m import tier_m_check_moderation
            findings.extend(tier_m_check_moderation(text, rules=moderation_rules))
        except Exception as e:  # noqa: BLE001
            try:
                from .tier_m import tier_m_requires_real_backend, tier_m_unavailable_finding
                if tier_m_requires_real_backend(moderation_rules):
                    findings.append(tier_m_unavailable_finding(
                        f"Tier-M layer crashed ({type(e).__name__})"))
            except Exception:
                pass

    decision = _decide_text(findings, text, mode, source)

    if audit is not None:
        audit.write_text(len(text), decision, mode, task_id=task_id)

    return decision


def _decide_text(
    findings: list[Finding],
    text: str,
    mode: Mode,
    source: str,
) -> TextDecision:
    has_high = any(f.severity == "high" for f in findings)
    has_findings = bool(findings)

    if mode == Mode.AUDIT_ONLY:
        return TextDecision(
            action="allow",
            findings=findings,
            reason="audit-only mode — recording only",
            source=source,
        )

    if mode == Mode.PERMISSIVE:
        return TextDecision(
            action="allow",
            findings=findings,
            reason="permissive mode — findings recorded, not enforced",
            source=source,
        )

    if not has_findings:
        return TextDecision(action="allow", findings=[], source=source)

    if mode == Mode.STRICT:
        return TextDecision(
            action="refuse",
            findings=findings,
            reason="strict mode: any finding blocks",
            source=source,
        )

    if has_high:
        return TextDecision(
            action="refuse",
            findings=findings,
            reason="high-severity finding (PII regex match, confidential term, or special-category)",
            source=source,
        )

    redacted = _redact_text_with_regex(text)
    return TextDecision(
        action="minimise",
        findings=findings,
        redacted_text=redacted,
        reason="medium-severity findings; pattern-matched spans redacted",
        source=source,
    )


def _redact_text_with_regex(text: str) -> str:
    """Replace any Tier B pattern match in ``text`` with ``[REDACTED-<LABEL>]``,
    in table order (specific before broad). Deterministic."""
    redacted = text
    for label, _matcher, _conf in _TIER_B_PATTERNS:
        placeholder = f"[REDACTED-{label.upper().replace('_', '-')}]"
        redacted = _redact_for_label(redacted, label, placeholder=placeholder)
    return redacted


# Capture-only credential patterns — widen coverage for the at-rest redactor
# without touching the shared Tier-B set.
_CAPTURE_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]+")
_CAPTURE_PEM_BEGIN_RE = re.compile(
    r"-----BEGIN ([A-Z ]{0,32}PRIVATE KEY)-----")
_CAPTURE_BEARER_CI_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-/+=]{8,}")
_CAPTURE_SECRET_ASSIGN_RE = re.compile(
    r"(?i)\b(?:password|passwd|secret|secret[_-]?access[_-]?key|api[_-]?key|token|access[_-]?token|refresh[_-]?token)\b"
    r"\s*[=:]\s*"
    r"(?:\"[^\"]{4,}\"|'[^']{4,}'|[^\s\"',;}]{4,})")

#: Tier-B labels worth redacting from at-rest captured text (credentials + PII).
_CAPTURE_REDACT_LABELS = (
    "url_with_creds", "api_key", "bearer_token", "credit_card", "email",
    "iban_full", "iban", "us_ssn", "uk_nino", "fr_ssn", "de_steuer_id",
    "es_dni_nie", "de_personnummer", "de_personalausweis_10", "mrn",
    "patient_case_id", "icd10", "name_possessive", "phone",
)


def _redact_pem_private_keys(text: str) -> str:
    """Redact complete PEM key blocks with a linear boundary scan (bounded BEGIN
    label, exact END marker); unclosed pseudo-blocks are left to the other detectors."""
    parts: list[str] = []
    cursor = 0
    while match := _CAPTURE_PEM_BEGIN_RE.search(text, cursor):
        end_marker = f"-----END {match.group(1)}-----"
        end = text.find(end_marker, match.end())
        if end < 0:
            break
        parts.append(text[cursor:match.start()])
        parts.append("[REDACTED-PRIVATE-KEY]")
        cursor = end + len(end_marker)
    if not parts:
        return text
    parts.append(text[cursor:])
    return "".join(parts)


def redact_for_capture(text: str) -> str:
    """Redact secrets + PII from text BEFORE it is persisted to a capture ledger
    or a signed audit chain. Full Tier-B set plus JWTs, PEM private-key blocks,
    case-insensitive bearer carriers and ``secret=/password=/token=`` assignments.

    Best-effort by design (residual gaps: opaque tokens with no recognised
    prefix, unenumerated vendor formats, secrets split across lines).
    """
    if not text:
        return text
    out = text
    for label in _CAPTURE_REDACT_LABELS:
        out = _redact_for_label(out, label)
    out = _redact_pem_private_keys(out)
    out = _CAPTURE_JWT_RE.sub("[REDACTED-JWT]", out)
    out = _CAPTURE_BEARER_CI_RE.sub("[REDACTED-BEARER]", out)
    out = _CAPTURE_SECRET_ASSIGN_RE.sub("[REDACTED-SECRET]", out)
    return out


# ===========================================================================
# Tier C ensemble with CoT prompting — over the host's classifier hook.
# ===========================================================================
#
# Unanimity trades single-model recall for ensemble precision: a joint pii_yes
# is high-confidence, and every disagreement is a deliberate escalation. The
# defaults name only weights whose licences permit commercial use.

ENSEMBLE_MODELS_DEFAULT = (
    "phi-3.5-mini-q4",
    "qwen-2.5-coder-7b-q4",
    "mistral-7b-instruct-q4",
)

TIER_C_ROLE = "lock-c"


def _models_for_role(
    role: str,
    default: tuple[str, ...] = (),
) -> tuple[str, ...]:
    """Resolve a role to the configured ensemble via ``host_deps.models_for_role``;
    empty or erroring → ``default``."""
    try:
        host_deps.ensure_wired()
        if host_deps.models_for_role is None:
            return tuple(default)
        configured = host_deps.models_for_role(role)
    except Exception:
        return tuple(default)
    if configured:
        return tuple(configured)
    return tuple(default)


TIER_C_COT_PROMPT_TEMPLATE = """\
You are a privacy classifier. Apply these rules IN ORDER:
1. Does the text mention a specific real person by name? (yes/no/unsure)
2. Does it reveal information not public about that person? (yes/no/n/a)
3. Could the combination of details identify the person? (yes/no/unsure)
Then classify: pii_yes / pii_no / insufficient.
Output ONLY the final label.

Text: {text}
"""


@dataclass
class TierCEnsembleResult:
    """Outcome of :func:`tier_c_semantic_check`: ``pii_yes`` / ``pii_no`` on
    unanimous agreement, ``insufficient`` on disagreement."""
    label: str
    per_model: dict[str, str]
    confidence: float
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _normalise_label(raw: Any) -> str:
    """Coerce a model output to one of pii_yes / pii_no / insufficient."""
    if raw is None:
        return "insufficient"
    s = str(raw).strip().lower()
    s = s.strip("\"' .\n\t")
    if "pii_yes" in s or s in {"yes", "pii"}:
        return "pii_yes"
    if "pii_no" in s or s in {"no", "none"}:
        return "pii_no"
    return "insufficient"


def tier_c_semantic_check(
    text: str,
    folder_context: str = "",
    *,
    models: tuple[str, ...] | None = None,
) -> TierCEnsembleResult | None:
    """Ensemble Tier C semantic check over ``host_deps.llm_classify``.

    ``models``: explicit non-empty tuple wins; otherwise the host's registered
    ensemble for :data:`TIER_C_ROLE`; otherwise :data:`ENSEMBLE_MODELS_DEFAULT`.
    All models must agree for a high-confidence label. Returns ``None`` when no
    classifier hook is wired (or every model was unavailable).
    """
    if not text or not text.strip():
        return TierCEnsembleResult(
            label="pii_no", per_model={},
            confidence=1.0, reason="empty input",
        )
    if models is None or len(models) == 0:
        models = _models_for_role(TIER_C_ROLE, default=ENSEMBLE_MODELS_DEFAULT)

    host_deps.ensure_wired()
    if host_deps.llm_classify is None:
        return None
    local_llm_classify = host_deps.llm_classify

    per_model: dict[str, str] = {}
    any_unavailable = False
    for model in models:
        prompt = TIER_C_COT_PROMPT_TEMPLATE.format(text=text)
        try:
            result = local_llm_classify(
                text=prompt,
                categories=["pii_yes", "pii_no", "insufficient"],
                folder_context=folder_context,
                model=model,
            )
        except Exception:
            any_unavailable = True
            per_model[model] = "insufficient"
            continue
        if not isinstance(result, dict):
            any_unavailable = True
            per_model[model] = "insufficient"
            continue
        if not result.get("ok", True):
            any_unavailable = True
            per_model[model] = "insufficient"
            continue
        label = _normalise_label(result.get("category"))
        per_model[model] = label

    if any_unavailable and all(v == "insufficient" for v in per_model.values()) \
       and len(per_model) == len(models):
        return None

    labels = set(per_model.values())
    if labels == {"pii_yes"}:
        return TierCEnsembleResult(
            label="pii_yes", per_model=per_model,
            confidence=0.9, reason="ensemble agreement (pii_yes)",
        )
    if labels == {"pii_no"}:
        return TierCEnsembleResult(
            label="pii_no", per_model=per_model,
            confidence=0.9, reason="ensemble agreement (pii_no)",
        )
    return TierCEnsembleResult(
        label="insufficient", per_model=per_model,
        confidence=0.5,
        reason="ensemble disagreement or insufficient — escalate per policy",
    )
