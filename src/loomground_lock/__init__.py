# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""loomground-lock — egress and ingress locks with capability tokens, and
at-rest sealing of a folder's memory.

Host ports live on :mod:`loomground_lock.host_deps`; verdict mapping on
:mod:`loomground_lock.verdicts`.
"""

from ._version import __version__
from . import (
    credential_resolver,
    host_deps,
    injection_scan,
    lock_classify,
    seal,
    seal_binding,
    tier_m,
    verdicts,
)
from .core import (
    AuditLog,
    CapabilityToken,
    EgressDecision,
    Finding,
    IngressDecision,
    Mode,
    RemediationAction,
    TextDecision,
    ToolCall,
    ToolResponse,
    egress,
    ingress,
    lock_text,
    redact_for_capture,
    tier_b_scan_text,
    tier_c_context_terms_check,
    validate_token,
)
from .credential_resolver import describe, is_valid_ref, resolve_secret
from .decisions import DecisionsStore, StoredDecision
from .injection_scan import scan_document, scan_text
from .lock_classify import LOCK_DISCLAIMER_VERSION, lock_classify_pair, reclassify_all_pairs
from .oversight import (
    PRIVACY_CLASS_DEFAULTS,
    OversightDecision,
    OversightLevel,
    effective_level,
)
from .scanned_response import LockAudit, ScannedResponse, assert_scanned
from .seal import SealError, decrypt_record, encrypt_record, is_sealed, seal_folder, unseal_folder
from .verdicts import verdict_for_action, verdict_for_oversight

__all__ = [
    "__version__",
    "AuditLog", "CapabilityToken", "EgressDecision", "Finding", "IngressDecision",
    "Mode", "RemediationAction", "TextDecision", "ToolCall", "ToolResponse",
    "egress", "ingress", "lock_text", "redact_for_capture", "tier_b_scan_text",
    "tier_c_context_terms_check", "validate_token",
    "describe", "is_valid_ref", "resolve_secret",
    "DecisionsStore", "StoredDecision",
    "scan_document", "scan_text",
    "LOCK_DISCLAIMER_VERSION", "lock_classify_pair", "reclassify_all_pairs",
    "PRIVACY_CLASS_DEFAULTS", "OversightDecision", "OversightLevel", "effective_level",
    "LockAudit", "ScannedResponse", "assert_scanned",
    "SealError", "decrypt_record", "encrypt_record", "is_sealed", "seal_folder", "unseal_folder",
    "verdict_for_action", "verdict_for_oversight",
    "credential_resolver", "host_deps", "injection_scan", "lock_classify",
    "seal", "seal_binding", "tier_m", "verdicts",
]
