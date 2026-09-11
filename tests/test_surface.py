# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Every public name of a MOVED module from the host seam survey (source commit
bac579b, seam-surface.json: modules lock, lock_classify, seal, seal_binding) is
importable here. Names of modules that stayed in the host are excluded."""
from __future__ import annotations

import importlib
import json
import os
import pathlib

import loomground_lock

# host `lock` package re-exports that originate in a moved module → loomground_lock attribute.
LOCK_TOP_LEVEL = [
    "AuditLog", "CapabilityToken", "DecisionsStore", "Finding", "LockAudit", "Mode",
    "OversightDecision", "OversightLevel", "PRIVACY_CLASS_DEFAULTS", "ScannedResponse",
    "ToolCall", "ToolResponse", "assert_scanned", "credential_resolver", "describe",
    "effective_level", "egress", "host_deps", "ingress", "injection_scan", "is_valid_ref",
    "lock_text", "redact_for_capture", "scan_document", "scan_text", "tier_b_scan_text", "tier_m",
]

# Dotted host names → (loomground_lock module, attribute).
DOTTED = {
    "lock.core.AuditLog": ("core", "AuditLog"),
    "lock.core.CapabilityToken": ("core", "CapabilityToken"),
    "lock.core.ENSEMBLE_MODELS_DEFAULT": ("core", "ENSEMBLE_MODELS_DEFAULT"),
    "lock.core.Finding": ("core", "Finding"),
    "lock.core.Mode": ("core", "Mode"),
    "lock.core.RemediationAction": ("core", "RemediationAction"),
    "lock.core.TextDecision": ("core", "TextDecision"),
    "lock.core.TierCEnsembleResult": ("core", "TierCEnsembleResult"),
    "lock.core.ToolCall": ("core", "ToolCall"),
    "lock.core._detect_confusable_bypass": ("core", "_detect_confusable_bypass"),
    "lock.core._flatten_argument_fields": ("core", "_flatten_argument_fields"),
    "lock.core._luhn_ok": ("core", "_luhn_ok"),
    "lock.core._redact_text_with_regex": ("core", "_redact_text_with_regex"),
    "lock.core.lock_text": ("core", "lock_text"),
    "lock.core.redact_for_capture": ("core", "redact_for_capture"),
    "lock.core.tier_a_check_arguments": ("core", "tier_a_check_arguments"),
    "lock.core.tier_a_check_response": ("core", "tier_a_check_response"),
    "lock.core.tier_b_scan_dict": ("core", "tier_b_scan_dict"),
    "lock.core.tier_b_scan_text": ("core", "tier_b_scan_text"),
    "lock.core.tier_c_semantic_check": ("core", "tier_c_semantic_check"),
    "lock.core.validate_token": ("core", "validate_token"),
    "lock.decisions.DecisionsStore": ("decisions", "DecisionsStore"),
    "lock.oversight.OversightLevel": ("oversight", "OversightLevel"),
    "lock.oversight.asks_user_per_finding": ("oversight", "asks_user_per_finding"),
    "lock.oversight.asks_user_per_plan": ("oversight", "asks_user_per_plan"),
    "lock.oversight.notifies_user_post_execution": ("oversight", "notifies_user_post_execution"),
    "lock.oversight.waits_for_review_after_execution": ("oversight", "waits_for_review_after_execution"),
    "lock.scanned_response.Cleartext": ("scanned_response", "Cleartext"),
    "lock.scanned_response.CleartextEgressError": ("scanned_response", "CleartextEgressError"),
    "lock.scanned_response.LockAudit": ("scanned_response", "LockAudit"),
    "lock.scanned_response.ScannedResponse": ("scanned_response", "ScannedResponse"),
    "lock.scanned_response.assert_scanned": ("scanned_response", "assert_scanned"),
    "lock.scanned_response.scan_payload": ("scanned_response", "scan_payload"),
    "lock_classify.LOCK_DISCLAIMER_VERSION": ("lock_classify", "LOCK_DISCLAIMER_VERSION"),
    "lock_classify._lock_string": ("lock_classify", "_lock_string"),
    "lock_classify.lock_classify_pair": ("lock_classify", "lock_classify_pair"),
    "lock_classify.reclassify_all_pairs": ("lock_classify", "reclassify_all_pairs"),
    "seal.SealError": ("seal", "SealError"),
    "seal._REC_MAGIC": ("seal", "_REC_MAGIC"),
    "seal._resolve_log_dir": ("seal", "_resolve_log_dir"),
    "seal.decrypt_record": ("seal", "decrypt_record"),
    "seal.encrypt_record": ("seal", "encrypt_record"),
    "seal.seal_folder": ("seal", "seal_folder"),
    "seal.unseal_folder": ("seal", "unseal_folder"),
    "seal_binding.read_pairs": ("seal_binding", "read_pairs"),
    "seal_binding.replay": ("seal_binding", "replay"),
}

MOVED_PREFIXES = ("lock.core.", "lock.decisions.", "lock.oversight.", "lock.scanned_response.",
                  "lock.host_deps.", "lock.injection_scan.", "lock.tier_m.", "lock.credential_resolver.")


def test_top_level_names_import():
    missing = [n for n in LOCK_TOP_LEVEL if not hasattr(loomground_lock, n)]
    assert missing == []


def test_dotted_names_import():
    missing = []
    for host_name, (mod, attr) in DOTTED.items():
        module = importlib.import_module(f"loomground_lock.{mod}")
        if not hasattr(module, attr):
            missing.append(host_name)
    assert missing == []


def test_seam_survey_cross_check_when_available():
    """If the seam survey file is present, every moved-module name it lists is covered above."""
    path = os.environ.get("LOOMGROUND_LOCK_SEAM_JSON", "")
    if not path or not pathlib.Path(path).exists():
        return
    survey = json.loads(pathlib.Path(path).read_text())
    expected = set()
    for name in survey["lock"]["names"]:
        if "." not in name:
            if name in LOCK_TOP_LEVEL:
                expected.add(name)
        elif name.startswith(MOVED_PREFIXES):
            expected.add(name)
    for mod in ("lock_classify", "seal", "seal_binding"):
        expected |= {f"{mod}.{n}" for n in survey[mod]["names"]}
    covered = set(DOTTED) | set(LOCK_TOP_LEVEL)
    assert expected <= covered, sorted(expected - covered)
