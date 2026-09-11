<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 flxk1 -->
# Changelog

## 0.1.0

* Extracted from the RVND engine at commit `bac579b` (`flxk1/RVND`, `server/src/rvnd/`): `lock/core.py`, `lock/host_deps.py`, `lock/decisions.py`, `lock/oversight.py`, `lock/injection_scan.py`, `lock/scanned_response.py`, `lock/tier_m.py`, `lock/credential_resolver.py`, `lock_classify.py`, `seal.py`, `seal_binding.py` → `loomground_lock.{core,host_deps,decisions,oversight,injection_scan,scanned_response,tier_m,credential_resolver,lock_classify,seal,seal_binding}`. Tests ported from `server/tests/test_lock_text.py`, `test_tier_b_extended.py`, `test_lock_core_ingress_invariant.py`, `test_capability_token_signatures.py`, `test_lock_hardening_067.py`, `test_tier_m_moderation.py`, `test_lock_classify_and_threshold_2026_05_22.py`, `test_seal*.py`, `test_scanned_response.py`, `test_per_track_credential.py`, `test_decisions_and_gate.py`.
* Licence: the source files carry `AGPL-3.0-only`, copyright flxk1; this package relicenses them to Apache-2.0 (code) / CC-BY-4.0 (README) by the same copyright holder, following the loomground-workspace extraction precedent. Felix confirms the relicensing.
* Seam changes (`docs/seam.md`): Tier C becomes the `host_deps.tier_c_check_semantic` hook with a built-in deterministic context-term check; `host_deps.ensure_wired()` runs a registered provider (`set_wiring_provider`, `register`) instead of importing a host module; seal reads `LOG_ROOT_DEFAULT`, `folder_hash`, `legacy_folder_hash` from `loomground_workspace`; `verdicts.py` maps lock actions and oversight levels onto `loomground_governance.vocabulary("verdicts")`.
