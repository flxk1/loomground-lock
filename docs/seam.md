<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 flxk1 -->
# Seam: what moved out of the host, and how a host wires it back

Source: `flxk1/RVND` at `bac579b`, `server/src/rvnd/`. The `lock/` package there is
mostly host runtime; only the primitive moved.

## Moved → package module map

| Source (`rvnd/`) | Package module | Notes |
|---|---|---|
| `lock/core.py` | `loomground_lock.core` | Tier C via hook (see port change a); `disable_lock` payload via hook |
| `lock/host_deps.py` | `loomground_lock.host_deps` | provider/register wiring (port change b); new hooks listed below |
| `lock/decisions.py` | `loomground_lock.decisions` | unchanged |
| `lock/oversight.py` | `loomground_lock.oversight` | unchanged |
| `lock/injection_scan.py` | `loomground_lock.injection_scan` | unchanged |
| `lock/scanned_response.py` | `loomground_lock.scanned_response` | `to_payload()`; `to_mcp_payload` kept as a compatibility alias |
| `lock/tier_m.py` | `loomground_lock.tier_m` | unchanged |
| `lock/credential_resolver.py` | `loomground_lock.credential_resolver` | key root via `host_deps.key_root_dir`, else `WORKSPACE_KEY_DIR` |
| `lock_classify.py` | `loomground_lock.lock_classify` | `_lock_string` over `core.lock_text`; doc token + memory via hooks |
| `seal.py` | `loomground_lock.seal` | identity/log root from `loomground_workspace`; own `_file_lock`; pending-erase via hooks |
| `seal_binding.py` | `loomground_lock.seal_binding` | served-store readers via hooks, JSON-line fallback |
| — | `loomground_lock.verdicts` | new: lock actions and oversight levels → `.lg` verdict alphabet |

## Preserved public names

From the seam survey (`seam-surface.json`), every name that belongs to a moved module
(`tests/test_surface.py` asserts each is importable):

- `rvnd.lock` re-exports: `AuditLog CapabilityToken DecisionsStore Finding LockAudit Mode
  OversightDecision OversightLevel PRIVACY_CLASS_DEFAULTS ScannedResponse ToolCall
  ToolResponse assert_scanned credential_resolver describe effective_level egress host_deps
  ingress injection_scan is_valid_ref lock_text redact_for_capture scan_document scan_text
  tier_b_scan_text tier_m` → `loomground_lock.<name>`.
- `rvnd.lock.core.*`: `AuditLog CapabilityToken ENSEMBLE_MODELS_DEFAULT Finding Mode
  RemediationAction TextDecision TierCEnsembleResult ToolCall _detect_confusable_bypass
  _flatten_argument_fields _luhn_ok _redact_text_with_regex lock_text redact_for_capture
  tier_a_check_arguments tier_a_check_response tier_b_scan_dict tier_b_scan_text
  tier_c_semantic_check validate_token` → `loomground_lock.core.*`.
- `rvnd.lock.decisions.DecisionsStore`; `rvnd.lock.oversight.{OversightLevel,
  asks_user_per_finding, asks_user_per_plan, notifies_user_post_execution,
  waits_for_review_after_execution}`; `rvnd.lock.scanned_response.{Cleartext,
  CleartextEgressError, LockAudit, ScannedResponse, assert_scanned, scan_payload}`.
- `rvnd.lock_classify.{LOCK_DISCLAIMER_VERSION, _lock_string, lock_classify_pair,
  reclassify_all_pairs}`; `rvnd.seal.{SealError, _REC_MAGIC, _resolve_log_dir,
  decrypt_record, encrypt_record, seal_folder, unseal_folder}`;
  `rvnd.seal_binding.{read_pairs, replay}`.

Names of staying modules (`BackendError GateDecision apply_config_to_env default_config_path
describe_tier_c egress_proxy gate_for_cloud interactive is_tier_c_available kg_context_for_vault
l0_bridge l0_mcp_client load_config make_local_llm probe_broker reset_backend_cache
review_findings run_wizard save_config tier_c tier_c_requires_real_backend`, and everything under
`lock.egress_proxy.* lock.gate.* lock.gate_and_capture.* lock.l0_bridge.* lock.mcp_server.*
lock.onboarding.* lock.backends.* lock.tier_c.* lock.track_broker.* lock.broker_probe.*
lock.interactive.* lock.__main__.*`) remain the host's.

## The two port changes

**(a) Tier C is a hook.** `core.lock_text` used to `from .tier_c import tier_c_check_semantic`.
It now calls `host_deps.tier_c_check_semantic(text, context=)` when wired. Composition in
`core._tier_c`:

1. `core.tier_c_context_terms_check(text, context)` always runs: a confidential term from
   `context` found in `text` is a high-severity Tier-C finding. This is the deterministic
   part of what the host's mock backend did, so an unwired package still refuses what the
   host refused on confidential terms.
2. If the hook is absent, semantic classification is skipped (degraded; the host's
   keyword/model heuristics are the host's).
3. If the hook raises or returns a non-list, the failure is a refusal
   (`tier_c_unavailable`, high) when `host_deps.tier_c_requires_real_backend()` is True or
   itself fails; when it returns False the failure is swallowed (the documented mock
   default). Detail strings carry the exception class name only.

**(b) `ensure_wired()` imports nothing by name.** A host calls
`host_deps.set_wiring_provider(fn)` (run once, lazily, on the first `ensure_wired()`) or
`host_deps.register(**hooks)` directly. `register` rejects unknown hook names and
non-callables; `clear()` drops everything (test isolation); `wired()` reports what is filled.

**Module-identity pitfall.** Hooks are attributes of the module object
`loomground_lock.host_deps`. A host shim named e.g. `rvnd.lock.host_deps` must be the SAME
object — `sys.modules["rvnd.lock.host_deps"] = loomground_lock.host_deps` (or
`from loomground_lock import host_deps` and assign on it). A shim that copies the names
(`from loomground_lock.host_deps import *`) gets a snapshot: assignments land on the copy and
the lock stays unwired, silently.

### Hooks (all `None` until wired; all degrade fail-safe)

Carried over from the source declaration: `models_for_role llm_classify key_root_dir
record_decision list_connectors l0_load_policy l0_capture_llm l0_capture_web list_models
registry_models_for_role capability_verifier_factory record_capability_refusal govern_egress
verify_agent_identity record_audit_drop` (several are consumed only by staying host modules,
which read them off this module through the shim).

Added by the extraction:

| Hook | Signature | Absent → |
|---|---|---|
| `tier_c_check_semantic` | `(text, context="") -> list[Finding]` | context-term check only |
| `tier_c_requires_real_backend` | `() -> bool` | False |
| `disable_lock_remediation` | `() -> dict` | `{"acknowledgement_required": True, "disclaimer_required": True}` (the source hard-coded a host CLI string, tool name and disclaimer URL) |
| `opaque_doc_token` | `(source, folder_path) -> str` | `<DOC_unknown>` (source imported the host's salted token) |
| `workspace_memory` | `(folder_context, log_root=, actor=) -> memory` with `all_pairs()`, `remember(pair, channel=, source_hash=)` | `reclassify_all_pairs` raises `RuntimeError` unless `memory=` is passed |
| `pending_erase_verify` | `(folder, log_dir=, sealed_path=, log_root=) -> markers` | no markers (source: env-gated `pending_erase` module) |
| `pending_erase_apply` | `(folder, markers, log_root=) -> result` | skipped |
| `events_from_bytes` | `(bytes) -> iterable[event]` | newline-delimited JSON dicts, malformed lines skipped |
| `pair_from_event` | `(event) -> dict \| None` | `event["extra"]["pair"]` |
| `read_served_versum_records` | `(store) -> records` | knowledge-sink bodies skipped |
| `read_disk_versum_records` | `(folder) -> records` | knowledge-sink bodies skipped |

## Compatibility constants and names

| Where | Name | Value / meaning |
|---|---|---|
| `core.ENV_STRICT_TOKEN_SIG` | `LOCK_BETA_STRICT_TOKEN_SIG` | `"1"` → Ed25519 signature verification required |
| `core.ENV_CAPABILITY_TRUST_STORE` | `LOCK_CAPABILITY_TRUST_STORE` | path of the `{issuer: PEM}` JSON trust store |
| `decisions.ENV_SESSION_ID` | `AGENT_TOOL_LOCK_SESSION_ID` | default `DecisionsStore.session_id` |
| `decisions.ENV_DECISION_TTL_SECONDS` | `AGENT_TOOL_LOCK_DECISION_TTL_SECONDS` | allow-clearance TTL (default 90 days) |
| `credential_resolver.ENV_KEY_DIR` | `WORKSPACE_KEY_DIR` | key root fallback when `key_root_dir` is unwired |
| `decisions._DEFAULT_PATH` | `~/.config/agent-tool-lock/decisions.jsonl` | default store path |
| `seal._REC_MAGIC` | `b"RVEC1"` | per-record envelope magic (on-disk format, kept byte-identical) |
| `seal._MAGIC` | `"workspace-seal"` | whole-store envelope magic |
| `scanned_response.ScannedResponse.to_mcp_payload` | alias of `to_payload` | the one host-protocol name kept in `src/`, for existing callers |
| — | `AGENT_TOOL_LOCK_LLM_BACKEND` | read by the host's `tier_c.py` (stays); unreached here |

## Other behaviour notes

- **Confusable folding** (`core._ascii_fold`): the source required `anyascii` and failed
  closed on every non-ASCII text when it was missing. This package uses `anyascii` when
  installed and otherwise NFKC + a Cyrillic/Greek/zero-width confusables table + combining-mark
  stripping, so Tier B+ always runs without an extra dependency.
- **`lock_classify_pair`**: the source shadowed its `context` keyword with the pair's
  `problem.context` dict before scanning triples, so Tier C never saw the caller's terms on
  triples. The local is now `ctx_block`; triples are scanned with the caller's `context`.
- **`seal._file_lock`**: a local `fcntl.flock`/`msvcrt.locking` context manager over
  `events.jsonl`, the same OS primitive the host's appender uses, so seal and append still
  serialise across processes.
- **`seal_binding._SESSION`** is a cryptographic key cache (`folder hash → derived AES key`,
  process memory only). It binds no identity, principal or host session; the name is kept
  for the source's readers.
- **Domain-neutral, host-agnostic**: `src/` names no host, protocol or agent runtime;
  `tests/` likewise. `grep -rniE 'rvnd|claude|anthropic|mcp|CLAUDE_CODE' src/ tests/` hits
  only the `to_mcp_payload` alias and its test.

## Stays in RVND (host runtime) — and why

| Module | Reason |
|---|---|
| `lock/mcp_server.py` | protocol server surface |
| `lock/egress_proxy.py` | HTTP proxy runtime (identity verification, brokered credentials, capture) |
| `lock/l0_bridge.py`, `lock/l0_mcp_client.py` | in-process/cross-process policy + capture bridge to the host |
| `lock/obsidian_kg.py` | host knowledge-vault adapter |
| `lock/onboarding/` | wizard + config for local models |
| `lock/backends/` | local-LLM backends (llama_cpp, onnx_genai, mock) |
| `lock/tier_c.py` | backend dispatcher over `backends/` + env spec; reaches the package through the `tier_c_check_semantic` hook |
| `lock/interactive.py` | CLI review loop |
| `lock/broker_probe.py`, `lock/track_broker.py` | broker liveness + track binding runtime |
| `lock/gate.py`, `lock/gate_and_capture.py` | policy gate composing decisions store, oversight and the host chain |
| `lock/__main__.py` | CLI entry |
| `lock_wiring.py` | the host wiring by definition — it becomes the provider passed to `set_wiring_provider` |

## How the host shims (for the RVND leg)

- `rvnd/adapters/lock.py`: `import loomground_lock; from loomground_lock import host_deps`,
  then `host_deps.set_wiring_provider(lambda: importlib.import_module("rvnd.lock_wiring"))`
  where `lock_wiring` assigns onto `loomground_lock.host_deps` (not a copy). Add
  `tier_c_check_semantic=rvnd.lock.tier_c.tier_c_check_semantic`,
  `tier_c_requires_real_backend`, `disable_lock_remediation` (the former hard-coded
  `cli`/`mcp`/`disclaimer_url` payload), `opaque_doc_token` (`rvnd.identity`),
  `workspace_memory` (`rvnd.memory.WorkspaceMemory`), `pending_erase_verify/apply`
  (`rvnd.pending_erase`, guarded by its `feature_enabled()`), `events_from_bytes`
  (`rvnd.mutation_log`), `pair_from_event` (`rvnd.memory._pair_from_event`),
  `read_served_versum_records`/`read_disk_versum_records` (`rvnd.adapters.versum`).
- Zero-definition shims, each `sys.modules[__name__] = loomground_lock.<module>` or
  `from loomground_lock.<module> import *` plus the private names the surface lists:
  `rvnd.lock.core`, `rvnd.lock.host_deps` (MUST alias the module object — see the pitfall),
  `rvnd.lock.decisions`, `rvnd.lock.oversight`, `rvnd.lock.injection_scan`,
  `rvnd.lock.scanned_response`, `rvnd.lock.tier_m`, `rvnd.lock.credential_resolver`,
  `rvnd.lock_classify`, `rvnd.seal`, `rvnd.seal_binding`.
- `rvnd/lock/__init__.py` keeps its re-export surface unchanged: moved names come from the
  shims, staying names from the staying modules.
