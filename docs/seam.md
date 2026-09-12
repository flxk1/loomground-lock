<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 flxk1 -->
# Host seam

`loomground-lock` owns the lock, scanning, decisions, oversight, credential,
and sealing primitives. A consuming host adds model backends, persistence
adapters, and product surfaces through `loomground_lock.host_deps`; the package
imports no host module.

## Public modules

| Module | Responsibility |
|---|---|
| `core` | Tier A/B/C inspection, capability-token validation, lock decisions |
| `host_deps` | explicit hook registry and lazy wiring provider |
| `decisions` | durable allow-clearance decisions |
| `oversight` | oversight levels and timing predicates |
| `injection_scan`, `scanned_response`, `tier_m` | ingress scanning and checked response carriers |
| `credential_resolver` | key-root resolution |
| `lock_classify` | pair classification over `core.lock_text` |
| `seal`, `seal_binding` | encrypted folder sealing, replay, and served-store readers |
| `verdicts` | lock actions and oversight levels mapped to Loomground verdicts |

`tests/test_surface.py` fixes the importable public names and signatures.

## Tier C and fail-closed wiring

`core.lock_text` always runs the deterministic context-term check. If
`tier_c_check_semantic` is registered, its result replaces the built-in
semantic backend. If the hook fails, returns an unusable value, or a host
declares `tier_c_requires_real_backend()` while no backend is available, the
decision gains a high-severity `tier_c_unavailable` finding and refuses. With
no hook and no real-backend requirement, `tier_c_default_check` supplies the
built-in health, financial, and capitalised-name heuristics.

Call `host_deps.register(**hooks)` directly or install a one-time lazy provider
with `host_deps.set_wiring_provider(fn)`. Unknown hook names and non-callables
are rejected. Provider failures are recorded by `wiring_error()` and keep Tier
C fail-closed until `clear()` or a new provider resets the state. A host must
mutate the actual `loomground_lock.host_deps` module object; copying its names
creates disconnected hook state.

## Hooks

| Hook | Shape | If absent |
|---|---|---|
| `tier_c_check_semantic` | `(text, context="") -> list[Finding]` | built-in semantic tier |
| `tier_c_requires_real_backend` | `() -> bool` | `False` |
| `disable_lock_remediation` | `() -> dict` | acknowledgement and disclaimer required |
| `opaque_doc_token` | `(source, folder_path) -> str` | `<DOC_unknown>` |
| `workspace_memory` | `(folder_context, log_root=, actor=) -> memory` | classification requires an explicit `memory=` argument |
| `pending_erase_verify`, `pending_erase_apply` | sealed-store marker hooks | no markers / skipped |
| `events_from_bytes` | `(bytes) -> iterable[event]` | newline-delimited JSON dictionaries |
| `pair_from_event` | `(event) -> dict | None` | `event["extra"]["pair"]` when present |
| `read_served_versum_records`, `read_disk_versum_records` | knowledge-record readers | corresponding bodies skipped |

The registry also accepts model-selection, identity, capability-verification,
decision-recording, egress-governance, and audit-drop hooks used by consumers.
`host_deps.wired()` reports the active set.

## Stable configuration

| Name | Meaning |
|---|---|
| `LOCK_BETA_STRICT_TOKEN_SIG` | require Ed25519 capability-token signatures |
| `LOCK_CAPABILITY_TRUST_STORE` | `{issuer: PEM}` trust-store path |
| `AGENT_TOOL_LOCK_SESSION_ID` | default decisions-store session id |
| `AGENT_TOOL_LOCK_DECISION_TTL_SECONDS` | allow-clearance TTL |
| `WORKSPACE_KEY_DIR` | fallback key root |
| `~/.config/agent-tool-lock/decisions.jsonl` | default decisions path |
| `b"RVEC1"` | stable per-record encrypted-envelope magic |
| `"workspace-seal"` | stable whole-store envelope magic |

The envelope magic is a data-format constant, not a repository or runtime
dependency.

## Behaviour notes

- Confusable folding uses `anyascii` when installed and otherwise NFKC plus a
  bounded Cyrillic/Greek/zero-width table, so Tier B+ still runs offline.
- `seal` serialises against appenders with an OS file lock.
- `seal_binding._SESSION` caches derived AES keys by folder hash in process
  memory; it does not represent a host identity or user session.
- `ScannedResponse.to_mcp_payload` remains an alias of the protocol-neutral
  `to_payload` for existing callers.

The host owns any CLI, HTTP proxy, model process, review UI, protocol server,
broker, knowledge-store adapter, and wiring provider. Those are consumers of
this contract, not dependencies of it.
