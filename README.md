<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- Copyright 2026 flxk1 -->
# loomground-lock

Egress and ingress locks with capability tokens, and at-rest sealing of a folder's memory.

## Problem

Secrets and personal data leave with every tool call. Egress and ingress locks with capability tokens, and at-rest sealing of a folder's memory.

## Install

```
pip install -r requirements-dev.txt && pip install loomground-lock
```

## Usage

```python
from loomground_lock import Mode, lock_text, redact_for_capture, seal_folder, verdict_for_action

decision = lock_text("mail alex@example.com the project atlas plan", context="- project atlas")
decision.action, [f.tier for f in decision.findings]        # 'refuse', ['B', 'C']
redact_for_capture("token=abcd1234 for alex@example.com")    # placeholders, same shape
verdict_for_action(decision.action)                         # a member of the .lg alphabet
seal_folder("~/Workspaces/alpha", passphrase="…")           # ciphertext at rest
```

## Example

```
in : lock_text("mail alex@example.com the project atlas plan", context="- project atlas")
out: refuse ['B', 'C'] high-severity finding (PII regex match, confidential term, or special-category)
in : lock_text("chemo starts Monday")            # nothing wired — the built-in Tier C
out: refuse ['C'] high-severity finding (PII regex match, confidential term, or special-category)
in : redact_for_capture("token=abcd1234 for alex@example.com")
out: [REDACTED-SECRET] for [REDACTED:email]
in : verdict_for_action("refuse"), verdict_for_action("minimise")
out: ('refused', 'auto')
```

## Interface

- `lock_text(text, context=, mode=, moderation_rules=) → TextDecision(action ∈ allow|minimise|refuse, findings, redacted_text)` · `egress(ToolCall, task_scope) → EgressDecision` · `ingress(ToolResponse, task_scope) → IngressDecision` · `validate_token(CapabilityToken, ToolCall)`
- `redact_for_capture(text)` · `DecisionsStore(path).remember/recall` · `OversightLevel`, `effective_level` · `injection_scan.scan_text` · `ScannedResponse`, `assert_scanned`
- `seal_folder`, `unseal_folder`, `encrypt_record`, `decrypt_record`; `seal_binding.unlock/serve/replay/read_pairs`
- `verdicts.verdict_for_action`, `verdict_for_oversight` — codomain read from `loomground_governance.vocabulary("verdicts")`
- Host ports on `loomground_lock.host_deps` (`register(**hooks)` or `set_wiring_provider(fn)`): `tier_c_check_semantic`, `tier_c_requires_real_backend`, `llm_classify`, `models_for_role`, `key_root_dir`, `disable_lock_remediation`, `opaque_doc_token`, `workspace_memory`, `pending_erase_verify/apply`, `events_from_bytes`, `pair_from_event`, `read_served_versum_records`, `read_disk_versum_records`. With nothing wired, Tier C runs the package's own default semantic tier (`tier_c_default_check`) at the strictness the host reaches with its default backend. A semantic check that cannot run — a crash, an unusable result, a promised backend missing, a wiring provider that raised — adds a high-severity `tier_c_unavailable` finding, which refuses. Full seam: [docs/seam.md](docs/seam.md).

## Family

Runtime controls. Consumes `loomground-governance` (verdict vocabulary) and `loomground-workspace` (folder identity, log root). Consumed by hosts, e.g. RVND, through the ports above; optional for every consumer.

## Status

0.1.0 · extracted from RVND `bac579b` · Python >=3.10 · governance 0.11 · workspace 0.1

## License

Apache-2.0 `LICENSES/Apache-2.0.txt` (code) · CC-BY-4.0 `LICENSES/CC-BY-4.0.txt` (README) · `NOTICE`
