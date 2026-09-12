<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 flxk1 -->
# Changelog

## [0.2.0](https://github.com/flxk1/loomground-lock/compare/loomground-lock-v0.1.0...loomground-lock-v0.2.0) (2026-09-11)


### Features

* extract the lock and seal primitive from the host engine ([b9dc09f](https://github.com/flxk1/loomground-lock/commit/b9dc09f8793720f4f94c3e3917a119d6acb7eec7))


### Bug Fixes

* fail closed when Tier C cannot run, not open ([441ad41](https://github.com/flxk1/loomground-lock/commit/441ad4106f2d36d8af5a76c7f7abc80304636e9f))

## 0.1.0

* Published the lock, decision, oversight, scanning, credential, classification, seal, and seal-binding primitives under `loomground_lock`; `tests/test_surface.py` fixes the public surface.
* Licence: the source files carry `AGPL-3.0-only`, copyright flxk1; this package relicenses them to Apache-2.0 (code) / CC-BY-4.0 (README) by the same copyright holder, following the loomground-workspace extraction precedent. Felix confirms the relicensing.
* Seam changes (`docs/seam.md`): Tier C becomes the `host_deps.tier_c_check_semantic` hook with a built-in deterministic context-term check; `host_deps.ensure_wired()` runs a registered provider (`set_wiring_provider`, `register`) instead of importing a host module; seal reads `LOG_ROOT_DEFAULT`, `folder_hash`, `legacy_folder_hash` from `loomground_workspace`; `verdicts.py` maps lock actions and oversight levels onto `loomground_governance.vocabulary("verdicts")`.
