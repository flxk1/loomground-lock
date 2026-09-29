<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 flxk1 -->
# Changelog

## [0.2.1](https://github.com/flxk1/loomground-lock/compare/loomground-lock-v0.2.0...loomground-lock-v0.2.1) (2026-09-29)


### Bug Fixes

* **release:** extra-files marker, version 0.2.0 matches the tag ([a6ec38b](https://github.com/flxk1/loomground-lock/commit/a6ec38b490c112a940a4d91626854e6faf7011c1))


### Documentation

* correct stale claims; add How this is made ([a082d66](https://github.com/flxk1/loomground-lock/commit/a082d6643f212d48a449f16737267df4d9ddc669))
* How this is made names no model vendor ([7012fa2](https://github.com/flxk1/loomground-lock/commit/7012fa289cc2493f16fd0f8b37acd3d937bc30ce))
* install from checkout; add How this is made; align NOTICE ([3126407](https://github.com/flxk1/loomground-lock/commit/31264077c58e9ca2d84ef18a9b5ec4f55a9f8851))

## [0.2.0](https://github.com/flxk1/loomground-lock/compare/loomground-lock-v0.1.0...loomground-lock-v0.2.0) (2026-09-11)


### Features

* extract the lock and seal primitive from the host engine ([b9dc09f](https://github.com/flxk1/loomground-lock/commit/b9dc09f8793720f4f94c3e3917a119d6acb7eec7))


### Bug Fixes

* fail closed when Tier C cannot run, not open ([441ad41](https://github.com/flxk1/loomground-lock/commit/441ad4106f2d36d8af5a76c7f7abc80304636e9f))

## 0.1.0

* Published the lock, decision, oversight, scanning, credential, classification, seal, and seal-binding primitives under `loomground_lock`; `tests/test_surface.py` fixes the public surface.
* Licence: the source files carry `AGPL-3.0-only`, copyright flxk1; this package relicenses them to Apache-2.0 (code) / CC-BY-4.0 (README) by the same copyright holder, following the loomground-workspace extraction precedent. Felix confirms the relicensing.
* Seam changes (`docs/seam.md`): Tier C becomes the `host_deps.tier_c_check_semantic` hook with a built-in deterministic context-term check; `host_deps.ensure_wired()` runs a registered provider (`set_wiring_provider`, `register`) instead of importing a host module; seal reads `LOG_ROOT_DEFAULT`, `folder_hash`, `legacy_folder_hash` from `loomground_workspace`; `verdicts.py` maps lock actions and oversight levels onto `loomground_governance.vocabulary("verdicts")`.
