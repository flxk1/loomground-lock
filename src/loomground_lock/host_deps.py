# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Host-injected dependencies — the outbound half of the lock boundary.

Every hook is a module attribute, ``None`` until a host fills it. The lock
reaches a host only through these attributes, so a host that wires nothing
gets the documented degraded behaviour at each call site (fail-safe, never
fail-open). Two ways to wire:

- ``register(**hooks)`` assigns hooks directly;
- ``set_wiring_provider(fn)`` defers to ``fn`` on the first
  ``ensure_wired()`` call, which the call sites make lazily.

Identity matters: hooks live on THIS module object. A host shim that
re-exports the lock under another name must alias the same module object
(``sys.modules``), or its assignments land on a copy and silently no-op.
"""
from __future__ import annotations

from typing import Any, Callable, Optional, Sequence

models_for_role: Optional[Callable[[str], Sequence[str]]] = None
llm_classify: Optional[Callable[..., Any]] = None
key_root_dir: Optional[Callable[[], Any]] = None
record_decision: Optional[Callable[..., str]] = None
list_connectors: Optional[Callable[..., Any]] = None
l0_load_policy: Optional[Callable[..., Any]] = None
l0_capture_llm: Optional[Callable[..., Any]] = None
l0_capture_web: Optional[Callable[..., Any]] = None
list_models: Optional[Callable[[], Any]] = None
registry_models_for_role: Optional[Callable[[str], Any]] = None
capability_verifier_factory: Optional[Callable[[], Any]] = None
record_capability_refusal: Optional[Callable[..., Any]] = None
govern_egress: Optional[Callable[..., Any]] = None
verify_agent_identity: Optional[Callable[..., Any]] = None
record_audit_drop: Optional[Callable[..., Any]] = None

# Tier C semantic check: ``(text, context="") -> list[Finding]``. Absent → the
# built-in deterministic context-term check runs and semantic classification
# is skipped; see ``core.lock_text``.
tier_c_check_semantic: Optional[Callable[..., Any]] = None
# ``() -> bool``: True when the host has a real semantic backend configured, so a
# failing Tier C must fail closed. Absent → False (nothing was promised).
tier_c_requires_real_backend: Optional[Callable[[], bool]] = None
# ``() -> dict``: payload for the ``disable_lock`` remediation action (how the
# host lets a person opt out, and where its disclaimer lives).
disable_lock_remediation: Optional[Callable[[], dict]] = None
# ``(source, folder_path) -> str``: an opaque per-folder document token.
opaque_doc_token: Optional[Callable[..., str]] = None
# ``(folder_context, log_root, actor) -> memory`` exposing ``all_pairs()`` and
# ``remember(pair, channel=..., source_hash=...)``.
workspace_memory: Optional[Callable[..., Any]] = None
# Pending-erasure markers around unseal: verify before decrypting, apply after
# restoring. Absent → no markers.
pending_erase_verify: Optional[Callable[..., Any]] = None
pending_erase_apply: Optional[Callable[..., Any]] = None
# Served-store readers: ``(bytes) -> iterator of events``, ``(event) -> pair|None``,
# ``(store) -> records``, ``(folder) -> records``.
events_from_bytes: Optional[Callable[..., Any]] = None
pair_from_event: Optional[Callable[..., Any]] = None
read_served_versum_records: Optional[Callable[..., Any]] = None
read_disk_versum_records: Optional[Callable[..., Any]] = None

HOOKS: tuple[str, ...] = tuple(
    name for name, value in list(globals().items())
    if not name.startswith("_") and value is None
)

_provider: Optional[Callable[[], Any]] = None
_wired = False


def set_wiring_provider(provider: Optional[Callable[[], Any]]) -> None:
    """Install the callable that fills the hooks on first use."""
    global _provider, _wired
    _provider = provider
    _wired = False


def register(**hooks: Optional[Callable[..., Any]]) -> None:
    """Assign hooks by name. Unknown names are an error; ``None`` clears one."""
    unknown = sorted(set(hooks) - set(HOOKS))
    if unknown:
        raise ValueError(f"unknown host hooks: {unknown}")
    for name, fn in hooks.items():
        if fn is not None and not callable(fn):
            raise TypeError(f"hook {name!r} must be callable or None")
        globals()[name] = fn


def clear() -> None:
    """Drop every hook and the provider (test isolation)."""
    global _provider, _wired
    for name in HOOKS:
        globals()[name] = None
    _provider = None
    _wired = False


def ensure_wired() -> None:
    global _wired
    if _wired:
        return
    _wired = True
    if _provider is None:
        return
    try:
        _provider()
    except Exception:
        pass


def wired() -> dict[str, bool]:
    """Which hooks a host has filled — for diagnostics, never for gating."""
    return {name: globals()[name] is not None for name in HOOKS}
