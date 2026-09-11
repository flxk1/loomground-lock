# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Host-injected dependencies — the outbound half of the lock boundary.

Every hook is a module attribute, ``None`` until a host fills it. The lock
reaches a host only through these attributes, so a host that wires nothing
gets the documented degraded behaviour at each call site — for Tier C, the
package's own built-in default tier (:mod:`loomground_lock.tier_c_default`).
Two ways to wire:

- ``register(**hooks)`` assigns hooks directly;
- ``set_wiring_provider(fn)`` defers to ``fn`` on the first
  ``ensure_wired()`` call, which the call sites make lazily.

``ensure_wired()`` is total — it raises nothing, whatever the provider does —
but a provider that raises is RECORDED, not swallowed: ``wiring_error()``
reports the exception class name, and a call site whose hooks may be missing
because of it treats its tier as unavailable and fails closed. The record is
sticky; ``set_wiring_provider()`` or ``clear()`` resets it.

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
# built-in context-term check and the built-in default semantic tier run in its
# place; see ``core._tier_c``.
tier_c_check_semantic: Optional[Callable[..., Any]] = None
# ``() -> bool``: True when the host has a real semantic backend configured, so a
# Tier C that cannot run must fail closed — consulted whether or not
# ``tier_c_check_semantic`` is wired. Absent → False (nothing was promised).
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
_wiring_error: Optional[str] = None


def set_wiring_provider(provider: Optional[Callable[[], Any]]) -> None:
    """Install the callable that fills the hooks on first use. Resets a
    previously recorded wiring failure."""
    global _provider, _wired, _wiring_error
    _provider = provider
    _wired = False
    _wiring_error = None


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
    """Drop every hook, the provider and any recorded wiring failure."""
    global _provider, _wired, _wiring_error
    for name in HOOKS:
        globals()[name] = None
    _provider = None
    _wired = False
    _wiring_error = None


def ensure_wired() -> None:
    """Run the provider once. Total: a provider that raises is recorded in
    ``wiring_error()``, leaving the hooks it meant to fill unknown, and call
    sites fail closed on that."""
    global _wired, _wiring_error
    if _wired:
        return
    _wired = True
    if _provider is None:
        return
    try:
        _provider()
    except Exception as e:  # noqa: BLE001
        # class name only — a provider's message can carry paths or credentials.
        _wiring_error = type(e).__name__


def wiring_error() -> Optional[str]:
    """The exception class name of a wiring provider that raised, else ``None``.
    Sticky until ``set_wiring_provider()`` or ``clear()``."""
    return _wiring_error


def wired() -> dict[str, bool]:
    """Which hooks a host has filled — for diagnostics, not for gating."""
    return {name: globals()[name] is not None for name in HOOKS}
