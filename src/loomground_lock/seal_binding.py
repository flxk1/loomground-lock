# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Unlock + served reads over :mod:`.seal` — the 'one wall' switch.

One state per workspace:

- **locked** — sealed on disk (ciphertext) and no derived key is held; reads
  are refused until :func:`unlock`.
- **unlocked (this process)** — the passphrase was supplied once; the derived
  AES key stays in this process's memory so reads decrypt in memory without
  unsealing to disk and without re-deriving the key each time.

The escape hatch for direct file access is ``seal.unseal_folder`` (writes
plaintext back) — a separate, deliberate act. The key cache is process
memory only: ``lock()`` or process exit drops it. It is a cryptographic
key cache keyed by folder hash — no identity, principal or host session
is bound here.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator

from . import host_deps, seal

# folder-hash (the log-dir name) -> derived AES key. In-memory only.
_SESSION: dict[str, bytes] = {}


def _name(folder: str | Path, log_root: str | Path | None) -> str:
    return seal._resolve_log_dir(folder, log_root).name


def is_sealed(folder: str | Path, *, log_root: str | Path | None = None) -> bool:
    return seal.is_sealed(folder, log_root=log_root)


def is_unlocked(folder: str | Path, *, log_root: str | Path | None = None) -> bool:
    return _name(folder, log_root) in _SESSION


def unlock(
    folder: str | Path, *, passphrase: str, log_root: str | Path | None = None,
) -> dict[str, Any]:
    """Verify the passphrase against the sealed blob and cache the derived key.
    Raises :class:`seal.SealError` on a wrong passphrase / not sealed. Writes
    nothing to disk."""
    mapping, key = seal.open_sealed_store(
        folder, passphrase=passphrase, log_root=log_root)
    _SESSION[_name(folder, log_root)] = key
    return {"unlocked": True, "files": len(mapping)}


def lock(folder: str | Path, *, log_root: str | Path | None = None) -> dict[str, Any]:
    """Drop the cached key (re-locks the workspace for reading)."""
    existed = _SESSION.pop(_name(folder, log_root), None) is not None
    return {"locked": True, "was_unlocked": existed}


def lock_all() -> int:
    n = len(_SESSION)
    _SESSION.clear()
    return n


def state(folder: str | Path, *, log_root: str | Path | None = None) -> dict[str, Any]:
    sealed = is_sealed(folder, log_root=log_root)
    return {
        "sealed": sealed,
        "unlocked": is_unlocked(folder, log_root=log_root),
        "wall": "up" if sealed else "down",
    }


def serve(folder: str | Path, *, log_root: str | Path | None = None) -> dict[str, bytes]:
    """The workspace's memory store as ``{relpath: bytes}``: from disk when
    unsealed; decrypted in memory when sealed + unlocked; refused when sealed
    + locked."""
    if not is_sealed(folder, log_root=log_root):
        log_dir = seal._resolve_log_dir(folder, log_root)
        if not log_dir.exists():
            return {}
        return {p.relative_to(log_dir).as_posix(): p.read_bytes()
                for p in sorted(log_dir.rglob("*")) if p.is_file()}
    key = _SESSION.get(_name(folder, log_root))
    if key is None:
        raise seal.SealError(
            "workspace is locked — unlock(folder, passphrase=…) to read it, "
            "or unseal it for direct access")
    mapping, _ = seal.open_sealed_store(folder, key=key, log_root=log_root)
    return mapping


def serve_file(
    folder: str | Path, relpath: str, *, log_root: str | Path | None = None,
) -> bytes:
    store = serve(folder, log_root=log_root)
    if relpath not in store:
        raise seal.SealError(f"{relpath!r} is not in the workspace's store")
    return store[relpath]


def _events_from_bytes(raw: bytes) -> Iterator[Any]:
    """The host's ``events_from_bytes`` hook, else newline-delimited JSON
    objects (malformed lines skipped)."""
    host_deps.ensure_wired()
    if host_deps.events_from_bytes is not None:
        return iter(host_deps.events_from_bytes(raw))

    def gen():
        for line in raw.splitlines():
            try:
                s = line.decode("utf-8").strip()
            except UnicodeDecodeError:
                continue
            if not s:
                continue
            try:
                obj = json.loads(s)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                yield obj
    return gen()


def _pair_from_event(evt: Any) -> dict | None:
    """The host's ``pair_from_event`` hook, else the ``extra.pair`` dict."""
    if host_deps.pair_from_event is not None:
        return host_deps.pair_from_event(evt)
    extra = evt.get("extra") if isinstance(evt, dict) else getattr(evt, "extra", None)
    pair = extra.get("pair") if isinstance(extra, dict) else None
    return pair if isinstance(pair, dict) else None


def replay(folder: str | Path, *, log_root: str | Path | None = None):
    """Iterate a workspace's events from its served store. Raises
    :class:`seal.SealError` if sealed + locked."""
    store = serve(folder, log_root=log_root)
    raw = store.get("events.jsonl")
    return _events_from_bytes(raw) if raw else iter(())


def read_pairs(folder: str | Path, *, log_root: str | Path | None = None) -> dict:
    """``{pair_id: pair}`` from the served chain (last-write-wins over
    pair-creating events), unioned with knowledge bodies from the folder's
    knowledge sink when the host wires ``read_served_versum_records`` /
    ``read_disk_versum_records``. Raises if sealed + locked."""
    store = serve(folder, log_root=log_root)
    out: dict = {}
    raw = store.get("events.jsonl")
    for evt in (_events_from_bytes(raw) if raw else ()):
        pair = _pair_from_event(evt)
        if pair is not None:
            pid = pair.get("id") or (pair.get("problem") or {}).get("id")
            if pid:
                out[pid] = pair
    served = host_deps.read_served_versum_records
    on_disk = host_deps.read_disk_versum_records
    if any(k.startswith(seal._SINK_PREFIX + ".versum/") for k in store):
        records = served(store) if served is not None else ()
    else:
        records = on_disk(folder) if on_disk is not None else ()
    for rec in records:
        body = rec.get("properties", {}).get("record") if isinstance(rec, dict) else None
        if isinstance(body, dict):
            pid = body.get("id") or (body.get("problem") or {}).get("id")
            if pid:
                out.setdefault(pid, body)
    return out
