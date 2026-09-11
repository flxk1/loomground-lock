# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""At-rest encryption for a folder's memory.

``seal_folder`` encrypts a folder's memory store (its log directory under
``LOG_ROOT_DEFAULT/<folder_hash>/`` plus the folder's plaintext knowledge
sinks) into one sealed blob and removes the plaintext; ``unseal_folder``
restores it with the passphrase. Protects the memory at rest — a synced,
copied, backed-up, or lost disk shows ciphertext. Data in use is the host's
concern: while unsealed the plaintext is on disk.

- The audit chain is untouched: files are sealed as opaque bytes.
- The key is scrypt-derived from the passphrase and never written to disk.
- AES-256-GCM authenticates the ciphertext with the folder hash as associated
  data, so a wrong passphrase or a blob moved between folders fails cleanly.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from loomground_workspace.identity import folder_hash, legacy_folder_hash
from loomground_workspace.paths import LOG_ROOT_DEFAULT

from . import host_deps

_MAGIC = "workspace-seal"
_VERSION = 1
# scrypt cost. n=2**14 keeps memory ~16 MB (under the stdlib default maxmem).
_N, _R, _P, _DKLEN = 2 ** 14, 8, 1, 32


class SealError(RuntimeError):
    """Raised when a seal/unseal operation cannot complete."""


def _resolve_log_dir(folder: str | Path, log_root: str | Path | None) -> Path:
    root = Path(log_root) if log_root else LOG_ROOT_DEFAULT
    primary = root / folder_hash(folder)
    if primary.exists():
        return primary
    legacy = root / legacy_folder_hash(folder)
    if legacy.exists():
        return legacy
    return primary


def _sealed_path(log_dir: Path) -> Path:
    return log_dir.parent / (log_dir.name + ".sealed")


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        passphrase.encode("utf-8"), salt=salt, n=_N, r=_R, p=_P, dklen=_DKLEN,
    )


@contextlib.contextmanager
def _file_lock(fh, *, exclusive: bool):
    """Advisory lock over ``fh`` — ``fcntl.flock`` on POSIX, ``msvcrt.locking``
    over the first byte on Windows. The same primitive an appending writer
    holds on ``events.jsonl``, so seal and append serialise. Fails closed."""
    if os.name == "nt":
        import msvcrt
        fh.seek(0)
        msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)
        try:
            yield
        finally:
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        return
    import fcntl
    fcntl.flock(fh.fileno(), fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
    try:
        yield
    finally:
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


# ── per-record encryption — data-in-use hardening ───────────────────────────
# ``seal_folder`` is whole-store, at-rest-only. These encrypt a SINGLE record so
# the on-disk bytes stay ciphertext during a session: a raw-file read sees
# ciphertext. The folder hash is bound as AAD so a record cannot be replayed
# into another folder. Hardening, not a boundary: the process holding the key
# can decrypt.
_REC_MAGIC = b"RVEC1"


def encrypt_record(plaintext: bytes, *, passphrase: str, folder: str | Path) -> bytes:
    """Encrypt one record: ``magic|salt|nonce|ciphertext``."""
    salt, nonce = os.urandom(16), os.urandom(12)
    key = _derive_key(passphrase, salt)
    aad = folder_hash(str(folder)).encode("utf-8")
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return _REC_MAGIC + salt + nonce + ct


def decrypt_record(blob: bytes, *, passphrase: str, folder: str | Path) -> bytes:
    """Decrypt a record in memory. ``SealError`` on a wrong passphrase or a
    record from a different folder (AAD authentication fails)."""
    if blob[:5] != _REC_MAGIC:
        raise SealError("not an encrypted record")
    salt, nonce, ct = blob[5:21], blob[21:33], blob[33:]
    key = _derive_key(passphrase, salt)
    aad = folder_hash(str(folder)).encode("utf-8")
    try:
        return AESGCM(key).decrypt(nonce, ct, aad)
    except InvalidTag as e:
        raise SealError("record decryption failed — wrong passphrase or wrong folder") from e


def is_sealed(folder: str | Path, *, log_root: str | Path | None = None) -> bool:
    return _sealed_path(_resolve_log_dir(folder, log_root)).exists()


# Plaintext knowledge sinks under the FOLDER itself (not the log dir). They are
# packed into the same blob under a distinct prefix so unseal routes them back.
_FOLDER_MEMORY_SINKS: tuple[str, ...] = (".versum", "grounding")
_SINK_PREFIX = "__folder_sink__/"


def _existing_sinks(folder: Path) -> list[tuple[str, Path]]:
    return [(name, folder / name) for name in _FOLDER_MEMORY_SINKS
            if (folder / name).exists()]


def seal_folder(
    folder: str | Path,
    *,
    passphrase: str,
    log_root: str | Path | None = None,
) -> dict[str, Any]:
    """Encrypt the folder's memory (log dir + knowledge sinks) at rest and
    remove the plaintext."""
    if not passphrase:
        raise SealError("a passphrase is required to seal")
    log_dir = _resolve_log_dir(folder, log_root)
    sealed = _sealed_path(log_dir)
    if sealed.exists():
        raise SealError(f"already sealed: {sealed}")
    if not log_dir.exists():
        raise SealError(f"no memory to seal for this folder ({log_dir} does not exist)")

    # Hold the appender's exclusive lock from snapshot to rmtree, so an append
    # either completes before the snapshot or blocks until sealing is done.
    # ``a+`` creates events.jsonl if absent, so the lock object always exists.
    events_file = log_dir / "events.jsonl"
    with open(events_file, "a+", encoding="utf-8") as lock_fh:
        with _file_lock(lock_fh, exclusive=True):
            files: dict[str, str] = {}
            for path in sorted(log_dir.rglob("*")):
                if path.is_file():
                    rel = path.relative_to(log_dir).as_posix()
                    files[rel] = base64.b64encode(path.read_bytes()).decode("ascii")
            folder_sinks = _existing_sinks(Path(folder))
            for name, sink in folder_sinks:
                for path in sorted(sink.rglob("*")):
                    if path.is_file():
                        rel = _SINK_PREFIX + name + "/" + path.relative_to(sink).as_posix()
                        files[rel] = base64.b64encode(path.read_bytes()).decode("ascii")
            plaintext = json.dumps({"files": files}).encode("utf-8")

            salt = os.urandom(16)
            nonce = os.urandom(12)
            key = _derive_key(passphrase, salt)
            aad = log_dir.name.encode("ascii")
            ct = AESGCM(key).encrypt(nonce, plaintext, aad)

            envelope = {
                "magic": _MAGIC,
                "v": _VERSION,
                "kdf": "scrypt",
                "n": _N, "r": _R, "p": _P,
                "salt": base64.b64encode(salt).decode("ascii"),
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "ct": base64.b64encode(ct).decode("ascii"),
            }
            # Write the blob first; delete the plaintext only once it is on disk.
            tmp = sealed.with_suffix(".sealed.tmp")
            tmp.write_text(json.dumps(envelope))
            os.replace(tmp, sealed)
            try:
                os.chmod(sealed, 0o600)
            except OSError:
                pass
            shutil.rmtree(log_dir)
            for _name, sink in folder_sinks:
                shutil.rmtree(sink, ignore_errors=True)

    return {"sealed": True, "path": str(sealed), "files_sealed": len(files)}


def unseal_folder(
    folder: str | Path,
    *,
    passphrase: str,
    log_root: str | Path | None = None,
) -> dict[str, Any]:
    """Decrypt a sealed folder's memory and restore the plaintext directory.

    Pending-erasure markers (host hooks ``pending_erase_verify`` /
    ``pending_erase_apply``) are verified fail-closed BEFORE any decryption and
    applied only after the plaintext is restored. With no hooks this is a no-op.
    """
    if not passphrase:
        raise SealError("a passphrase is required to unseal")
    log_dir = _resolve_log_dir(folder, log_root)
    sealed = _sealed_path(log_dir)
    if not sealed.exists():
        raise SealError(f"not sealed: {sealed} does not exist")
    if log_dir.exists():
        raise SealError(f"refusing to overwrite existing plaintext at {log_dir}")
    for name in _FOLDER_MEMORY_SINKS:
        if (Path(folder) / name).exists():
            raise SealError(
                f"refusing to overwrite existing plaintext at {Path(folder) / name}")

    pending_markers: list[dict[str, Any]] = []
    host_deps.ensure_wired()
    if host_deps.pending_erase_verify is not None:
        pending_markers = list(host_deps.pending_erase_verify(
            folder, log_dir=log_dir, sealed_path=sealed, log_root=log_root) or [])

    envelope = json.loads(sealed.read_text())
    if envelope.get("magic") != _MAGIC:
        raise SealError("not a Workspace seal file")
    salt = base64.b64decode(envelope["salt"])
    nonce = base64.b64decode(envelope["nonce"])
    ct = base64.b64decode(envelope["ct"])
    key = hashlib.scrypt(
        passphrase.encode("utf-8"), salt=salt,
        n=envelope.get("n", _N), r=envelope.get("r", _R),
        p=envelope.get("p", _P), dklen=_DKLEN,
    )
    aad = log_dir.name.encode("ascii")
    try:
        plaintext = AESGCM(key).decrypt(nonce, ct, aad)
    except InvalidTag:
        raise SealError("wrong passphrase or corrupted seal — nothing restored")

    manifest = json.loads(plaintext.decode("utf-8"))
    log_dir.mkdir(parents=True, exist_ok=True)
    n = 0
    for rel, b64 in manifest.get("files", {}).items():
        if rel.startswith(_SINK_PREFIX):
            dest = Path(folder) / rel[len(_SINK_PREFIX):]
        else:
            dest = log_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(base64.b64decode(b64))
        try:
            os.chmod(dest, 0o600)
        except OSError:
            pass
        n += 1
    sealed.unlink()
    result: dict[str, Any] = {"unsealed": True, "files_restored": n}

    if pending_markers and host_deps.pending_erase_apply is not None:
        result["pending_erase_applied"] = host_deps.pending_erase_apply(
            folder, pending_markers, log_root=log_root)

    return result


# ── "sealed but served" read-through (no unseal-to-disk) ─────────────────────

def _open_sealed(
    sealed: Path, aad_name: str, *,
    passphrase: str | None = None, key: bytes | None = None,
) -> tuple[dict[str, str], bytes]:
    """Decrypt a sealed envelope; return ``({rel: b64}, key)``. Accepts a
    passphrase (scrypt) or a pre-derived key. Pure read."""
    envelope = json.loads(sealed.read_text())
    if envelope.get("magic") != _MAGIC:
        raise SealError("not a Workspace seal file")
    salt = base64.b64decode(envelope["salt"])
    nonce = base64.b64decode(envelope["nonce"])
    ct = base64.b64decode(envelope["ct"])
    if key is None:
        if not passphrase:
            raise SealError("a passphrase or key is required")
        key = hashlib.scrypt(
            passphrase.encode("utf-8"), salt=salt,
            n=envelope.get("n", _N), r=envelope.get("r", _R),
            p=envelope.get("p", _P), dklen=_DKLEN,
        )
    aad = aad_name.encode("ascii")
    try:
        plaintext = AESGCM(key).decrypt(nonce, ct, aad)
    except InvalidTag:
        raise SealError("wrong passphrase or corrupted seal")
    return json.loads(plaintext.decode("utf-8")).get("files", {}), key


def open_sealed_store(
    folder: str | Path, *,
    passphrase: str | None = None, key: bytes | None = None,
    log_root: str | Path | None = None,
) -> tuple[dict[str, bytes], bytes]:
    """Decrypt a sealed folder's store into memory; return ``({relpath: bytes}, key)``.
    The ``.sealed`` blob is left untouched and nothing is written to disk."""
    log_dir = _resolve_log_dir(folder, log_root)
    sealed = _sealed_path(log_dir)
    if not sealed.exists():
        raise SealError(f"not sealed: {sealed} does not exist")
    files, used_key = _open_sealed(sealed, log_dir.name, passphrase=passphrase, key=key)
    return {rel: base64.b64decode(b64) for rel, b64 in files.items()}, used_key


def read_through(
    folder: str | Path,
    *,
    passphrase: str,
    log_root: str | Path | None = None,
) -> dict[str, bytes]:
    """Decrypt a SEALED folder's memory into memory: ``{relpath: bytes}``. The
    disk stays ciphertext. ``SealError`` if unsealed or the passphrase is wrong."""
    if not passphrase:
        raise SealError("a passphrase is required to read through a sealed workspace")
    mapping, _ = open_sealed_store(folder, passphrase=passphrase, log_root=log_root)
    return mapping


def read_through_file(
    folder: str | Path,
    relpath: str,
    *,
    passphrase: str,
    log_root: str | Path | None = None,
) -> bytes:
    data = read_through(folder, passphrase=passphrase, log_root=log_root)
    if relpath not in data:
        raise SealError(f"{relpath!r} is not in the sealed store")
    return data[relpath]
