# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""At-rest sealing: round trip, wrong passphrase, knowledge sinks, read-through,
per-record encryption. The log dir is seeded directly (the store is opaque bytes)."""
from __future__ import annotations

import json

import pytest
from loomground_workspace.identity import folder_hash, legacy_folder_hash
from loomground_workspace.paths import LOG_ROOT_DEFAULT

from loomground_lock import host_deps, seal


def _seed(folder, log_root, n=3, secret="item"):
    log_dir = log_root / folder_hash(folder)
    log_dir.mkdir(parents=True)
    events = [json.dumps({"event": "ingest", "pair_id": f"p{i}",
                          "extra": {"pair": {"id": f"p{i}", "problem": {"summary": f"{secret} {i}"}}}})
              for i in range(n)]
    (log_dir / "events.jsonl").write_text("\n".join(events) + "\n")
    (log_dir / "meta.json").write_text('{"v": 1}')
    return log_dir


def test_seal_unseal_round_trip_preserves_bytes(tmp_path):
    folder = tmp_path / "wks"; folder.mkdir()
    log_root = tmp_path / "log"
    log_dir = _seed(folder, log_root)
    before = {p.name: p.read_bytes() for p in log_dir.iterdir()}
    assert not seal.is_sealed(folder, log_root=log_root)

    out = seal.seal_folder(folder, passphrase="pw-123", log_root=log_root)
    assert out["sealed"] and out["files_sealed"] == 2
    assert seal.is_sealed(folder, log_root=log_root)
    assert not log_dir.exists()

    res = seal.unseal_folder(folder, passphrase="pw-123", log_root=log_root)
    assert res["unsealed"] and res["files_restored"] == 2
    assert not seal.is_sealed(folder, log_root=log_root)
    assert {p.name: p.read_bytes() for p in log_dir.iterdir()} == before


def test_seal_covers_knowledge_sinks_no_plaintext_leak(tmp_path):
    folder = tmp_path / "wks"; folder.mkdir()
    log_root = tmp_path / "log"
    _seed(folder, log_root, n=1)
    secret = "UNIQUE_SEALED_KNOWLEDGE_TOKEN_9f3a"
    (folder / ".versum").mkdir(); (folder / ".versum" / "records.jsonl").write_text(secret)
    (folder / "grounding").mkdir(); (folder / "grounding" / "g.json").write_text(secret)

    def hits():
        return [p for p in tmp_path.rglob("*") if p.is_file() and secret.encode() in p.read_bytes()]

    assert hits()
    seal.seal_folder(folder, passphrase="pw", log_root=log_root)
    assert not (folder / ".versum").exists() and not (folder / "grounding").exists()
    assert hits() == []
    seal.unseal_folder(folder, passphrase="pw", log_root=log_root)
    assert (folder / ".versum" / "records.jsonl").read_text() == secret
    assert (folder / "grounding" / "g.json").read_text() == secret


def test_wrong_passphrase_restores_nothing(tmp_path):
    folder = tmp_path / "wks"; folder.mkdir()
    log_root = tmp_path / "log"
    _seed(folder, log_root, n=2)
    seal.seal_folder(folder, passphrase="correct-horse", log_root=log_root)
    with pytest.raises(seal.SealError):
        seal.unseal_folder(folder, passphrase="wrong", log_root=log_root)
    assert seal.is_sealed(folder, log_root=log_root)
    seal.unseal_folder(folder, passphrase="correct-horse", log_root=log_root)
    assert not seal.is_sealed(folder, log_root=log_root)


def test_double_seal_and_overwrite_are_refused(tmp_path):
    folder = tmp_path / "wks"; folder.mkdir()
    log_root = tmp_path / "log"
    log_dir = _seed(folder, log_root, n=1)
    seal.seal_folder(folder, passphrase="pw", log_root=log_root)
    with pytest.raises(seal.SealError):
        seal.seal_folder(folder, passphrase="pw", log_root=log_root)
    log_dir.mkdir()
    with pytest.raises(seal.SealError, match="refusing to overwrite"):
        seal.unseal_folder(folder, passphrase="pw", log_root=log_root)


def test_seal_requires_passphrase_and_existing_memory(tmp_path):
    folder = tmp_path / "wks"; folder.mkdir()
    log_root = tmp_path / "log"
    _seed(folder, log_root, n=1)
    with pytest.raises(seal.SealError):
        seal.seal_folder(folder, passphrase="", log_root=log_root)
    empty = tmp_path / "empty"; empty.mkdir()
    with pytest.raises(seal.SealError):
        seal.seal_folder(empty, passphrase="pw", log_root=log_root)


def test_sealed_blob_is_not_plaintext_and_is_private(tmp_path):
    folder = tmp_path / "wks"; folder.mkdir()
    log_root = tmp_path / "log"
    _seed(folder, log_root, n=1, secret="topsecret")
    seal.seal_folder(folder, passphrase="pw", log_root=log_root)
    blob = next(log_root.rglob("*.sealed"))
    raw = blob.read_text()
    assert "topsecret" not in raw
    assert "workspace-seal" in raw
    assert (blob.stat().st_mode & 0o777) == 0o600


def test_read_through_serves_without_unsealing(tmp_path):
    folder = tmp_path / "wks"; folder.mkdir()
    log_root = tmp_path / "log"
    log_dir = _seed(folder, log_root, n=3)
    before = {p.name: p.read_bytes() for p in log_dir.iterdir()}
    seal.seal_folder(folder, passphrase="pw-123", log_root=log_root)
    served = seal.read_through(folder, passphrase="pw-123", log_root=log_root)
    assert served == before
    assert seal.read_through_file(folder, "events.jsonl", passphrase="pw-123", log_root=log_root) == before["events.jsonl"]
    assert seal.is_sealed(folder, log_root=log_root)
    assert not log_dir.exists()
    with pytest.raises(seal.SealError):
        seal.read_through(folder, passphrase="wrong", log_root=log_root)
    with pytest.raises(seal.SealError):
        seal.read_through_file(folder, "missing", passphrase="pw-123", log_root=log_root)


def test_read_through_on_unsealed_folder_raises(tmp_path):
    folder = tmp_path / "wks"; folder.mkdir()
    log_root = tmp_path / "log"
    _seed(folder, log_root, n=1)
    with pytest.raises(seal.SealError):
        seal.read_through(folder, passphrase="pw", log_root=log_root)


PLAIN = b"controller: acme; special-category data: health records for 12,000 patients"


def test_record_round_trip_and_ciphertext_opaque():
    blob = seal.encrypt_record(PLAIN, passphrase="correct horse", folder="/tmp/folder-a")
    assert PLAIN not in blob
    assert blob[:5] == seal._REC_MAGIC == b"RVEC1"
    assert seal.decrypt_record(blob, passphrase="correct horse", folder="/tmp/folder-a") == PLAIN


def test_record_wrong_passphrase_and_wrong_folder_fail():
    blob = seal.encrypt_record(PLAIN, passphrase="right", folder="/tmp/folder-a")
    with pytest.raises(seal.SealError):
        seal.decrypt_record(blob, passphrase="wrong", folder="/tmp/folder-a")
    with pytest.raises(seal.SealError):
        seal.decrypt_record(blob, passphrase="right", folder="/tmp/folder-b")
    with pytest.raises(seal.SealError):
        seal.decrypt_record(b"XXXXX" + blob[5:], passphrase="right", folder="/tmp/folder-a")


def test_resolve_log_dir_prefers_current_hash_then_legacy(tmp_path):
    folder = tmp_path / "Wks"
    folder.mkdir()
    log_root = tmp_path / "log"
    legacy = log_root / legacy_folder_hash(folder)
    assert seal._resolve_log_dir(folder, log_root) == log_root / folder_hash(folder)
    if legacy_folder_hash(folder) != folder_hash(folder):
        legacy.mkdir(parents=True)
        assert seal._resolve_log_dir(folder, log_root) == legacy


def test_default_log_root_and_identity_come_from_loomground_workspace(tmp_path):
    import inspect
    import loomground_workspace.identity as ident
    import loomground_workspace.paths as paths
    assert seal.LOG_ROOT_DEFAULT is paths.LOG_ROOT_DEFAULT is LOG_ROOT_DEFAULT
    assert seal.folder_hash is ident.folder_hash
    assert seal.legacy_folder_hash is ident.legacy_folder_hash
    src = inspect.getsource(seal)
    assert "def folder_hash" not in src and "LOG_ROOT_DEFAULT =" not in src
    assert seal._resolve_log_dir(tmp_path, None).parent == LOG_ROOT_DEFAULT


def test_unseal_runs_pending_erase_hooks_in_order(tmp_path):
    folder = tmp_path / "wks"; folder.mkdir()
    log_root = tmp_path / "log"
    log_dir = _seed(folder, log_root, n=1)
    seal.seal_folder(folder, passphrase="pw", log_root=log_root)
    calls = []

    def verify(f, *, log_dir, sealed_path, log_root):
        calls.append(("verify", log_dir.exists()))
        return [{"marker": 1}]

    def apply(f, markers, *, log_root):
        calls.append(("apply", log_dir.exists(), markers))
        return {"applied": len(markers)}

    host_deps.register(pending_erase_verify=verify, pending_erase_apply=apply)
    res = seal.unseal_folder(folder, passphrase="pw", log_root=log_root)
    assert res["pending_erase_applied"] == {"applied": 1}
    assert calls == [("verify", False), ("apply", True, [{"marker": 1}])]


def test_unseal_aborts_before_decrypting_when_verify_refuses(tmp_path):
    folder = tmp_path / "wks"; folder.mkdir()
    log_root = tmp_path / "log"
    log_dir = _seed(folder, log_root, n=1)
    seal.seal_folder(folder, passphrase="pw", log_root=log_root)

    def verify(*a, **k):
        raise seal.SealError("forged marker")

    host_deps.register(pending_erase_verify=verify)
    with pytest.raises(seal.SealError, match="forged"):
        seal.unseal_folder(folder, passphrase="pw", log_root=log_root)
    assert seal.is_sealed(folder, log_root=log_root) and not log_dir.exists()
