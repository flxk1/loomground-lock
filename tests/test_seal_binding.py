# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Unlock + served reads: the key cache is process memory, the disk stays ciphertext."""
from __future__ import annotations

import json

import pytest
from loomground_workspace.identity import folder_hash

from loomground_lock import host_deps, seal, seal_binding as SB


def _seed(folder, log_root, pairs):
    log_dir = log_root / folder_hash(folder)
    log_dir.mkdir(parents=True)
    lines = [json.dumps({"event": "ingest", "pair_id": p["id"], "extra": {"pair": p}}) for p in pairs]
    lines.insert(1, "not json")
    lines.append(json.dumps({"event": "admit", "pair_id": pairs[0]["id"], "extra": {}}))
    (log_dir / "events.jsonl").write_text("\n".join(lines) + "\n")
    return log_dir


PAIRS = [{"id": "p1", "problem": {"id": "p1", "summary": "one"}},
         {"id": "p2", "problem": {"id": "p2", "summary": "two"}},
         {"id": "p1", "problem": {"id": "p1", "summary": "one-v2"}}]


def test_unsealed_folder_is_served_from_disk(tmp_path):
    folder = tmp_path / "wks"; folder.mkdir(); log_root = tmp_path / "log"
    _seed(folder, log_root, PAIRS)
    assert SB.state(folder, log_root=log_root) == {"sealed": False, "unlocked": False, "wall": "down"}
    store = SB.serve(folder, log_root=log_root)
    assert set(store) == {"events.jsonl"}
    assert SB.serve_file(folder, "events.jsonl", log_root=log_root) == store["events.jsonl"]
    assert SB.serve(tmp_path / "nowhere", log_root=log_root) == {}


def test_sealed_locked_refuses_then_unlock_serves_in_memory(tmp_path):
    folder = tmp_path / "wks"; folder.mkdir(); log_root = tmp_path / "log"
    log_dir = _seed(folder, log_root, PAIRS)
    plain = (log_dir / "events.jsonl").read_bytes()
    seal.seal_folder(folder, passphrase="pw", log_root=log_root)

    assert SB.state(folder, log_root=log_root)["wall"] == "up"
    with pytest.raises(seal.SealError, match="locked"):
        SB.serve(folder, log_root=log_root)
    with pytest.raises(seal.SealError):
        SB.unlock(folder, passphrase="wrong", log_root=log_root)
    assert not SB.is_unlocked(folder, log_root=log_root)

    res = SB.unlock(folder, passphrase="pw", log_root=log_root)
    assert res == {"unlocked": True, "files": 1}
    assert SB.is_unlocked(folder, log_root=log_root)
    assert SB.serve_file(folder, "events.jsonl", log_root=log_root) == plain
    assert seal.is_sealed(folder, log_root=log_root) and not log_dir.exists()

    assert SB.lock(folder, log_root=log_root) == {"locked": True, "was_unlocked": True}
    with pytest.raises(seal.SealError):
        SB.serve(folder, log_root=log_root)
    assert SB.lock(folder, log_root=log_root)["was_unlocked"] is False


def test_lock_all_drops_every_key(tmp_path):
    log_root = tmp_path / "log"
    for name in ("a", "b"):
        folder = tmp_path / name; folder.mkdir()
        _seed(folder, log_root, PAIRS)
        seal.seal_folder(folder, passphrase="pw", log_root=log_root)
        SB.unlock(folder, passphrase="pw", log_root=log_root)
    assert SB.lock_all() == 2
    assert SB.lock_all() == 0


def test_replay_and_read_pairs_without_host_hooks(tmp_path):
    folder = tmp_path / "wks"; folder.mkdir(); log_root = tmp_path / "log"
    _seed(folder, log_root, PAIRS)
    events = list(SB.replay(folder, log_root=log_root))
    assert [e["event"] for e in events] == ["ingest", "ingest", "ingest", "admit"]
    pairs = SB.read_pairs(folder, log_root=log_root)
    assert set(pairs) == {"p1", "p2"}
    assert pairs["p1"]["problem"]["summary"] == "one-v2"
    assert list(SB.replay(tmp_path / "nowhere", log_root=log_root)) == []


def test_read_pairs_serves_sealed_unlocked_and_uses_host_hooks(tmp_path):
    folder = tmp_path / "wks"; folder.mkdir(); log_root = tmp_path / "log"
    _seed(folder, log_root, PAIRS)
    (folder / ".versum").mkdir()
    (folder / ".versum" / "r.jsonl").write_text("{}")
    seal.seal_folder(folder, passphrase="pw", log_root=log_root)
    with pytest.raises(seal.SealError):
        SB.read_pairs(folder, log_root=log_root)
    SB.unlock(folder, passphrase="pw", log_root=log_root)

    seen = {}
    host_deps.register(
        events_from_bytes=lambda raw: [json.loads(l) for l in raw.decode().splitlines() if l.startswith("{")],
        pair_from_event=lambda e: e["extra"].get("pair"),
        read_served_versum_records=lambda store: seen.setdefault("store", store) and [
            {"properties": {"record": {"id": "k1", "problem": {"id": "k1"}}}},
            {"properties": {"record": {"id": "p2", "problem": {"summary": "shadowed"}}}}],
        read_disk_versum_records=lambda f: pytest.fail("disk reader must not run for a sealed store"),
    )
    pairs = SB.read_pairs(folder, log_root=log_root)
    assert set(pairs) == {"p1", "p2", "k1"}
    assert pairs["p2"]["problem"]["summary"] == "two"
    assert "__folder_sink__/.versum/r.jsonl" in seen["store"]
