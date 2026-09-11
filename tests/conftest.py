# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Hermetic suite: HOME, the key root and the log root are redirected into the
session's temp tree at configure time, before any test module imports the
package (``loomground_workspace.paths.LOG_ROOT_DEFAULT`` and the decisions
store default are baked from ``Path.home()`` at import)."""
from __future__ import annotations

import os

import pytest
from _pytest.tmpdir import TempPathFactory

def pytest_configure(config):
    factory = TempPathFactory.from_config(config, _ispytest=True)
    home = os.path.realpath(str(factory.mktemp("home", numbered=True)))
    os.environ["HOME"] = home
    os.environ["USERPROFILE"] = home
    os.environ["WORKSPACE_KEY_DIR"] = os.path.join(home, "keys")
    os.environ["WORKSPACES_ALLOW_UNREGISTERED"] = "1"
    for name in ("AGENT_TOOL_LOCK_SESSION_ID", "AGENT_TOOL_LOCK_DECISION_TTL_SECONDS",
                 "LOCK_BETA_STRICT_TOKEN_SIG", "LOCK_CAPABILITY_TRUST_STORE",
                 "WORKSPACE_FOLDER_CONTEXT", "WORKSPACE_SYMLINK_MODE"):
        os.environ.pop(name, None)
    os.makedirs(os.environ["WORKSPACE_KEY_DIR"], exist_ok=True)


@pytest.fixture(autouse=True)
def _unwired_host():
    """Every test starts with no host wired and an empty key cache."""
    from loomground_lock import host_deps, seal_binding
    host_deps.clear()
    seal_binding.lock_all()
    yield
    host_deps.clear()
    seal_binding.lock_all()
