"""Shared fixtures for the metadata runtime tests."""

from __future__ import annotations

import pytest

# The caches the metadata_parts fragments share, with the value each one holds
# on a freshly imported module. Six test modules used to carry their own copy of
# this list; keeping it in one place means a name that moves again is re-pointed
# once rather than six times.
_RUNTIME_STATE_DEFAULTS = {
    "_base_metadata_cache": None,
    "_base_metadata_mtime": None,
    "_base_metadata_source": None,
    "_base_verifier_cache": None,
    "_base_verifier_mtime": None,
    "_base_metadata_trust_verified": None,
    "_base_metadata_entry_ids": frozenset(),
    "_base_explorer_snapshot_cache": None,
    "_base_explorer_snapshot_mtime": None,
    "_base_full_snapshot_cache": None,
    "_base_full_snapshot_mtime": None,
    "_session_metadata_entry_ids": frozenset(),
    "_session_metadata_last_cleanup": 0.0,
    "_session_cleanup_worker": None,
    "_session_cleanup_pending": False,
}


@pytest.fixture
def metadata_runtime_state(monkeypatch):
    """Reset the shared metadata runtime caches for the duration of one test.

    ``raising`` is deliberately left at its default. These names moved here from
    ``server.app.metadata`` once already; if one moves again, the patch must fail
    loudly rather than quietly resetting nothing and leaving the test to pass
    while exercising stale state.
    """

    state = pytest.importorskip("server.app.metadata_parts.runtime_state")
    for name, default in _RUNTIME_STATE_DEFAULTS.items():
        monkeypatch.setattr(state, name, set() if default is frozenset() else default)
    return state


@pytest.fixture
def identity_runtime():
    """The fragment that defines the session identity helpers.

    Patch here rather than on ``server.app.metadata``: the other fragments call
    these through this module, so this is the binding that is actually read.
    """

    return pytest.importorskip("server.app.metadata_parts.session_identity_runtime")


@pytest.fixture
def payload_runtime():
    """The fragment that defines the entry payload helpers."""

    return pytest.importorskip("server.app.metadata_parts.entry_payload_runtime")


@pytest.fixture
def snapshot_runtime():
    """The fragment that defines the base/explorer/full snapshot loaders."""

    return pytest.importorskip("server.app.metadata_parts.base_snapshot_runtime")


@pytest.fixture
def items_runtime():
    """The fragment that defines the session metadata item helpers."""

    return pytest.importorskip("server.app.metadata_parts.session_items_runtime")


@pytest.fixture
def cache_runtime():
    """The fragment that defines the metadata cache helpers."""

    return pytest.importorskip("server.app.metadata_parts.cache_runtime")
