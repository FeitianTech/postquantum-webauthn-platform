"""Shared fixtures for the metadata runtime tests."""

from __future__ import annotations

import importlib

import pytest


@pytest.fixture
def sessions():
    """``server.app.mds.uploads``: a visitor's uploaded metadata."""

    return importlib.import_module("server.app.mds.uploads")


@pytest.fixture
def entries():
    """``server.app.mds.entries``: uploaded statements, read."""

    return importlib.import_module("server.app.mds.entries")


@pytest.fixture
def blob():
    """``server.app.mds.cache``: the snapshot loaders and their cache."""

    return importlib.import_module("server.app.mds.cache")


@pytest.fixture
def uploads():
    """``server.app.storage.github_mirror``: the uploads' GitHub mirror."""

    return importlib.import_module("server.app.storage.github_mirror")


@pytest.fixture
def effective():
    """``server.app.mds.effective``: the snapshot merged with a visitor's uploads."""

    return importlib.import_module("server.app.mds.effective")


@pytest.fixture
def session_store():
    """The storage module the metadata fragments write through."""

    return importlib.import_module("server.app.storage.session_metadata")


@pytest.fixture
def app_config():
    """The app config module, for the Flask app and its logger."""

    return importlib.import_module("server.app.config")


@pytest.fixture
def verifier():
    """``server.app.mds.verifier``: fido2's MDS verifier."""

    return importlib.import_module("server.app.mds.verifier")
