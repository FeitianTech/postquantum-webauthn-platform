import atexit
import os
import shutil
import tempfile
from pathlib import Path

import pytest

# Hypothesis writes under <cwd>/.hypothesis whatever its database setting -- a
# cache of each local module's constants, the Unicode character map -- so its
# storage is pointed at a directory of this run's before anything reads it. The
# checkout guard (tests/checkout_guard.py) watches .hypothesis to prove it.
if "HYPOTHESIS_STORAGE_DIRECTORY" not in os.environ:
    _HYPOTHESIS_STORAGE = tempfile.mkdtemp(prefix="hypothesis-")
    os.environ["HYPOTHESIS_STORAGE_DIRECTORY"] = _HYPOTHESIS_STORAGE
    atexit.register(shutil.rmtree, _HYPOTHESIS_STORAGE, ignore_errors=True)

# An app built with no secret generates one and persists it in instance/. The
# entry point (server.app.app) builds its app on import, and tests import it --
# some while they are collected -- so every app the tests build gets this secret
# before anything is imported. A test of the secret's resolution removes it.
os.environ.setdefault("FIDO_SERVER_SECRET_KEY", "test-session-secret-0123456789abcdef")

# The checkout guard (tests/checkout_guard.py) fails the run if a test wrote app
# state into the checkout.
pytest_plugins = ["tests.checkout_guard"]


def pytest_configure(config):
    from hypothesis import settings

    # Deterministic examples, and none saved between runs: a property test's
    # cases are the same on every run of one Python and Hypothesis version.
    settings.register_profile("repository", database=None, derandomize=True, deadline=None)
    settings.load_profile("repository")


def pytest_addoption(parser):
    parser.addoption("--reader", action="store")
    parser.addoption("--no-device", action="store_true")
    parser.addoption("--ep-rp-id", action="store")
    parser.addoption("--ccid", action="store_true")
    parser.addoption(
        "--run-device-tests",
        action="store_true",
        help="Include the hardware-in-the-loop tests under tests/device.",
    )


def pytest_ignore_collect(collection_path, config):
    """Skip destructive hardware tests unless explicitly requested."""

    if config.getoption("--run-device-tests"):
        return False

    try:
        path_obj = Path(str(collection_path))
    except TypeError:
        return False

    parts = path_obj.parts
    try:
        tests_index = parts.index("tests")
    except ValueError:
        return False

    return tests_index + 1 < len(parts) and parts[tests_index + 1] == "device"


@pytest.fixture(autouse=True)
def _isolated_challenge_registry(monkeypatch):
    """Give every test its own single-use challenge registry.

    The registry is process-global, and many tests reuse fixed challenge
    strings; without this, one test's consumed challenge would read as a
    replay in the next.
    """

    try:
        from server.app import challenge_registry
    except Exception:  # pragma: no cover - app not importable in this run
        yield None
        return
    registry = challenge_registry.InMemoryChallengeRegistry()
    monkeypatch.setattr(challenge_registry, "_registry", registry)
    yield registry
