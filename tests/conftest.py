from pathlib import Path

import pytest


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
