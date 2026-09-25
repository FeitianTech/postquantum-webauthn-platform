import atexit
import os
import shutil
import tempfile
from pathlib import Path

import pytest

# Hypothesis writes under <cwd>/.hypothesis whatever its database setting -- a
# cache of each local module's constants, the Unicode character map -- so its
# storage is pointed at a directory of this run's before anything reads it. The
# checkout guard below watches .hypothesis to prove it.
if "HYPOTHESIS_STORAGE_DIRECTORY" not in os.environ:
    _HYPOTHESIS_STORAGE = tempfile.mkdtemp(prefix="hypothesis-")
    os.environ["HYPOTHESIS_STORAGE_DIRECTORY"] = _HYPOTHESIS_STORAGE
    atexit.register(shutil.rmtree, _HYPOTHESIS_STORAGE, ignore_errors=True)

# An app built with no secret generates one and persists it in instance/. The
# entry point (server.app.app) builds its app on import, and tests import it --
# some while they are collected -- so every app the tests build gets this secret
# before anything is imported. A test of the secret's resolution removes it.
os.environ.setdefault("FIDO_SERVER_SECRET_KEY", "test-session-secret-0123456789abcdef")

_REPO_ROOT = Path(__file__).resolve().parents[1]
# Where the app keeps state on a developer's machine -- including the legacy
# credential stores in the source tree, which are still read -- and the MDS
# snapshot files (docs/MDS_SNAPSHOT.md). What is there already mixes the owner's
# local data with earlier test runs' leftovers, so the guard compares, never cleans.
_GUARDED_TREES = ("server/runtime", "instance", "server/app/session-credentials", ".hypothesis")
_GUARDED_STATIC = (
    "frontend/static/fido-mds3.*",
    "frontend/static/blob.jwt*",
    "server/app/*_credential_data.pkl",
)


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


def _repo_state_listing() -> dict[str, object]:
    listing: dict[str, object] = {}
    paths = [path for tree in _GUARDED_TREES for path in (_REPO_ROOT / tree).rglob("*")]
    paths += [path for pattern in _GUARDED_STATIC for path in _REPO_ROOT.glob(pattern)]
    for path in paths:
        try:
            status = path.lstat()
        except FileNotFoundError:
            continue
        key = path.relative_to(_REPO_ROOT).as_posix()
        listing[key] = "dir" if path.is_dir() else (status.st_size, status.st_mtime_ns)
    return listing


def _describe(kind: str, names: list[str]) -> str:
    shown = "\n".join(f"    {name}" for name in names[:20])
    more = f"\n    ... and {len(names) - 20} more" if len(names) > 20 else ""
    return f"  {kind} ({len(names)}):\n{shown}{more}"


@pytest.fixture(scope="session", autouse=True)
def _no_writes_into_the_checkout():
    """Fail the run if a test created, changed or removed app state in the checkout.

    Tests keep their stores in temporary directories. A test that does not
    left a session directory under server/runtime/ on every run, and a stray
    session cleanup there removed a hundred earlier ones.
    """

    before = _repo_state_listing()
    yield
    after = _repo_state_listing()
    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))
    changed = sorted(name for name in set(before) & set(after) if before[name] != after[name])
    problems = [
        _describe(kind, names)
        for kind, names in (("created", added), ("removed", removed), ("changed", changed))
        if names
    ]
    if problems:
        pytest.fail(
            "Tests wrote into the checkout (server/runtime/, instance/, the legacy credential "
            "stores in server/app/, .hypothesis/ or the MDS snapshot):\n"
            + "\n".join(problems),
            pytrace=False,
        )
