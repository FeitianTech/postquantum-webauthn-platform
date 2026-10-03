import atexit
import os
import shutil
import tempfile

import pytest

from server.app import challenge_registry, visitor_session

# Hypothesis writes under <cwd>/.hypothesis whatever its database setting -- a
# cache of each local module's constants, the Unicode character map -- so its
# storage is pointed at a directory of this run's before anything reads it. The
# checkout guard (tests/checkout_guard.py) watches .hypothesis to prove it.
if "HYPOTHESIS_STORAGE_DIRECTORY" not in os.environ:
    _HYPOTHESIS_STORAGE = tempfile.mkdtemp(prefix="hypothesis-")
    os.environ["HYPOTHESIS_STORAGE_DIRECTORY"] = _HYPOTHESIS_STORAGE
    atexit.register(shutil.rmtree, _HYPOTHESIS_STORAGE, ignore_errors=True)

# The MDS snapshot is read from (and, by the provisioning and the updater, written
# to) FIDO_SERVER_MDS_SNAPSHOT_DIR, else instance/mds-snapshot, where a developer's real
# snapshot lives. Every test starts from an empty directory of this run's instead,
# whatever the shell exports: no test reads or writes the real snapshot, and a
# test that needs one points the setting at a fixture of its own
# (mds_fixture_snapshot, tests/app/conftest.py). Nothing is fetched from upstream either.
_MDS_SNAPSHOT_DIR = tempfile.mkdtemp(prefix="mds-snapshot-")
os.environ["FIDO_SERVER_MDS_SNAPSHOT_DIR"] = _MDS_SNAPSHOT_DIR
os.environ["FIDO_SERVER_MDS_FETCH_UPSTREAM"] = "0"
atexit.register(shutil.rmtree, _MDS_SNAPSHOT_DIR, ignore_errors=True)

# The local stores default to instance/ (config.paths.store_dir), the checkout's.
# Every test starts from directories of this run's instead; a test that needs its
# own sets the variable, and when that is undone a worker thread that outlives the
# test (the session-metadata cleanup) still finds this run's, never the checkout's.
_STORES = tempfile.mkdtemp(prefix="stores-")
for _setting, _name in (
    ("FIDO_SERVER_CREDENTIAL_DIR", "session-credentials"),
    ("FIDO_SERVER_CREDENTIAL_ARTIFACT_DIR", "credential-artifacts"),
    ("FIDO_SERVER_SESSION_METADATA_DIR", "session-metadata"),
):
    os.environ[_setting] = os.path.join(_STORES, _name)
atexit.register(shutil.rmtree, _STORES, ignore_errors=True)

# The UI's static export is served from FIDO_SERVER_WEB_EXPORT_ROOT, else
# web/out, which a local build -- or Cloud Build's web step, running beside the
# Python tests -- may be writing, and which the Python CI job never builds. Every
# test starts from an empty directory of this run's instead, so what a page answers
# never depends on whether a build happened to run; a test that needs an export
# builds its own (the export_root fixture, tests/app/conftest.py).
_WEB_EXPORT_ROOT = tempfile.mkdtemp(prefix="web-export-")
os.environ["FIDO_SERVER_WEB_EXPORT_ROOT"] = _WEB_EXPORT_ROOT
atexit.register(shutil.rmtree, _WEB_EXPORT_ROOT, ignore_errors=True)

# An app built with no secret generates one and persists it in instance/. The
# entry point (server.app.app) builds its app on import, and tests import it --
# some while they are collected -- so every app the tests build gets this secret
# before anything is imported. A test of the secret's resolution removes it.
os.environ.setdefault("FIDO_SERVER_SECRET_KEY", "test-session-secret-0123456789abcdef")

# A registration logs itself to the credential log repository on GitHub
# (storage/github_mirror.py), with whatever GITHUB_TOKEN the shell holds. No test
# reaches GitHub: logging is off for the run, and a test of the log turns it on
# against its own stand-in for the API.
os.environ["ENABLE_GITHUB_LOGGING"] = "0"

# The checkout guard (tests/checkout_guard.py) fails the run if a test wrote app
# state into the checkout; tests/fixture_values.py fails a fixture whose value is a module.
pytest_plugins = ["tests.checkout_guard", "tests.fixture_values"]


def pytest_configure(config):
    from hypothesis import settings

    # Deterministic examples, and none saved between runs: a property test's
    # cases are the same on every run of one Python and Hypothesis version.
    settings.register_profile("repository", database=None, derandomize=True, deadline=None)
    settings.load_profile("repository")


@pytest.fixture(autouse=True)
def _isolated_challenge_registry(monkeypatch):
    """Give every test its own single-use challenge registry.

    The registry is process-global, and many tests reuse fixed challenge
    strings; without this, one test's consumed challenge would read as a
    replay in the next.
    """

    registry = challenge_registry.InMemoryChallengeRegistry()
    monkeypatch.setattr(challenge_registry, "_registry", registry)
    yield registry


@pytest.fixture(autouse=True)
def _fresh_touch_throttle(monkeypatch):
    """Give every test its own memory of the namespaces it refreshed.

    The throttle is process-global, and tests reuse namespace names.
    """

    monkeypatch.setattr(visitor_session, "TOUCHES", visitor_session.TouchState())
