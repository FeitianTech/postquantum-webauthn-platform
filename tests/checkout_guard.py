"""The checkout guard: fail the run if a test created, changed or removed app state in the checkout.

Tests keep their stores in temporary directories. A test that does not left a
session directory under server/runtime/ on every run, and a stray session
cleanup there removed a hundred earlier ones.

What the guarded paths hold already mixes the owner's local data with earlier
test runs' leftovers, so the guard compares a listing taken before the tests are
collected -- a module that writes while it is imported is seen -- with one taken
when the session finishes, and never cleans. A difference fails the run.

It is a pytest plugin (``tests/conftest.py`` loads it) rooted at the checkout,
or at ``--checkout-root``, which is how its own test points it at a directory of
its own.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
# Where the app keeps state on a developer's machine -- including the legacy
# credential stores in the source tree, which are still read -- and the MDS
# snapshot files (docs/MDS_SNAPSHOT.md).
GUARDED_TREES = ("server/runtime", "instance", "server/app/session-credentials", ".hypothesis")
GUARDED_STATIC = (
    "frontend/static/fido-mds3.*",
    "frontend/static/blob.jwt*",
    "server/app/*_credential_data.pkl",
)


def pytest_addoption(parser):
    parser.addoption(
        "--checkout-root",
        action="store",
        default=None,
        help="The directory the checkout guard watches (default: this checkout).",
    )


def root(config: pytest.Config) -> Path:
    given = config.getoption("--checkout-root")
    return Path(given).resolve() if given else _REPO_ROOT


def listing(base: Path) -> dict[str, object]:
    found: dict[str, object] = {}
    paths = [path for tree in GUARDED_TREES for path in (base / tree).rglob("*")]
    paths += [path for pattern in GUARDED_STATIC for path in base.glob(pattern)]
    for path in paths:
        try:
            status = path.lstat()
        except FileNotFoundError:
            continue
        key = path.relative_to(base).as_posix()
        found[key] = "dir" if path.is_dir() else (status.st_size, status.st_mtime_ns)
    return found


def _describe(kind: str, names: list[str]) -> str:
    shown = "\n".join(f"    {name}" for name in names[:20])
    more = f"\n    ... and {len(names) - 20} more" if len(names) > 20 else ""
    return f"  {kind} ({len(names)}):\n{shown}{more}"


def problems(before: dict[str, object], after: dict[str, object]) -> str | None:
    """What changed between two listings, said for a person; ``None`` when nothing did."""

    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))
    changed = sorted(name for name in set(before) & set(after) if before[name] != after[name])
    described = [
        _describe(kind, names)
        for kind, names in (("created", added), ("removed", removed), ("changed", changed))
        if names
    ]
    if not described:
        return None
    return (
        "Tests wrote into the checkout (server/runtime/, instance/, the legacy credential "
        "stores in server/app/, .hypothesis/ or the MDS snapshot):\n" + "\n".join(described)
    )


_BEFORE = pytest.StashKey[dict]()


def pytest_configure(config: pytest.Config) -> None:
    # Before collection: a test module that writes while it is imported is seen too.
    config.stash[_BEFORE] = listing(root(config))


@pytest.hookimpl(tryfirst=True)
def pytest_sessionfinish(session: pytest.Session) -> None:
    before = session.config.stash.get(_BEFORE, None)
    if before is None:
        return
    found = problems(before, listing(root(session.config)))
    if not found:
        return
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    if reporter is not None:
        reporter.write("\n")
        reporter.write_sep("=", "checkout guard", red=True)
        reporter.write_line(found)
    else:  # -p no:terminal
        sys.stderr.write(found + "\n")
    session.exitstatus = pytest.ExitCode.TESTS_FAILED
