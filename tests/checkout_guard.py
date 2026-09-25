"""The checkout guard: fail the run if a test created, changed or removed app state in the checkout.

Tests keep their stores in temporary directories. A test that does not left a
session directory under server/runtime/ on every run, and a stray session
cleanup there removed a hundred earlier ones.

What the guarded paths hold already mixes the owner's local data with earlier
test runs' leftovers, so the guard compares listings taken before and after,
and never cleans. It is a pytest plugin (``tests/conftest.py`` loads it) rooted
at the checkout, or at ``--checkout-root``, which is how its own test points it
at a directory of its own.
"""
from __future__ import annotations

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


@pytest.fixture(scope="session", autouse=True)
def _no_writes_into_the_checkout(request):
    """Fail the run if a test created, changed or removed app state in the checkout."""

    base = root(request.config)
    before = listing(base)
    yield
    found = problems(before, listing(base))
    if found:
        pytest.fail(found, pytrace=False)
