"""Every npm lockfile names each platform build its packages may need.

``npm ci`` installs exactly what ``package-lock.json`` lists. Native tools ship
one optional package per platform (rolldown's ``@rolldown/binding-*`` for vitest,
Next's ``@next/swc-*``, Tailwind's ``@tailwindcss/oxide-*``, ``lightningcss-*``),
and npm drops the ones for other platforms when it regenerates a lock against a
partly installed tree (npm/cli#4828). The lock then works on the machine that
wrote it and fails on the Linux CI runner and in the image build.

So every optional dependency a locked package declares must itself be locked,
found the way Node resolves it: in the package's own ``node_modules``, then in
each enclosing one. To repair a lock, delete ``node_modules`` and the lock and
run ``npm install`` from clean.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[3]
LOCKFILES = ("package-lock.json", "web/package-lock.json")


def _resolves(packages: dict, owner: str, name: str) -> bool:
    base = owner
    while True:
        candidate = f"{base}/node_modules/{name}" if base else f"node_modules/{name}"
        if candidate in packages:
            return True
        if not base:
            return False
        marker = base.rfind("/node_modules/")
        base = base[:marker] if marker >= 0 else ""


def missing_optional_dependencies(lock: dict) -> list[str]:
    packages = lock.get("packages", {})
    return [
        f"{owner or '(root)'} -> {name}"
        for owner, entry in packages.items()
        for name in entry.get("optionalDependencies", {})
        if not _resolves(packages, owner, name)
    ]


@pytest.mark.parametrize("lockfile", LOCKFILES)
def test_every_optional_dependency_is_locked(lockfile):
    lock = json.loads((_ROOT / lockfile).read_text(encoding="utf-8"))

    assert lock["lockfileVersion"] == 3
    assert missing_optional_dependencies(lock) == []


def test_the_web_lock_holds_the_linux_builds_the_image_needs():
    packages = json.loads((_ROOT / "web/package-lock.json").read_text(encoding="utf-8"))["packages"]

    for name in (
        "@next/swc-linux-x64-gnu",
        "@next/swc-linux-arm64-gnu",
        "@tailwindcss/oxide-linux-x64-gnu",
        "lightningcss-linux-x64-gnu",
        "@rolldown/binding-linux-x64-gnu",
    ):
        assert f"node_modules/{name}" in packages, name


def test_a_dropped_platform_build_is_found():
    lock = {
        "packages": {
            "": {"optionalDependencies": {"top": "1"}},
            "node_modules/top": {},
            "node_modules/tool": {"optionalDependencies": {"@x/binding-linux": "1", "@x/binding-darwin": "1"}},
            "node_modules/@x/binding-darwin": {},
            "node_modules/tool/node_modules/nested": {"optionalDependencies": {"@x/binding-darwin": "1", "own": "1"}},
            "node_modules/tool/node_modules/own": {},
        }
    }

    assert missing_optional_dependencies(lock) == ["node_modules/tool -> @x/binding-linux"]
