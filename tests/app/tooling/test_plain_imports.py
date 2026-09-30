"""Tests import the app's own modules plainly: no ``pytest.importorskip`` of them.

``pytest.importorskip("server.app.x")`` turns a module that fails to import -- one
that moved, or an import cycle -- into a skipped test, so the run stays green while
testing less. The app's modules (``server``), the tools and the test helpers are
always importable in this repository; a test imports them like any other module.
A call whose argument is not a literal cannot be checked, so it is refused too.
"""
from __future__ import annotations

import ast
from pathlib import Path

TESTS_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = TESTS_ROOT.parent
FIRST_PARTY = ("server", "tools", "tests")


def _first_party_skips(tree: ast.AST) -> int:
    found = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
        if name != "importorskip":
            continue
        target = node.args[0]
        if isinstance(target, ast.Constant) and isinstance(target.value, str):
            if target.value.split(".")[0] not in FIRST_PARTY:
                continue
        found += 1
    return found


def _measure() -> dict[str, int]:
    measured = {}
    for source in sorted(TESTS_ROOT.rglob("*.py")):
        count = _first_party_skips(ast.parse(source.read_text(), filename=str(source)))
        if count:
            measured[source.relative_to(REPO_ROOT).as_posix()] = count
    return measured


def test_no_test_skips_on_importing_the_app():
    found = [f"{path}: {count} importorskip of the app's own modules; import them plainly" for path, count in _measure().items()]
    assert not found, "\n".join(found)


def test_the_check_counts_first_party_and_unreadable_targets_only():
    source = (
        "import pytest\n"
        "pytest.importorskip('server.app.app')\n"
        "pytest.importorskip('tests.app.helpers')\n"
        "pytest.importorskip(name)\n"
        "pytest.importorskip('hypothesis')\n"
        "pytest.importorskip('gunicorn')\n"
    )
    assert _first_party_skips(ast.parse(source)) == 3
