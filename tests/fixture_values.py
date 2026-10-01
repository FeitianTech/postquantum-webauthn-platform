"""No fixture's value is a module, or holds one: a test imports the modules it uses.

A fixture that hands back a module hides what a test depends on behind a name the
reader has to look up, and a test that patches through it patches whatever that
fixture happened to import. This plugin (``tests/conftest.py`` loads it) checks
every fixture's value as the fixture is set up -- returned or yielded, a module or
a tuple, list, set, dict or namespace with one inside -- and fails the fixture.
``tests/app/tooling/test_test_layout.py`` tests the check.
"""
from __future__ import annotations

import types
from typing import Any

import pytest

# How deep a container is searched for a module.
_DEPTH = 3


def holds_module(value: Any, depth: int = _DEPTH) -> bool:
    """Whether ``value`` is a module, or a container with one within ``depth`` levels."""

    if isinstance(value, types.ModuleType):
        return True
    if depth == 0:
        return False
    if isinstance(value, (tuple, list, set, frozenset)):
        return any(holds_module(item, depth - 1) for item in value)
    if isinstance(value, dict):
        return any(holds_module(item, depth - 1) for item in value.values())
    if isinstance(value, types.SimpleNamespace):
        return any(holds_module(item, depth - 1) for item in vars(value).values())
    return False


@pytest.hookimpl(wrapper=True)
def pytest_fixture_setup(fixturedef, request):
    value = yield
    if holds_module(value):
        pytest.fail(
            f"fixture {fixturedef.argname!r} gives a module; import the module in the test instead",
            pytrace=False,
        )
    return value
