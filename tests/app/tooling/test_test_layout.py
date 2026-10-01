"""The tests' own layout: imports at the top, no module in a fixture or sys.modules, each helper once.

- A first-party module (``server``, ``tools``, ``tests``) is imported at the top of a
  file, never inside a function, class or lambda, and never through
  ``importlib.import_module`` with its name: what a file uses is in its imports, and a
  patch reaches the module the test imported.
- Nothing writes ``sys.modules``: a module put there outlives the test that put it.
- No fixture's value holds a module; ``tests/fixture_values.py`` checks each one as it
  is set up, and this file tests that check and that the plugin is loaded.
- No two files define the same top-level function or class: a helper the tests share
  lives once, in a module they import.

The few exceptions are listed with their reason, and the lists only shrink.
"""
from __future__ import annotations

import ast
import types
from pathlib import Path

import pytest

from tests import fixture_values

TESTS_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = TESTS_ROOT.parent
FIRST_PARTY = ("server", "tools", "tests")

ALLOWED_DYNAMIC_IMPORTS: dict[tuple[str, str], str] = {
    ("tests/app/characterization/encoding_diff.py", "server.app.encoding"): (
        "run as a script by its path, it puts the repository on sys.path before importing the app"
    ),
}

_SYS_MODULES_METHODS = {"update", "setdefault", "pop", "popitem", "clear", "__setitem__", "__delitem__"}


def _first_party(node: ast.Import | ast.ImportFrom) -> bool:
    if isinstance(node, ast.ImportFrom):
        return node.level > 0 or (node.module or "").split(".")[0] in FIRST_PARTY
    return any(alias.name.split(".")[0] in FIRST_PARTY for alias in node.names)


def _imports_below_module_level(tree: ast.AST) -> list[int]:
    """The lines of first-party imports inside a function, class or lambda."""

    found: list[int] = []

    def visit(node: ast.AST, nested: bool) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.Import, ast.ImportFrom)):
                if nested and _first_party(child):
                    found.append(child.lineno)
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
                visit(child, True)
            else:
                visit(child, nested)

    visit(tree, False)
    return found


def _dynamic_imports(tree: ast.AST) -> list[tuple[int, str]]:
    """``import_module`` calls given a first-party module's name, with the name."""

    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
        target = node.args[0]
        if name != "import_module":
            continue
        if isinstance(target, ast.Constant) and isinstance(target.value, str):
            if target.value.split(".")[0] in FIRST_PARTY:
                found.append((node.lineno, target.value))
    return found


def _is_sys_modules(node: ast.AST) -> bool:
    if isinstance(node, ast.Attribute):
        return node.attr == "modules" and isinstance(node.value, ast.Name) and node.value.id == "sys"
    return isinstance(node, ast.Constant) and node.value == "sys.modules"


def _sys_modules_writes(tree: ast.AST) -> list[int]:
    """The lines that write ``sys.modules``, in any spelling."""

    found = []
    for node in ast.walk(tree):
        targets: list[ast.AST] = []
        if isinstance(node, (ast.Assign, ast.Delete)):
            targets = list(node.targets)
        elif isinstance(node, (ast.AugAssign, ast.AnnAssign)):
            targets = [node.target]
        if any(isinstance(t, ast.Subscript) and _is_sys_modules(t.value) for t in targets):
            found.append(node.lineno)
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
        args = node.args
        if isinstance(func, ast.Attribute) and _is_sys_modules(func.value) and name in _SYS_MODULES_METHODS:
            found.append(node.lineno)
        elif name in {"setitem", "delitem", "dict"} and args and _is_sys_modules(args[0]):
            found.append(node.lineno)
        elif name in {"setattr", "delattr"} and args:
            sys_attribute = (
                len(args) > 1
                and isinstance(args[0], ast.Name)
                and args[0].id == "sys"
                and isinstance(args[1], ast.Constant)
                and args[1].value == "modules"
            )
            if sys_attribute or _is_sys_modules(args[0]):
                found.append(node.lineno)
    return found


def _empty(body: list[ast.stmt]) -> bool:
    return all(isinstance(s, ast.Pass) or (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)) for s in body)


def _shape(node: ast.stmt) -> tuple | None:
    """A top-level function or class without its name and docstring; ``None`` for one with no body."""

    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return None
    body = node.body
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
        body = body[1:]
    if _empty(body):
        return None
    head = ast.dump(node.args) if not isinstance(node, ast.ClassDef) else tuple(ast.dump(b) for b in node.bases)
    return (
        type(node).__name__,
        head,
        tuple(ast.dump(d) for d in node.decorator_list),
        tuple(ast.dump(s) for s in body),
    )


def _sources() -> dict[str, ast.Module]:
    return {
        source.relative_to(REPO_ROOT).as_posix(): ast.parse(source.read_text(), filename=str(source))
        for source in sorted(TESTS_ROOT.rglob("*.py"))
    }


def test_first_party_modules_are_imported_at_the_top():
    found = [f"{path}:{line}" for path, tree in _sources().items() for line in _imports_below_module_level(tree)]
    assert not found, "Import these at the top of the file:\n" + "\n".join(found)


def test_no_test_imports_a_first_party_module_by_its_name():
    used = set()
    found = []
    for path, tree in _sources().items():
        for line, name in _dynamic_imports(tree):
            if (path, name) in ALLOWED_DYNAMIC_IMPORTS:
                used.add((path, name))
            else:
                found.append(f"{path}:{line}: import_module({name!r})")
    assert not found, "Import these with an import statement:\n" + "\n".join(found)
    stale = sorted(set(ALLOWED_DYNAMIC_IMPORTS) - used)
    assert not stale, f"ALLOWED_DYNAMIC_IMPORTS lists imports no file makes any more; remove them: {stale}"


def test_no_test_writes_sys_modules():
    found = [f"{path}:{line}" for path, tree in _sources().items() for line in _sys_modules_writes(tree)]
    assert not found, "These write sys.modules:\n" + "\n".join(found)


def test_no_two_files_define_the_same_helper():
    defined: dict[tuple, list[str]] = {}
    for path, tree in _sources().items():
        for node in tree.body:
            shape = _shape(node)
            if shape is not None:
                defined.setdefault(shape, []).append(f"{path}:{node.lineno} {node.name}")
    found = [" = ".join(where) for where in defined.values() if len({w.split(":")[0] for w in where}) > 1]
    assert not found, "Define each once, in a module the tests import:\n" + "\n".join(found)


def test_the_fixture_value_check_is_loaded(pytestconfig):
    assert pytestconfig.pluginmanager.has_plugin("tests.fixture_values")


def test_the_fixture_value_check_finds_a_module_in_any_container():
    module = types.ModuleType("example")
    for value in (
        module,
        (1, module),
        [module],
        {module},
        {"key": module},
        types.SimpleNamespace(store=module),
        ({"nested": [module]},),
    ):
        assert fixture_values.holds_module(value), value
    for value in (None, "types", object(), {"module": "name"}, [[[[module]]]]):
        assert not fixture_values.holds_module(value), value


def test_the_import_check_finds_imports_in_functions_classes_and_lambdas():
    source = (
        "import json\n"
        "from server.app import encoding\n"
        "try:\n"
        "    from tests.app import entry_app\n"
        "except ImportError:\n"
        "    pass\n"
        "def f():\n"
        "    from server.app import factory\n"
        "    import tools.update_mds_snapshot\n"
        "    from . import helpers\n"
        "    import json\n"
        "async def g():\n"
        "    from tests.app import cbor_items\n"
        "class C:\n"
        "    from server.app import paths\n"
        "h = lambda: __import__('os')\n"
    )
    assert _imports_below_module_level(ast.parse(source)) == [8, 9, 10, 13, 15]


def test_the_dynamic_import_check_reads_first_party_names():
    source = (
        "import importlib\n"
        "importlib.import_module('server.app.encoding')\n"
        "import_module('tests.app.entry_app')\n"
        "importlib.import_module(name)\n"
        "importlib.import_module('hypothesis')\n"
    )
    assert _dynamic_imports(ast.parse(source)) == [(2, "server.app.encoding"), (3, "tests.app.entry_app")]


def test_the_sys_modules_check_finds_every_spelling():
    writes = [
        "sys.modules['x'] = module",
        "sys.modules['x'] += 1",
        "del sys.modules['x']",
        "sys.modules.update({'x': module})",
        "sys.modules.setdefault('x', module)",
        "sys.modules.pop('x')",
        "sys.modules.popitem()",
        "sys.modules.clear()",
        "sys.modules.__setitem__('x', module)",
        "sys.modules.__delitem__('x')",
        "monkeypatch.setitem(sys.modules, 'x', module)",
        "monkeypatch.delitem(sys.modules, 'x')",
        "mock.patch.dict(sys.modules, {'x': module})",
        "mock.patch.dict('sys.modules', {'x': module})",
        "setattr(sys, 'modules', {})",
        "monkeypatch.setattr(sys, 'modules', {})",
        "monkeypatch.setattr('sys.modules', {})",
    ]
    for line in writes:
        assert _sys_modules_writes(ast.parse(line)) == [1], line
    reads = ["'x' in sys.modules", "sys.modules.get('x')", "sorted(sys.modules)", "modules['x'] = 1"]
    for line in reads:
        assert _sys_modules_writes(ast.parse(line)) == [], line


@pytest.mark.parametrize(
    ("first", "second", "same"),
    [
        ("def a(x):\n    return x + 1\n", "def b(x):\n    '''Doc.'''\n    return x + 1\n", True),
        ("def a(x):\n    return x + 1\n", "def a(y):\n    return y + 1\n", False),
        ("class A:\n    def f(self):\n        return 1\n", "class B:\n    def f(self):\n        return 1\n", True),
        ("class A(Exception):\n    pass\n", "class B(Exception):\n    pass\n", False),
    ],
)
def test_the_helper_check_compares_bodies_without_names(first, second, same):
    a, b = (_shape(ast.parse(source).body[0]) for source in (first, second))
    if a is None or b is None:
        assert not same
    else:
        assert (a == b) is same
