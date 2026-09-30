"""No function in server/app over 80 lines, and no module over 700.

The big route and attestation functions were split along the stages of the work
they do; this keeps new ones from growing. There are no exceptions: split a
function or a module that would pass its limit.

A function's length is its ``def`` line through its last line, decorators
excluded, nested functions counted inside their parent too. It is named
``path::Class.method`` or ``path::outer.<locals>.inner``. A module's length is
its number of lines.
"""
from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SOURCE_ROOT = REPO_ROOT / "server" / "app"

MAX_FUNCTION_LINES = 80
MAX_MODULE_LINES = 700


def _functions(tree: ast.Module, path: str) -> list[tuple[str, int]]:
    found: list[tuple[str, int]] = []

    def visit(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                found.append((f"{path}::{prefix}{child.name}", child.end_lineno - child.lineno + 1))
                visit(child, f"{prefix}{child.name}.<locals>.")
            elif isinstance(child, ast.ClassDef):
                visit(child, f"{prefix}{child.name}.")
            else:
                visit(child, prefix)

    visit(tree, "")
    return found


def _measure() -> tuple[dict[str, int], dict[str, int]]:
    functions: dict[str, int] = {}
    modules: dict[str, int] = {}
    duplicates: list[str] = []
    for source in sorted(SOURCE_ROOT.rglob("*.py")):
        path = source.relative_to(REPO_ROOT).as_posix()
        text = source.read_text()
        modules[path] = len(text.splitlines())
        for name, length in _functions(ast.parse(text, filename=path), path):
            if name in functions:
                duplicates.append(name)
            functions[name] = length
    assert not duplicates, f"two functions share a name, so their lengths cannot be told apart: {duplicates}"
    return functions, modules


def _problems(measured: dict[str, int], limit: int, kind: str) -> list[str]:
    return [
        f"{name} is {length} lines, over the {limit}-line {kind} limit: split it"
        for name, length in sorted(measured.items())
        if length > limit
    ]


def test_no_function_is_over_its_limit():
    functions, _modules = _measure()
    problems = _problems(functions, MAX_FUNCTION_LINES, "function")
    assert not problems, "\n".join(problems)


def test_no_module_is_over_its_limit():
    _functions_measured, modules = _measure()
    problems = _problems(modules, MAX_MODULE_LINES, "module")
    assert not problems, "\n".join(problems)


def test_the_measure_counts_nested_and_async_functions_under_their_own_names():
    source = (
        "class Box:\n"
        "    def method(self):\n"
        "        def inner():\n"
        "            return 1\n"
        "        return inner\n"
        "async def fetch():\n"
        "    return 2\n"
    )
    assert _functions(ast.parse(source), "m.py") == [
        ("m.py::Box.method", 4),
        ("m.py::Box.method.<locals>.inner", 2),
        ("m.py::fetch", 2),
    ]
