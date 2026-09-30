"""No import cycle in server/app, and no import inside a function beyond the listed ones.

A module that imports one which, directly or not, imports it back only loads in
some orders: which one fails depends on who is imported first. The edges are every
import that runs when a module is imported (``TYPE_CHECKING`` blocks aside): "A
imports B" makes A depend on B and on each package of B's that is not also one of
A's, since importing B runs those packages' ``__init__`` first.

An import inside a function runs later and so hides a cycle rather than removing
it; the few kept are listed with their reason.

Both lists only shrink: a cycle that is gone, or one that got smaller, must be
removed or edited to what is left.
"""
from __future__ import annotations

import ast
from pathlib import Path

ALLOWED_CYCLES: list[frozenset[str]] = [
    frozenset({
        "server.app.decoder.decode.pipeline",
        "server.app.decoder.decode.readings",
    }),
]

ALLOWED_DEFERRED: dict[tuple[str, str], str] = {
    ("server/app/mds/provisioning.py", "tools"): "the updater is imported only when a refresh runs, and may be absent",
    ("server/app/startup.py", "server.app.mds.provisioning"): "the warm-up loads the MDS runtime on its own thread",
    ("server/app/startup.py", "server.app.mds.cache"): "the warm-up loads the MDS runtime on its own thread",
}

REPO_ROOT = Path(__file__).resolve().parents[3]
SOURCE_ROOT = REPO_ROOT / "server" / "app"
PACKAGE = "server.app"


def _module_names() -> dict[str, Path]:
    names = {}
    for source in sorted(SOURCE_ROOT.rglob("*.py")):
        parts = list(source.relative_to(REPO_ROOT).with_suffix("").parts)
        if parts[-1] == "__init__":
            parts = parts[:-1]
        names[".".join(parts)] = source
    return names


def _is_type_checking(test: ast.expr) -> bool:
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
        isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
    )


def _imports(tree: ast.Module) -> list[tuple[ast.stmt, bool]]:
    """Every import statement with whether it runs when the module is imported."""

    found: list[tuple[ast.stmt, bool]] = []

    def visit(node: ast.AST, at_import: bool) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.If) and _is_type_checking(child.test):
                for other in child.orelse:
                    visit(ast.Module(body=[other], type_ignores=[]), at_import)
                continue
            if isinstance(child, (ast.Import, ast.ImportFrom)):
                found.append((child, at_import))
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                visit(child, False)
            else:
                visit(child, at_import)

    visit(tree, True)
    return found


def _targets(module: str, is_package: bool, node: ast.stmt, known: dict[str, Path]) -> list[str]:
    if isinstance(node, ast.Import):
        return [alias.name for alias in node.names]
    assert isinstance(node, ast.ImportFrom)
    if node.level:
        base_parts = module.split(".") if is_package else module.split(".")[:-1]
        base_parts = base_parts[: len(base_parts) - (node.level - 1)]
        base = ".".join(base_parts + ([node.module] if node.module else []))
    else:
        base = node.module or ""
    targets = []
    for alias in node.names:
        candidate = f"{base}.{alias.name}"
        targets.append(candidate if candidate in known else base)
    return targets


def _ancestors(module: str) -> list[str]:
    parts = module.split(".")
    return [".".join(parts[:end]) for end in range(len(PACKAGE.split(".")), len(parts))]


def _graph() -> tuple[dict[str, set[str]], set[tuple[str, str]]]:
    known = _module_names()
    edges: dict[str, set[str]] = {name: set() for name in known}
    deferred: set[tuple[str, str]] = set()
    for module, source in known.items():
        is_package = source.name == "__init__.py"
        for node, at_import in _imports(ast.parse(source.read_text(), filename=str(source))):
            for target in _targets(module, is_package, node, known):
                if not at_import:
                    deferred.add((source.relative_to(REPO_ROOT).as_posix(), target))
                    continue
                if target not in known:
                    continue
                reached = {target} | {
                    package for package in _ancestors(target) if package not in _ancestors(module)
                }
                edges[module] |= reached - {module}
    return edges, deferred


def _cycles(edges: dict[str, set[str]]) -> list[frozenset[str]]:
    """The strongly connected components of more than one module (Tarjan)."""

    index: dict[str, int] = {}
    low: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    found: list[frozenset[str]] = []
    counter = [0]

    def connect(node: str) -> None:
        index[node] = low[node] = counter[0]
        counter[0] += 1
        stack.append(node)
        on_stack.add(node)
        for target in sorted(edges[node]):
            if target not in index:
                connect(target)
                low[node] = min(low[node], low[target])
            elif target in on_stack:
                low[node] = min(low[node], index[target])
        if low[node] == index[node]:
            component = set()
            while True:
                member = stack.pop()
                on_stack.discard(member)
                component.add(member)
                if member == node:
                    break
            if len(component) > 1:
                found.append(frozenset(component))

    for node in sorted(edges):
        if node not in index:
            connect(node)
    return found


def test_no_import_cycle():
    edges, _deferred = _graph()
    found = set(_cycles(edges))
    allowed = set(ALLOWED_CYCLES)
    problems = [f"import cycle: {' -> '.join(sorted(cycle))}" for cycle in sorted(found - allowed, key=sorted)]
    problems += [
        f"listed cycle no longer exists as listed (remove or shrink it): {sorted(cycle)}"
        for cycle in sorted(allowed - found, key=sorted)
    ]
    assert not problems, "\n".join(problems)


def test_no_import_inside_a_function_but_the_listed_ones():
    _edges, deferred = _graph()
    problems = [f"{path} imports {target} inside a function" for path, target in sorted(deferred - set(ALLOWED_DEFERRED))]
    problems += [f"{path} no longer imports {target} inside a function: remove its entry"
                 for path, target in sorted(set(ALLOWED_DEFERRED) - deferred)]
    assert not problems, "\n".join(problems)


def test_the_edges_include_the_packages_an_import_runs():
    known = {"server.app.a.b": Path("b.py"), "server.app.a": Path("__init__.py"), "server.app.c": Path("c.py")}
    node = ast.parse("from .a import b").body[0]
    assert _targets("server.app.c", False, node, known) == ["server.app.a.b"]
    assert _ancestors("server.app.a.b") == ["server.app", "server.app.a"]
    assert _cycles({"x": {"y"}, "y": {"x"}, "z": {"x"}}) == [frozenset({"x", "y"})]
