"""No function in server/app over 80 lines, no module over 700, except the listed ones.

The big route and attestation functions of Phase 18 were split along the stages
of the work they did; this keeps new ones from growing. A function or module
already over its limit is listed below at its current length. The lists only
tighten: an entry must equal the current length (edit it down when the code
shrinks, never up), and an entry that is now within the limit must be removed.

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

LONG_FUNCTIONS: dict[str, int] = {
    "server/app/config/session_secret.py::_resolve_secret_key": 84,
    "server/app/decoder/decode/response.py::_build_credential_payload": 88,
    "server/app/mds_snapshot.py::build_explorer_entry": 131,
    "server/app/routes/advanced/parsing.py::_parse_client_supplied_credentials": 100,
    "server/app/routes/advanced/tracing.py::_log_authenticator_attestation_response": 94,
    "server/app/routes/simple/authentication.py::authenticate_complete": 126,
    "server/app/routes/simple/credential_list.py::build_credential_info_from_dict_credential_data": 114,
    "server/app/routes/simple/credential_list.py::build_credential_info_from_object_credential_data": 85,
    "server/app/webauthn/attestation/classical.py::_evaluate_classical_attestation_root": 122,
    "server/app/webauthn/attestation/pqc.py::_attempt_pqc_attestation_signature_validation": 89,
    "server/app/webauthn/attestation/pqc.py::_evaluate_mldsa_attestation_root": 120,
}

LONG_MODULES: dict[str, int] = {}


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


def _problems(measured: dict[str, int], allowed: dict[str, int], limit: int, kind: str) -> list[str]:
    problems = []
    for name, length in sorted(measured.items()):
        if length <= limit:
            if name in allowed:
                problems.append(f"{name} is {length} lines, within the {limit}-line limit: remove its entry")
            continue
        if name not in allowed:
            problems.append(f"{name} is {length} lines, over the {limit}-line {kind} limit: split it")
        elif length > allowed[name]:
            problems.append(f"{name} grew from {allowed[name]} to {length} lines: split it rather than raise the entry")
        elif length < allowed[name]:
            problems.append(f"{name} shrank from {allowed[name]} to {length} lines: lower its entry to {length}")
    for name in sorted(set(allowed) - set(measured)):
        problems.append(f"{name} is listed but no longer exists: remove its entry")
    return problems


def test_no_function_is_over_its_limit():
    functions, _modules = _measure()
    problems = _problems(functions, LONG_FUNCTIONS, MAX_FUNCTION_LINES, "function")
    assert not problems, "\n".join(problems)


def test_no_module_is_over_its_limit():
    _functions_measured, modules = _measure()
    problems = _problems(modules, LONG_MODULES, MAX_MODULE_LINES, "module")
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
